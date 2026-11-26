#include "warp/wifi_update.h"
#include "warp/build_profile.h"
#include "warp/update_probe.h"
#include <Arduino.h>
#if WARP_PROTECTED_BUILD
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <WiFiUdp.h>
#include "esp_https_server.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "esp_system.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

namespace warp::wifi_update {
namespace {
constexpr std::uint16_t kDiscoveryPort = 47831;
constexpr std::uint16_t kTlsPort = 8443;
constexpr char kDiscoverDomain[] = "WARP-WIFI-DISCOVER-1";
constexpr char kUploadDomain[] = "WARP-WIFI-UPLOAD-1";
constexpr std::uint32_t kChallengeMs = 60000;
constexpr std::uint32_t kRebootDelayMs = 1500;
constexpr std::uint32_t kRetryMs = 10000;
constexpr std::size_t kPage = 4096;
constexpr std::size_t kBlock = 0x10000;
constexpr std::size_t kPemSize = 1024;
// Record in partition "wifi_tls", written once by scripts/wifi_update.py during migration:
// "WARPTLS1" | u32 cert_len | u32 key_len | 64-hex fingerprint | cert PEM | key PEM | 0xFF padding.
constexpr char kRecordMagic[] = "WARPTLS1";
constexpr std::size_t kRecordHeader = 80;

struct Identity {
    std::array<char, kPemSize> certificate{}, key{};
    std::array<char, 65> fingerprint{};
};

Identity active{};
WiFiUDP udp;
bool started{false};
bool serverUp{false};
std::uint32_t nextAttempt{0};
std::array<char, 65> challenge{};
std::uint32_t challengeAt{0};
bool challengeLive{false};
bool rebootPending{false};
std::uint32_t rebootAt{0};

void toHex(const unsigned char* source, std::size_t size, char* out) {
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < size; ++i) { out[i * 2] = digits[source[i] >> 4]; out[i * 2 + 1] = digits[source[i] & 15]; }
    out[size * 2] = '\0';
}

bool loadIdentity(Identity& identity) {
    static std::array<unsigned char, kPage> record{};
    const auto* partition = esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, "wifi_tls");
    if (!partition || partition->size != kPage || esp_partition_read(partition, 0, record.data(), record.size()) != ESP_OK ||
        std::memcmp(record.data(), kRecordMagic, 8) != 0) return false;
    std::uint32_t certificateSize = 0, keySize = 0;
    std::memcpy(&certificateSize, record.data() + 8, 4);
    std::memcpy(&keySize, record.data() + 12, 4);
    if (certificateSize == 0 || certificateSize >= kPemSize || keySize == 0 || keySize >= kPemSize ||
        kRecordHeader + certificateSize + keySize > kPage) return false;
    std::memcpy(identity.fingerprint.data(), record.data() + 16, 64);
    identity.fingerprint[64] = '\0';
    std::memcpy(identity.certificate.data(), record.data() + kRecordHeader, certificateSize);
    identity.certificate[certificateSize] = '\0';
    std::memcpy(identity.key.data(), record.data() + kRecordHeader + certificateSize, keySize);
    identity.key[keySize] = '\0';
    return true;
}

// Reply and upload tags cover exact ASCII text, so the PC can reconstruct them without JSON canonicalization.
void sendDiscovery() {
    const int size = udp.parsePacket();
    if (size <= 0) return;
    const IPAddress peer = udp.remoteIP();
    const std::uint16_t peerPort = udp.remotePort();
    std::array<char, 96> request{};
    const bool fits = size == 80 || size == 81;
    if (fits) udp.read(reinterpret_cast<std::uint8_t*>(request.data()), size);
    udp.clear();
    if (!fits || std::memcmp(request.data(), "WARP-DISCOVER-1 ", 16) != 0) return;
    for (unsigned i = 16; i < 80; ++i) {
        const char c = request[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return;
    }
    request[80] = '\0';
    update::SlotDescription slot{};
    const auto* target = esp_ota_get_next_update_partition(nullptr);
    if (!update::describeRunningSlot(slot) || !target) return;
    std::array<char, 480> payload{};
    const int length = std::snprintf(payload.data(), payload.size(),
        "{\"schema\":1,\"nonce\":\"%.64s\",\"mac\":\"%s\",\"model\":\"esp32c3\",\"app_sha\":\"%s\","
        "\"version_hex\":\"%s\",\"slot\":%lu,\"target\":%lu,\"target_size\":%lu,\"tls_port\":%u,"
        "\"tls_sha256\":\"%s\"}",
        request.data() + 16, slot.mac, slot.app, slot.version, static_cast<unsigned long>(slot.address),
        static_cast<unsigned long>(target->address), static_cast<unsigned long>(target->size), kTlsPort,
        active.fingerprint.data());
    if (length <= 0 || static_cast<std::size_t>(length) >= payload.size()) return;
    char tag[65]{};
    if (!update::deviceTag(kDiscoverDomain, payload.data(), length, tag)) return;
    std::array<char, 640> packet{};
    const int packetLength = std::snprintf(packet.data(), packet.size(), "WARP-HERE-1 %s %s\n", payload.data(), tag);
    if (packetLength <= 0 || static_cast<std::size_t>(packetLength) >= packet.size()) return;
    udp.beginPacket(peer, peerPort);
    udp.write(reinterpret_cast<const std::uint8_t*>(packet.data()), packetLength);
    udp.endPacket();
}

void newChallenge() {
    unsigned char random[32]{};
    esp_fill_random(random, sizeof(random));
    toHex(random, sizeof(random), challenge.data());
    challengeAt = millis();
    challengeLive = true;
}

esp_err_t handleHello(httpd_req_t* request) {
    update::SlotDescription slot{};
    const auto* target = esp_ota_get_next_update_partition(nullptr);
    if (!update::describeRunningSlot(slot) || !target) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unavailable");
    newChallenge();
    std::array<char, 256> body{};
    const int length = std::snprintf(body.data(), body.size(),
        "{\"schema\":1,\"challenge\":\"%s\",\"target\":%lu,\"target_size\":%lu}", challenge.data(),
        static_cast<unsigned long>(target->address), static_cast<unsigned long>(target->size));
    httpd_resp_set_type(request, "application/json");
    return httpd_resp_send(request, body.data(), length);
}

bool parseNumber(const char* text, std::uint32_t& value) {
    if (!*text || std::strlen(text) > 10) return false;
    std::uint32_t result = 0;
    for (const char* p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        result = result * 10 + static_cast<std::uint32_t>(*p - '0');
    }
    value = result;
    return true;
}

// Writes only after the tag is verified. Every full page is erased, written raw (already flash-encrypted
// by the PC for this slot) and hashed; the final digest must equal the authenticated digest.
bool writeImage(const esp_partition_t* partition, httpd_req_t* request, std::uint32_t length, const char* expectedSha) {
    static std::array<unsigned char, kPage> page{};
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    bool ok = mbedtls_sha256_starts(&sha, 0) == 0;
    std::uint32_t offset = 0, received = 0;
    std::size_t filled = 0;
    while (ok && received < length) {
        const int count = httpd_req_recv(request, reinterpret_cast<char*>(page.data() + filled),
            std::min<std::size_t>(kPage - filled, length - received));
        if (count <= 0) { ok = false; break; }
        filled += count;
        received += count;
        if (filled < kPage) continue;
        if (offset % kBlock == 0 && esp_partition_erase_range(partition, offset,
                std::min<std::uint32_t>(kBlock, length - offset)) != ESP_OK) { ok = false; break; }
        ok = esp_partition_write_raw(partition, offset, page.data(), kPage) == ESP_OK &&
             mbedtls_sha256_update(&sha, page.data(), kPage) == 0;
        offset += kPage;
        filled = 0;
    }
    unsigned char hash[32]{};
    char hex[65]{};
    ok = ok && mbedtls_sha256_finish(&sha, hash) == 0;
    mbedtls_sha256_free(&sha);
    if (ok) toHex(hash, sizeof(hash), hex);
    return ok && std::strcmp(hex, expectedSha) == 0;
}

esp_err_t handleUpload(httpd_req_t* request) {
    char live[65]{}, target[16]{}, length[16]{}, sha[65]{}, tag[65]{};
    const bool headers = httpd_req_get_hdr_value_str(request, "X-WARP-Challenge", live, sizeof(live)) == ESP_OK &&
        httpd_req_get_hdr_value_str(request, "X-WARP-Target", target, sizeof(target)) == ESP_OK &&
        httpd_req_get_hdr_value_str(request, "X-WARP-Length", length, sizeof(length)) == ESP_OK &&
        httpd_req_get_hdr_value_str(request, "X-WARP-Sha256", sha, sizeof(sha)) == ESP_OK &&
        httpd_req_get_hdr_value_str(request, "X-WARP-Tag", tag, sizeof(tag)) == ESP_OK &&
        std::strlen(live) == 64 && std::strlen(sha) == 64 && std::strlen(tag) == 64;
    // A challenge is single-use, even when the request is rejected.
    const bool fresh = headers && challengeLive && static_cast<std::uint32_t>(millis() - challengeAt) <= kChallengeMs &&
        std::strcmp(live, challenge.data()) == 0;
    challengeLive = false;
    if (!fresh) return httpd_resp_send_err(request, HTTPD_403_FORBIDDEN, "challenge");
    std::uint32_t targetAddress = 0, size = 0;
    if (!parseNumber(target, targetAddress) || !parseNumber(length, size)) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "format");
    const auto* partition = esp_ota_get_next_update_partition(nullptr);
    if (!partition || partition->address != targetAddress || size == 0 || size > partition->size ||
        size % kPage || static_cast<std::size_t>(request->content_len) != size)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "target");
    std::array<char, 256> message{};
    const int messageLength = std::snprintf(message.data(), message.size(), "%s\n%s\n%s\n%s\n", live, target, length, sha);
    if (messageLength <= 0 || !update::deviceTagMatches(kUploadDomain, message.data(), messageLength, tag)) {
        return httpd_resp_send_err(request, HTTPD_403_FORBIDDEN, "authentication");
    }
    if (!update::beginMaintenance()) return httpd_resp_send_err(request, HTTPD_403_FORBIDDEN, "busy");
    if (!writeImage(partition, request, size, sha)) {
        update::endMaintenance();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "write");
    }
    if (esp_ota_set_boot_partition(partition) != ESP_OK) {
        update::endMaintenance();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "boot");
    }
    std::array<char, 96> body{};
    const int bodyLength = std::snprintf(body.data(), body.size(), "{\"result\":\"staged\",\"target\":%lu}",
        static_cast<unsigned long>(targetAddress));
    httpd_resp_set_type(request, "application/json");
    const auto status = httpd_resp_send(request, body.data(), bodyLength);
    // Keep the maintenance lock until reboot so router control stays paused for the staged image.
    rebootPending = true;
    rebootAt = millis() + kRebootDelayMs;
    return status;
}

bool startServer() {
    httpd_handle_t server{nullptr};
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.port_secure = kTlsPort;
    config.httpd.max_open_sockets = 2;
    config.httpd.stack_size = 8192;
    config.httpd.recv_wait_timeout = 10;
    config.httpd.send_wait_timeout = 10;
    config.httpd.max_uri_handlers = 4;
    config.cacert_pem = reinterpret_cast<const std::uint8_t*>(active.certificate.data());
    config.cacert_len = std::strlen(active.certificate.data()) + 1;
    config.prvtkey_pem = reinterpret_cast<const std::uint8_t*>(active.key.data());
    config.prvtkey_len = std::strlen(active.key.data()) + 1;
    if (httpd_ssl_start(&server, &config) != ESP_OK) return false;
    const httpd_uri_t hello{"/api/v1/hello", HTTP_GET, handleHello, nullptr};
    const httpd_uri_t upload{"/api/v1/firmware", HTTP_POST, handleUpload, nullptr};
    return httpd_register_uri_handler(server, &hello) == ESP_OK &&
           httpd_register_uri_handler(server, &upload) == ESP_OK;
}

bool start() {
    update::SlotDescription slot{};
    if (!update::describeRunningSlot(slot)) return false;
    if (!serverUp) {
        if (!loadIdentity(active) || !startServer()) return false;
        serverUp = true;
    }
    started = udp.begin(kDiscoveryPort) == 1;
    return started;
}
}

void tick(bool wifiConnected) {
    const auto now = static_cast<std::uint32_t>(millis());
    if (rebootPending && static_cast<std::int32_t>(now - rebootAt) >= 0) esp_restart();
    if (!wifiConnected) return;
    if (!started) {
        if (static_cast<std::int32_t>(now - nextAttempt) < 0) return;
        nextAttempt = now + kRetryMs;
        start();
        return;
    }
    sendDiscovery();
}
}
#else
namespace warp::wifi_update {
void tick(bool) {}
}
#endif
