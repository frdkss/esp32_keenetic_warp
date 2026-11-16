#include "warp/update_probe.h"
#include "warp/build_profile.h"
#include <Arduino.h>
#if WARP_PROTECTED_BUILD
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash.h"
#include "esp_flash_encrypt.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "nvs_flash.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

namespace warp::update {
namespace {
std::array<char, 160> input{};
std::size_t inputSize{0};
bool overflow{false};
std::uint32_t lastInput{0}, lastRequest{0};
std::array<char, 2048> output{};
std::size_t outputSize{0}, outputSent{0};
std::uint32_t outputStarted{0};
ServiceHooks hooks{};
std::array<char, 65> challenge{}, probeNonce{};
bool locked{false};
std::uint32_t challengeAt{0}, lockedAt{0};

template <std::size_t N> void hex(const unsigned char* source, std::size_t size, std::array<char, N>& out) {
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < size; ++i) {
        out[i * 2] = digits[source[i] >> 4]; out[i * 2 + 1] = digits[source[i] & 15];
    }
    out[size * 2] = '\0';
}
unsigned field(const esp_efuse_desc_t** description, std::size_t bits = 1) {
    unsigned value = 0;
    if (esp_efuse_read_field_blob(description, &value, bits) != ESP_OK) return ~0U;
    return value;
}
bool protection() {
    const esp_efuse_desc_t** enabled[] = {
        ESP_EFUSE_SECURE_BOOT_EN, ESP_EFUSE_DIS_USB_JTAG, ESP_EFUSE_DIS_PAD_JTAG,
        ESP_EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT, ESP_EFUSE_DIS_DOWNLOAD_ICACHE,
        ESP_EFUSE_DIS_DIRECT_BOOT, ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD,
        ESP_EFUSE_SECURE_BOOT_KEY_REVOKE1, ESP_EFUSE_SECURE_BOOT_KEY_REVOKE2,
        ESP_EFUSE_WR_DIS_SPI_BOOT_CRYPT_CNT, ESP_EFUSE_WR_DIS_RD_DIS, ESP_EFUSE_WR_DIS_DIS_ICACHE,
    };
    const esp_efuse_desc_t** disabled[] = {
        ESP_EFUSE_DIS_ICACHE, ESP_EFUSE_DIS_USB_SERIAL_JTAG, ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE,
        ESP_EFUSE_DIS_DOWNLOAD_MODE, ESP_EFUSE_SECURE_BOOT_KEY_REVOKE0, ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE,
    };
    for (auto entry : enabled) if (field(entry) != 1) return false;
    for (auto entry : disabled) if (field(entry) != 0) return false;
    if (!esp_flash_encryption_enabled() || !esp_secure_boot_enabled() ||
        field(ESP_EFUSE_SPI_BOOT_CRYPT_CNT, 3) != 7 || field(ESP_EFUSE_SOFT_DIS_JTAG, 3) != 7 ||
        esp_efuse_get_key_purpose(EFUSE_BLK_KEY0) != ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY ||
        esp_efuse_get_key_purpose(EFUSE_BLK_KEY1) != ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0 ||
        !esp_efuse_get_key_dis_read(EFUSE_BLK_KEY0) || !esp_efuse_get_key_dis_write(EFUSE_BLK_KEY0) ||
        esp_efuse_get_key_dis_read(EFUSE_BLK_KEY1) || !esp_efuse_get_key_dis_write(EFUSE_BLK_KEY1) ||
        !esp_efuse_get_keypurpose_dis_write(EFUSE_BLK_KEY0) || !esp_efuse_get_keypurpose_dis_write(EFUSE_BLK_KEY1)) return false;
    for (int i = EFUSE_BLK_KEY2; i < EFUSE_BLK_KEY_MAX; ++i)
        if (esp_efuse_get_key_purpose(static_cast<esp_efuse_block_t>(i)) != ESP_EFUSE_KEY_PURPOSE_USER) return false;
    return true;
}

// Cache immutable public measurements; never cache the NVS keys.
struct Measurements {
    std::array<char, 13> mac{};
    std::array<char, 65> digest{}, table{}, app{}, image{}, version{}, plain{};
    std::array<char, 257> cipher{};
    bool valid{false}, attempted{false};
} measured;

bool measure() {
    if (measured.attempted) return measured.valid;
    measured.attempted = true;
    esp_chip_info_t chip{};
    esp_chip_info(&chip);
    std::uint32_t size = 0;
    unsigned char mac[6]{}, digest[32]{}, cipher[128]{}, plain[128]{}, hash[32]{};
    const auto* running = esp_ota_get_running_partition();
    if (chip.model != CHIP_ESP32C3 || chip.revision != 4 || !protection() ||
        esp_flash_get_size(nullptr, &size) != ESP_OK || size != 4194304 ||
        esp_efuse_mac_get_default(mac) != ESP_OK ||
        esp_efuse_read_block(EFUSE_BLK_KEY1, digest, 0, 256) != ESP_OK ||
        !running || running->address != 0x20000 || running->size != 0x3E0000 ||
        esp_partition_get_sha256(running, hash) != ESP_OK) return false;
    hex(hash, sizeof(hash), measured.image);
    if (esp_partition_read_raw(running, 0, cipher, sizeof(cipher)) != ESP_OK ||
        esp_partition_read(running, 0, plain, sizeof(plain)) != ESP_OK ||
        mbedtls_sha256(plain, sizeof(plain), hash, 0) != 0) return false;
    hex(mac, sizeof(mac), measured.mac); hex(digest, sizeof(digest), measured.digest);
    hex(cipher, sizeof(cipher), measured.cipher); hex(hash, sizeof(hash), measured.plain);
    const auto* app = esp_app_get_description();
    hex(app->app_elf_sha256, 32, measured.app);
    hex(reinterpret_cast<const unsigned char*>(app->version), 32, measured.version);
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    bool ok = mbedtls_sha256_starts(&sha, 0) == 0;
    std::array<unsigned char, 256> block{};
    for (unsigned offset = 0; ok && offset < 0xC00; offset += 256) {
        ok = esp_flash_read_encrypted(nullptr, 0xF000 + offset, block.data(), block.size()) == ESP_OK &&
             mbedtls_sha256_update(&sha, block.data(), block.size()) == 0;
    }
    if (ok) ok = mbedtls_sha256_finish(&sha, hash) == 0;
    mbedtls_sha256_free(&sha);
    if (!ok) return false;
    hex(hash, sizeof(hash), measured.table);
    measured.valid = true;
    return true;
}

void respond(bool ready, const CheckCycle& cycle, bool timeSynchronized, ErrorReason runtimeError, int routerHttp) {
    if (!measure()) return;  // No unauthenticated success/fallback response.
    const auto* partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_keys");
    nvs_sec_cfg_t config{};
    if (!partition || nvs_flash_read_security_cfg(partition, &config) != ESP_OK) {
        mbedtls_platform_zeroize(&config, sizeof(config)); return;
    }
    unsigned char random[32]{};
    esp_fill_random(random, sizeof(random));
    hex(random, sizeof(random), challenge);
    challengeAt = millis();
    const bool service = hooks.configurationTag && std::strlen(hooks.configurationTag) == 64 &&
                         hooks.acquire && hooks.release && hooks.scheduleDate;
    // Exact bytes are authenticated; JSON parsing is only done after verification.
    const auto length = std::snprintf(output.data(), output.size(),
        "\nWARP9 {\"schema\":1,\"nonce\":\"%s\",\"mac\":\"%s\",\"revision\":4,\"flash_bytes\":4194304,"
        "\"secure\":1,\"boot_digest\":\"%s\",\"table_sha\":\"%s\",\"app_sha\":\"%s\",\"image_sha\":\"%s\",\"version_hex\":\"%s\","
        "\"cipher\":\"%s\",\"plain_sha\":\"%s\",\"cycle\":%lu,\"controls\":%u,\"targets\":%u,\"ready\":%u,\"internet\":%u,\"time\":%u,"
        "\"runtime_error\":%u,\"router_http\":%d,"
        "\"service\":%u,\"locked\":%u,\"challenge\":\"%s\",\"config_tag\":\"%s\",\"weekly_date\":%lu}",
        probeNonce.data(), measured.mac.data(), measured.digest.data(), measured.table.data(), measured.app.data(), measured.image.data(),
        measured.version.data(), measured.cipher.data(), measured.plain.data(),
        // sequence counts completed cycles, including while the next one runs.
        static_cast<unsigned long>(cycle.sequence), cycle.controlSummary.total,
        cycle.targetSummary.total, ready, cycle.internetConfirmed, timeSynchronized,
        static_cast<unsigned>(runtimeError), routerHttp,
        service, locked, challenge.data(), service ? hooks.configurationTag : "",
        static_cast<unsigned long>(service ? hooks.scheduleDate() : 0));
    unsigned char tag[32]{};
    std::array<unsigned char, 64> hmacKey{};
    std::memcpy(hmacKey.data(), config.eky, 32);
    std::memcpy(hmacKey.data() + 32, config.tky, 32);
    std::array<char, 65> tagHex{};
    constexpr char domain[] = "WARP-USB-PROBE-1";  // Include the terminating NUL.
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    bool ok = length > 7 && static_cast<std::size_t>(length) + 67 < output.size() &&
        mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) == 0 &&
        mbedtls_md_hmac_starts(&md, hmacKey.data(), hmacKey.size()) == 0 &&
        mbedtls_md_hmac_update(&md, reinterpret_cast<const unsigned char*>(domain), sizeof(domain)) == 0 &&
        mbedtls_md_hmac_update(&md, reinterpret_cast<const unsigned char*>(output.data() + 7), length - 7) == 0 &&
        mbedtls_md_hmac_finish(&md, tag) == 0;
    mbedtls_md_free(&md);
    mbedtls_platform_zeroize(&config, sizeof(config));
    mbedtls_platform_zeroize(hmacKey.data(), hmacKey.size());
    if (!ok) return;
    hex(tag, sizeof(tag), tagHex);
    std::snprintf(output.data() + length, output.size() - length, " %s\n", tagHex.data());
    outputSize = length + 66; outputSent = 0; outputStarted = millis();
}

bool lockRequest() {
    if (!hooks.acquire || !hooks.release || locked || !challenge[0] ||
        static_cast<std::uint32_t>(millis() - challengeAt) > 10000 ||
        std::memcmp(input.data() + 9, challenge.data(), 64) != 0 || input[73] != ' ') return false;
    const auto* partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_keys");
    nvs_sec_cfg_t config{};
    if (!partition || nvs_flash_read_security_cfg(partition, &config) != ESP_OK) {
        mbedtls_platform_zeroize(&config, sizeof(config)); return false;
    }
    std::array<unsigned char, 64> key{};
    std::memcpy(key.data(), config.eky, 32); std::memcpy(key.data() + 32, config.tky, 32);
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    constexpr char domain[] = "WARP-USB-LOCK-1";
    unsigned char tag[32]{};
    std::array<char, 65> expected{};
    bool ok = mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) == 0 &&
        mbedtls_md_hmac_starts(&md, key.data(), key.size()) == 0 &&
        mbedtls_md_hmac_update(&md, reinterpret_cast<const unsigned char*>(domain), sizeof(domain)) == 0 &&
        mbedtls_md_hmac_update(&md, reinterpret_cast<const unsigned char*>(challenge.data()), 64) == 0 &&
        mbedtls_md_hmac_finish(&md, tag) == 0;
    mbedtls_md_free(&md);
    mbedtls_platform_zeroize(&config, sizeof(config)); mbedtls_platform_zeroize(key.data(), key.size());
    hex(tag, sizeof(tag), expected);
    unsigned difference = 0;
    for (unsigned i = 0; i < 64; ++i) difference |= static_cast<unsigned char>(expected[i] ^ input[74 + i]);
    mbedtls_platform_zeroize(tag, sizeof(tag));
    challenge[0] = '\0';  // A challenge authorizes at most one attempt.
    if (!ok || difference) return false;
    locked = hooks.acquire();
    lockedAt = millis();
    return true;  // Signed response also reports a busy/refused lock.
}
}

void configureService(const ServiceHooks& value) { hooks = value; }
bool sending() { return outputSent < outputSize; }
void tick(bool runtimeReady, const CheckCycle& cycle, bool timeSynchronized, ErrorReason runtimeError, int routerHttp) {
    const auto now = static_cast<std::uint32_t>(millis());
    if (locked && now - lockedAt > 300000) { hooks.release(); locked = false; }
    if (sending()) {
        if (now - outputStarted > 2000 || !Serial) { outputSize = outputSent = 0; return; }
        const auto room = Serial.availableForWrite();
        const auto count = room > 0 ? std::min<std::size_t>(room, outputSize - outputSent) : 0;
        if (count) outputSent += Serial.write(reinterpret_cast<const std::uint8_t*>(output.data() + outputSent), count);
        return;
    }
    if (now - lastInput > 2000) { inputSize = 0; overflow = false; }
    for (unsigned count = 0; Serial.available() && count < 80; ++count) {
        const auto character = Serial.read(); lastInput = now;
        if (character == '\n') {
            input[inputSize] = '\0';
            bool valid = !overflow && inputSize == 70 && std::memcmp(input.data(), "WARP9 ", 6) == 0;
            for (unsigned i = 6; valid && i < 70; ++i)
                valid = (input[i] >= '0' && input[i] <= '9') || (input[i] >= 'a' && input[i] <= 'f');
            if (valid && now - lastRequest >= 1000) {
                std::memcpy(probeNonce.data(), input.data() + 6, 64);
                probeNonce[64] = '\0';
                lastRequest = now; respond(runtimeReady, cycle, timeSynchronized, runtimeError, routerHttp);
            } else if (!overflow && inputSize == 138 && std::memcmp(input.data(), "WARPLOCK ", 9) == 0 &&
                       lockRequest()) {
                respond(runtimeReady, cycle, timeSynchronized, runtimeError, routerHttp);
            }
            inputSize = 0; overflow = false;
            if (sending()) break;
        } else if (inputSize < input.size() - 1) input[inputSize++] = static_cast<char>(character);
        else overflow = true;
    }
}
}
#else
namespace warp::update {
void configureService(const ServiceHooks&) {}
void tick(bool, const CheckCycle&, bool, ErrorReason, int) {}
bool sending() { return false; }
}
#endif
