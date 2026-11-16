#include "warp/runtime_config.h"
#include "warp/build_profile.h"
#include "warp/network_protocol.h"
#include <ArduinoJson.h>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_flash_encrypt.h"
#include "esp_secure_boot.h"
#include "mbedtls/platform_util.h"
#if !WARP_PROTECTED_BUILD
#include "warp/test_credentials.h"
#endif

namespace warp {
namespace {
#if WARP_PROTECTED_BUILD
template <std::size_t N>
bool readString(nvs_handle_t handle, const char* key, std::array<char, N>& out) {
    std::size_t size = 0;
    if (nvs_get_str(handle, key, nullptr, &size) != ESP_OK || !size || size > N) return false;
    if (nvs_get_str(handle, key, out.data(), &size) != ESP_OK) return false;
    return std::strlen(out.data()) + 1 == size;
}
bool readSeconds(nvs_handle_t handle, const char* key, std::uint32_t& out, std::uint32_t maximum) {
    std::uint32_t seconds = 0;
    if (nvs_get_u32(handle, key, &seconds) != ESP_OK || !seconds || seconds > maximum) return false;
    out = seconds * 1000;
    return true;
}
// ArduinoJson 7 uses a dynamic document; cap its allocator even for corrupt NVS.
class CappedAllocator : public ArduinoJson::Allocator {
    struct alignas(std::max_align_t) Block { std::size_t size; };
    std::size_t used_{0};
    static constexpr std::size_t budget = 8192;
public:
    void* allocate(std::size_t size) override {
        if (size > budget - used_) return nullptr;
        auto* block = static_cast<Block*>(std::malloc(sizeof(Block) + size));
        if (!block) return nullptr;
        block->size = size; used_ += size;
        return block + 1;
    }
    void deallocate(void* pointer) override {
        if (!pointer) return;
        auto* block = static_cast<Block*>(pointer) - 1;
        used_ -= block->size;
        std::free(block);
    }
    void* reallocate(void* pointer, std::size_t size) override {
        if (!pointer) return allocate(size);
        auto* block = static_cast<Block*>(pointer) - 1;
        const auto oldSize = block->size;
        if (size > budget - (used_ - oldSize)) return nullptr;
        auto* replacement = static_cast<Block*>(std::realloc(block, sizeof(Block) + size));
        if (!replacement) return nullptr;
        replacement->size = size; used_ = used_ - oldSize + size;
        return replacement + 1;
    }
};
bool readUrls(nvs_handle_t handle, const char* key, std::array<CheckUrl, maxCheckUrls>& urls, std::uint8_t& count) {
    std::array<char, 3501> json{};
    if (!readString(handle, key, json)) return false;
    CappedAllocator allocator;
    JsonDocument document(&allocator);
    if (deserializeJson(document, json.data(), DeserializationOption::NestingLimit(1)) ||
        !document.is<JsonArray>()) return false;
    const auto array = document.as<JsonArray>();
    if (array.size() < 1 || array.size() > maxCheckUrls) return false;
    count = 0;
    for (JsonVariant value : array) {
        if (!value.is<const char*>()) return false;
        const auto text = value.as<JsonString>();
        if (!text.size() || text.size() > maxUrlBytes || std::strlen(text.c_str()) != text.size()) return false;
        std::memcpy(urls[count++].data(), text.c_str(), text.size());
    }
    return true;
}
#endif
}
void RuntimeConfiguration::clearCredentials() {
    mbedtls_platform_zeroize(wifiSsid.data(), wifiSsid.size());
    mbedtls_platform_zeroize(wifiPassword.data(), wifiPassword.size());
    mbedtls_platform_zeroize(routerLogin.data(), routerLogin.size());
    mbedtls_platform_zeroize(routerPassword.data(), routerPassword.size());
}
OperationResult initializeStorage() {
#if WARP_PROTECTED_BUILD
    if (!esp_flash_encryption_enabled() || !esp_secure_boot_enabled()) return {ErrorReason::StorageFailure};
    const auto* keys = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_keys");
    if (!keys) return {ErrorReason::StorageFailure};
    nvs_sec_cfg_t config{};
    auto error = nvs_flash_read_security_cfg(keys, &config);
    if (error == ESP_OK) error = nvs_flash_secure_init(&config);
    mbedtls_platform_zeroize(&config, sizeof(config));
#else
    const auto error = nvs_flash_init();
#endif
    return {error == ESP_OK ? ErrorReason::None : ErrorReason::StorageFailure};
}
OperationResult loadRuntimeConfiguration(RuntimeConfiguration& out) {
    out.clearCredentials();
    out.network = {};
    out.router = {};
    out.monitor = {};
    out.scheduler = {};
    out.oledEnabled = false;
#if !WARP_PROTECTED_BUILD
    // No owner configuration or real sites are compiled into a test build.
    const auto credentials = test::credentials;
    std::memcpy(out.wifiSsid.data(), credentials.wifiSsid.data(), credentials.wifiSsid.size());
    std::memcpy(out.wifiPassword.data(), credentials.wifiPassword.data(), credentials.wifiPassword.size());
    std::memcpy(out.routerLogin.data(), credentials.routerLogin.data(), credentials.routerLogin.size());
    std::memcpy(out.routerPassword.data(), credentials.routerPassword.data(), credentials.routerPassword.size());
    return {ErrorReason::NotConfigured};  // Website lists must come from the owner.
#else
    nvs_handle_t handle;
    if (nvs_open("warp", NVS_READONLY, &handle) != ESP_OK) return {ErrorReason::NotConfigured};
    std::uint32_t schema = 0;
    std::uint32_t routerPort = 0;
    std::uint32_t autoRecovery = 0, failureThreshold = 0, weeklyRestart = 0, scheduleDay = 0, oledEnabled = 0, targetPolicy = 2;
    std::array<char, 6> scheduleTime{};
    const bool valid = nvs_get_u32(handle, "schema", &schema) == ESP_OK && (schema == 1 || schema == 2) &&
        (schema == 1 || (nvs_get_u32(handle, "target_policy", &targetPolicy) == ESP_OK && targetPolicy <= 3)) &&
        readString(handle, "wifi_ssid", out.wifiSsid) && readString(handle, "wifi_pass", out.wifiPassword) &&
        readString(handle, "router_login", out.routerLogin) && readString(handle, "router_pass", out.routerPassword) &&
        readString(handle, "router_addr", out.router.address) && readString(handle, "router_tls", out.router.tlsName) &&
        readString(handle, "warp_iface", out.router.interfaceName) &&
        nvs_get_u32(handle, "router_port", &routerPort) == ESP_OK && routerPort && routerPort <= 65535 &&
        readString(handle, "timezone", out.network.timezone) &&
        readSeconds(handle, "check_secs", out.network.checkIntervalMs, 86400) &&
        readSeconds(handle, "connect_secs", out.network.connectTimeoutMs, 60) &&
        readSeconds(handle, "read_secs", out.network.readTimeoutMs, 60) &&
        readSeconds(handle, "disable_secs", out.monitor.disablePauseMs, 3600) &&
        readSeconds(handle, "warmup_secs", out.monitor.warmupMs, 3600) &&
        readSeconds(handle, "cooldown_secs", out.monitor.cooldownMs, 86400) &&
        nvs_get_u32(handle, "autorecovery", &autoRecovery) == ESP_OK && autoRecovery <= 1 &&
        nvs_get_u32(handle, "fail_threshold", &failureThreshold) == ESP_OK &&
        (schema == 1 ? failureThreshold == 5 : (failureThreshold >= 1 && failureThreshold <= 1000)) &&
        nvs_get_u32(handle, "weekly_restart", &weeklyRestart) == ESP_OK && weeklyRestart <= 1 &&
        nvs_get_u32(handle, "schedule_day", &scheduleDay) == ESP_OK && scheduleDay <= 6 &&
        nvs_get_u32(handle, "oled_enabled", &oledEnabled) == ESP_OK && oledEnabled <= 1 &&
        readString(handle, "schedule_time", scheduleTime) && std::strlen(scheduleTime.data()) == 5 &&
        scheduleTime[0] >= '0' && scheduleTime[0] <= '2' &&
        scheduleTime[1] >= '0' && scheduleTime[1] <= '9' && scheduleTime[2] == ':' &&
        scheduleTime[3] >= '0' && scheduleTime[3] <= '5' && scheduleTime[4] >= '0' && scheduleTime[4] <= '9' &&
        (scheduleTime[0] - '0') * 10 + scheduleTime[1] - '0' <= 23 &&
        readUrls(handle, "control_urls", out.network.controls, out.network.controlCount) &&
        readUrls(handle, "target_urls", out.network.targets, out.network.targetCount) &&
        net::validSettings(out.network) && out.wifiSsid[0] &&
        out.routerLogin[0] && out.routerPassword[0];
    nvs_close(handle);
    out.router.port = static_cast<std::uint16_t>(routerPort);
    out.router.connectMs = out.network.connectTimeoutMs;
    out.router.readMs = out.network.readTimeoutMs;
    out.monitor.autoRecovery = autoRecovery == 1;
    out.monitor.failureThreshold = failureThreshold;
    out.monitor.targetFailurePolicy = static_cast<TargetFailurePolicy>(targetPolicy);
    out.scheduler.enabled = weeklyRestart == 1;
    out.scheduler.weekday = static_cast<std::uint8_t>(scheduleDay);
    if (valid) {
        out.scheduler.hour = static_cast<std::uint8_t>((scheduleTime[0] - '0') * 10 + scheduleTime[1] - '0');
        out.scheduler.minute = static_cast<std::uint8_t>((scheduleTime[3] - '0') * 10 + scheduleTime[4] - '0');
    }
    out.oledEnabled = oledEnabled == 1;
    if (!valid || !keenetic::validSettings(out.router)) {
        out.clearCredentials();
        out.network = {};
        out.router = {};
        out.monitor = {};
        out.scheduler = {};
        out.oledEnabled = false;
        return {ErrorReason::NotConfigured};
    }
    return {ErrorReason::None};
#endif
}
}  // namespace warp
