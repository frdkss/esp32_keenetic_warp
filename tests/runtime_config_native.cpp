#include "warp/runtime_config.h"
#include "fake_runtime.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
std::unordered_map<std::string, std::string> strings;
std::unordered_map<std::string, std::uint32_t> integers;
bool flashEnabled = true, bootEnabled = true, keysPresent = true;
int keyError = ESP_OK, initError = ESP_OK, keyReads = 0, inits = 0;
bool esp_flash_encryption_enabled() { return flashEnabled; }
bool esp_secure_boot_enabled() { return bootEnabled; }
const esp_partition_t* esp_partition_find_first(int, int, const char*) {
    static esp_partition_t partition; return keysPresent ? &partition : nullptr;
}
int nvs_flash_read_security_cfg(const esp_partition_t*, nvs_sec_cfg_t*) { ++keyReads; return keyError; }
int nvs_flash_secure_init(nvs_sec_cfg_t*) { ++inits; return initError; }
int nvs_open(const char*, int mode, nvs_handle_t* handle) { CHECK(mode == NVS_READONLY); *handle = 1; return ESP_OK; }
void nvs_close(nvs_handle_t) {}
int nvs_get_u32(nvs_handle_t, const char* key, std::uint32_t* value) {
    const auto found = integers.find(key);
    if (found == integers.end()) return -1;
    *value = found->second; return ESP_OK;
}
int nvs_get_str(nvs_handle_t, const char* key, char* out, std::size_t* size) {
    const auto found = strings.find(key);
    if (found == strings.end()) return -1;
    const auto needed = found->second.size() + 1;
    if (!out) { *size = needed; return ESP_OK; }
    if (*size < needed) return -1;
    std::memcpy(out, found->second.c_str(), needed); *size = needed;
    return ESP_OK;
}
void defaults() {
    integers = {{"schema", 1}, {"check_secs", 60}, {"connect_secs", 5}, {"read_secs", 5}, {"router_port", 443},
        {"disable_secs", 2}, {"warmup_secs", 30}, {"cooldown_secs", 300}, {"autorecovery", 1}, {"fail_threshold", 5},
        {"weekly_restart", 1}, {"schedule_day", 4}, {"oled_enabled", 0}};
    strings = {{"wifi_ssid", "SYNTHETIC_SSID"}, {"wifi_pass", "SYNTHETIC_PASSWORD"},
        {"router_login", "SYNTHETIC_LOGIN"}, {"router_pass", "SYNTHETIC_ROUTER_PASSWORD"},
        {"router_addr", "192.0.2.1"}, {"router_tls", "router.invalid"}, {"warp_iface", "Wireguard1"},
        {"timezone", "MSK-3"}, {"schedule_time", "05:00"},
        {"control_urls", "[\"https://control.invalid/\"]"}, {"target_urls", "[\"https://target.invalid/\"]"}};
}
void valid() {
    defaults(); RuntimeConfiguration c;
    CHECK(loadRuntimeConfiguration(c).ok());
    CHECK(c.network.controlCount == 1 && c.network.targetCount == 1 && c.network.checkIntervalMs == 60000);
    CHECK(c.credentials().wifiSsid == "SYNTHETIC_SSID");
    CHECK(c.credentials().routerPassword == "SYNTHETIC_ROUTER_PASSWORD");
    CHECK(std::string(c.router.address.data()) == "192.0.2.1" && c.router.port == 443);
    CHECK(std::string(c.router.interfaceName.data()) == "Wireguard1");
    CHECK(c.monitor.autoRecovery && c.monitor.disablePauseMs == 2000 && c.monitor.warmupMs == 30000 && c.monitor.cooldownMs == 300000);
    CHECK(c.scheduler.enabled && c.scheduler.weekday == 4 && c.scheduler.hour == 5 && c.scheduler.minute == 0 && !c.oledEnabled);
    c.clearCredentials();
    for (char ch : c.wifiSsid) CHECK(ch == 0);
    for (char ch : c.wifiPassword) CHECK(ch == 0);
    for (char ch : c.routerPassword) CHECK(ch == 0);
}
void invalid() {
    RuntimeConfiguration c;
    for (const auto& key : {"schema", "check_secs", "connect_secs", "read_secs", "router_port",
         "disable_secs", "warmup_secs", "cooldown_secs", "autorecovery", "fail_threshold", "weekly_restart", "schedule_day", "oled_enabled"}) {
        defaults(); integers.erase(key); CHECK(!loadRuntimeConfiguration(c).ok() && c.wifiPassword[0] == 0);
    }
    for (const auto& key : {"wifi_ssid", "wifi_pass", "router_login", "router_pass", "router_addr", "router_tls",
         "warp_iface", "timezone", "schedule_time", "control_urls", "target_urls"}) {
        defaults(); strings.erase(key); CHECK(!loadRuntimeConfiguration(c).ok() && c.routerPassword[0] == 0);
    }
    for (const auto& bad : {"[]", "{}", "[false]", "[1]", "[[\"https://a.invalid/\"]]",
         "[\"https://control.invalid/\"]", "[\"https://u:p@a.invalid/\"]", "[\"http://a.invalid/#x\"]",
         "[\"https://a.invalid/\\u0000suffix\"]", "[\"https://a.invalid/\\r\\nHost: evil\"]"}) {
        defaults(); strings["target_urls"] = bad; CHECK(!loadRuntimeConfiguration(c).ok());
    }
    defaults(); integers["schema"] = 99; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); integers["read_secs"] = 61; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); integers["check_secs"] = 0; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["wifi_ssid"] = std::string(33, 'x'); CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["wifi_pass"] = std::string("abc\0def", 7); CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); integers["router_port"] = 65536; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["router_tls"] = "http://router.invalid"; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["router_addr"] = "router.invalid"; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["warp_iface"] = "GigabitEthernet0"; CHECK(!loadRuntimeConfiguration(c).ok());
    for (const auto& field : {"disable_secs", "warmup_secs", "cooldown_secs"}) {
        defaults(); integers[field] = 0; CHECK(!loadRuntimeConfiguration(c).ok());
        defaults(); integers[field] = 86401; CHECK(!loadRuntimeConfiguration(c).ok());
    }
    defaults(); integers["autorecovery"] = 2; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); integers["fail_threshold"] = 4; CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); integers["autorecovery"] = 0; CHECK(loadRuntimeConfiguration(c).ok() && !c.monitor.autoRecovery);
    for (const auto& field : {"weekly_restart", "oled_enabled"}) {
        defaults(); integers[field] = 2; CHECK(!loadRuntimeConfiguration(c).ok());
    }
    defaults(); integers["schedule_day"] = 7; CHECK(!loadRuntimeConfiguration(c).ok());
    for (const auto* time : {"5:00", "24:00", "05:60", "05-00", "xx:xx", "05:00x", "", "-1:00"}) {
        defaults(); strings["schedule_time"] = time; CHECK(!loadRuntimeConfiguration(c).ok());
    }
    defaults(); integers["weekly_restart"] = 0; integers["oled_enabled"] = 1;
    integers["schedule_day"] = 0; strings["schedule_time"] = "23:59";
    CHECK(loadRuntimeConfiguration(c).ok() && !c.scheduler.enabled && c.monitor.autoRecovery && c.oledEnabled &&
        c.scheduler.weekday == 0 && c.scheduler.hour == 23 && c.scheduler.minute == 59);
    defaults(); integers["autorecovery"] = 0;
    CHECK(loadRuntimeConfiguration(c).ok() && !c.monitor.autoRecovery && c.scheduler.enabled);
}
void schema2() {
    RuntimeConfiguration c;
    for (unsigned policy = 0; policy < 4; ++policy) {
        defaults(); integers["schema"] = 2; integers["target_policy"] = policy; integers["fail_threshold"] = 7;
        CHECK(loadRuntimeConfiguration(c).ok());
        CHECK(c.monitor.failureThreshold == 7 && static_cast<unsigned>(c.monitor.targetFailurePolicy) == policy);
    }
    integers["target_policy"] = 4; CHECK(!loadRuntimeConfiguration(c).ok());
    integers["target_policy"] = 2; integers["fail_threshold"] = 0; CHECK(!loadRuntimeConfiguration(c).ok());
    integers["fail_threshold"] = 1001; CHECK(!loadRuntimeConfiguration(c).ok());
    integers["fail_threshold"] = 1000; CHECK(loadRuntimeConfiguration(c).ok());
    integers.erase("target_policy"); CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); CHECK(loadRuntimeConfiguration(c).ok() && c.monitor.failureThreshold == 5 &&
        c.monitor.targetFailurePolicy == TargetFailurePolicy::Majority);
}
void limits() {
    RuntimeConfiguration c;
    defaults(); strings["target_urls"] = std::string(3501, 'x'); CHECK(!loadRuntimeConfiguration(c).ok());
    defaults(); strings["target_urls"] = "[" + std::string(3490, '['); CHECK(!loadRuntimeConfiguration(c).ok());
    defaults();
    std::string list = "[";
    for (int i = 0; i < 8; ++i) {
        if (i) list += ",";
        list += "\"https://target-" + std::to_string(i) + ".invalid/" + std::string(360, 'a') + "\"";
    }
    list += "]"; strings["target_urls"] = list;
    CHECK(loadRuntimeConfiguration(c).ok() && c.network.targetCount == 8);
    strings["target_urls"] = list.substr(0, list.size() - 1) + ",\"https://ninth.invalid/\"]";
    CHECK(!loadRuntimeConfiguration(c).ok());
}
void storage() {
    CHECK(initializeStorage().ok() && keyReads == 1 && inits == 1);
    flashEnabled = false; CHECK(!initializeStorage().ok() && keyReads == 1);
    flashEnabled = true; bootEnabled = false; CHECK(!initializeStorage().ok() && keyReads == 1);
    bootEnabled = true; keysPresent = false; CHECK(!initializeStorage().ok() && keyReads == 1);
    keysPresent = true; keyError = -1; CHECK(!initializeStorage().ok() && keyReads == 2 && inits == 1);
    keyError = ESP_OK; initError = -1; CHECK(!initializeStorage().ok() && inits == 2);
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::string name = argv[1];
        if (name == "valid") valid();
        else if (name == "schema2") schema2();
        else if (name == "invalid") invalid();
        else if (name == "limits") limits();
        else if (name == "storage") storage();
        else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
