#pragma once
#include "network.h"
#include "keenetic_protocol.h"
#include "monitor.h"
#include "scheduler.h"
namespace warp {
struct RuntimeConfiguration {
    NetworkSettings network{};
    keenetic::Settings router{};
    MonitorSettings monitor{};
    SchedulerSettings scheduler{};
    bool oledEnabled{false};
    std::array<char, 33> wifiSsid{};
    std::array<char, 65> wifiPassword{};
    std::array<char, 129> routerLogin{};
    std::array<char, 257> routerPassword{};
    CredentialsView credentials() const {
        return {wifiSsid.data(), wifiPassword.data(), routerLogin.data(), routerPassword.data()};
    }
    void clearCredentials();
};
// Call BEFORE initArduino: never erase NVS or generate missing keys on errors.
OperationResult initializeStorage();
OperationResult loadRuntimeConfiguration(RuntimeConfiguration& configuration);
}  // namespace warp
