#include <Arduino.h>
#include "warp/board_profile.h"
#include "warp/build_profile.h"
#include "warp/display.h"
#include "warp/keenetic.h"
#include "warp/keenetic_esp.h"
#include "warp/monitor.h"
#include "warp/network.h"
#include "warp/network_esp.h"
#include "warp/runtime_config.h"
#include "warp/scheduler.h"
#include "warp/status.h"
#include "warp/update_probe.h"
#include "warp/config_tag.h"
#include "nvs_flash.h"
#include "mbedtls/platform_util.h"
#include "esp_log.h"
#include <ctime>
#include <cstring>

namespace {
warp::EspNetworkPlatform networkPlatform;
warp::Network network(networkPlatform);
warp::RuntimeConfiguration configuration;
warp::EspKeeneticTransport routerTransport;
warp::KeeneticClient router(network, routerTransport);
warp::NvsRecoveryStore recoveryStore;
warp::Monitor monitor(network, router, recoveryStore);
warp::NvsScheduleStore scheduleStore;
warp::Scheduler scheduler(scheduleStore);
warp::Display display;
std::uint32_t lastReportMs{0};
warp::SystemStatus lastReport{};
std::uint32_t reportedCycle{0};
bool routerReadStarted{false}, routerWasBusy{false};
std::uint32_t routerCycle{0};
bool runtimeReady{false};
bool servicePaused{false};
std::array<char, 65> configurationTag{};
std::uint32_t serviceDate{0};

bool acquireService() {
    bool pending = false;
    if (!runtimeReady || monitor.ownsRouter() || router.busy() || monitor.status().restorePending ||
        !recoveryStore.load(configuration.router, pending).ok() || pending || !scheduleStore.load(serviceDate).ok()) return false;
    servicePaused = true;
    return true;
}
void releaseService() { servicePaused = false; }
std::uint32_t serviceScheduleDate() { return servicePaused ? serviceDate : scheduler.status().lastDate; }

void measureConfiguration() {
#if WARP_PROTECTED_BUILD
    const auto* partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_keys");
    nvs_sec_cfg_t keys{};
    std::array<unsigned char, 64> key{};
    unsigned char tag[32]{};
    if (partition && nvs_flash_read_security_cfg(partition, &keys) == ESP_OK) {
        std::memcpy(key.data(), keys.eky, 32); std::memcpy(key.data() + 32, keys.tky, 32);
        if (warp::configurationTag(configuration, key.data(), tag)) {
            constexpr char digits[] = "0123456789abcdef";
            for (unsigned i = 0; i < 32; ++i) { configurationTag[i * 2] = digits[tag[i] >> 4]; configurationTag[i * 2 + 1] = digits[tag[i] & 15]; }
        }
    }
    mbedtls_platform_zeroize(&keys, sizeof(keys)); mbedtls_platform_zeroize(key.data(), key.size());
    mbedtls_platform_zeroize(tag, sizeof(tag));
#endif
}

void report() {
    // Both sinks consume exactly the same snapshot.
    monitor.setDisplayState(display.check());
    auto snapshot = monitor.status();
    snapshot.schedule = scheduler.status();
    if (Serial && !warp::update::sending()) warp::status::writeSerial(Serial, snapshot);
    display.render(snapshot);
    lastReport = snapshot;
}
}

void setup() {
    Serial.begin(115200);  // No waiting for a USB host.
    Serial.setTxTimeoutMs(0);  // A missing/stalled USB reader cannot hold up control.
    const auto loaded = warp::loadRuntimeConfiguration(configuration);
    if (loaded.ok()) measureConfiguration();
    const auto displayState = display.begin(warp::board::current().display, loaded.ok() && configuration.oledEnabled);
    warp::SystemStatus starting{};
    starting.display = displayState;
    if (Serial) warp::status::writeSerial(Serial, starting);
    display.render(starting);
    const auto credentials = configuration.credentials();
    const auto netResult = loaded.ok() ? network.begin(credentials, configuration.network, millis()) : loaded;
    const auto routerResult = loaded.ok() ? router.begin(credentials, configuration.router) : loaded;
    runtimeReady = loaded.ok() && netResult.ok() && routerResult.ok();
    // Wi-Fi and Keenetic own their required RAM copies; erase the temporary provisioning object.
    configuration.clearCredentials();
    monitor.begin(netResult.ok() ? routerResult.error : netResult.error, displayState, configuration.monitor);
    auto scheduleSettings = configuration.scheduler;
    if (!loaded.ok()) scheduleSettings.enabled = false;
    scheduler.begin(scheduleSettings);  // Scheduler storage errors do not interrupt monitoring/compensation.
    warp::update::configureService({configurationTag.data(), acquireService, releaseService, serviceScheduleDate});
    report();
}

void loop() {
    const auto now = static_cast<std::uint32_t>(millis());
    warp::update::tick(runtimeReady && monitor.status().state != warp::SystemState::Error,
                       network.checks(), network.timeSynchronized(), monitor.status().reason,
                       router.diagnostic().httpStatus);
    network.tick(now);
    router.tick(now);
    if (Serial && !warp::update::sending() && routerWasBusy && !router.busy()) {
        const auto& diagnostic = router.diagnostic();
        const auto& state = router.state();
        const auto& identity = router.identity();
        Serial.printf("router reason=%s http=%d state_valid=%u enabled=%u link=%u connected=%u tls=%d cert=%d model=%s os=%s\n",
            warp::status::label(router.result().error), diagnostic.httpStatus, state.valid,
            state.enabled, state.linkUp, state.connected, diagnostic.tlsCode, diagnostic.certificateFlags,
            identity.model[0] ? identity.model.data() : "unknown", identity.version[0] ? identity.version.data() : "unknown");
    }
    if (!servicePaused) monitor.tick(now);
    const auto epoch = static_cast<std::time_t>(networkPlatform.epochSeconds());
    std::tm local{};
    const auto* localTime = monitor.status().timeSynchronized ? localtime_r(&epoch, &local) : nullptr;
    if (!servicePaused) {
        if (const auto request = scheduler.poll(monitor.status(), localTime))
            scheduler.recordDecision(monitor.requestRestart(*request));
    }
    if (!servicePaused && !monitor.ownsRouter() && !router.busy() && !router.blocked() && network.wifiConnected() && network.timeSynchronized() &&
        (!routerReadStarted || (network.checks().complete && network.checks().sequence != routerCycle))) {
        routerCycle = network.checks().sequence;
        routerReadStarted = true;
        router.readWarpState();
    }
    routerWasBusy = router.busy();
    const auto& checks = network.checks();
    if (checks.complete && checks.sequence != reportedCycle) {
        reportedCycle = checks.sequence;
        for (unsigned group = 0; Serial && !warp::update::sending() && group < 2; ++group) {
            const auto count = group ? checks.targetSummary.total : checks.controlSummary.total;
            for (unsigned i = 0; i < count; ++i) {
                const auto& result = (group ? checks.targets : checks.controls)[i];
                Serial.printf("check=%s index=%u http=%d reason=%s ms=%lu attempted=%u transport=%d tls=%d cert=%d\n",
                    group ? "target" : "control", i, result.httpStatus, warp::status::label(result.error),
                    static_cast<unsigned long>(result.durationMs), result.attempted,
                    result.transportCode, result.tlsCode, result.certificateFlags);
            }
        }
    }
    const auto& state = monitor.status();
    const auto& weekly = scheduler.status();
    // Preserve brief phases (Inspect/Disable/Enable), even between one-second reports.
    if (now - lastReportMs >= 1000 || state.state != lastReport.state || state.reason != lastReport.reason ||
        state.recovery != lastReport.recovery || weekly.state != lastReport.schedule.state ||
        weekly.lastDate != lastReport.schedule.lastDate || weekly.decision != lastReport.schedule.decision ||
        weekly.error != lastReport.schedule.error) {
        lastReportMs = now;
        report();
    }
    delay(1);  // Yield to FreeRTOS; no blocking startup or recovery delay.
}

extern "C" void app_main() {
    // Stop before Arduino's automatic erase/retry path if storage or keys are invalid.
    if (!warp::initializeStorage().ok()) {
        ESP_LOGE("startup", "NVS initialization failed; storage preserved, network disabled");
        return;
    }
    initArduino();
    setup();
    for (;;) loop();
}
