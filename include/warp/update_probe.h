#pragma once
#include <cstddef>
#include <cstdint>
#include "network.h"
namespace warp::update {
struct ServiceHooks {
    const char* configurationTag{nullptr};
    bool (*acquire)(){nullptr};
    void (*release)(){nullptr};
    std::uint32_t (*scheduleDate)(){nullptr};
};
void configureService(const ServiceHooks& hooks);
// Probe remains read-only. Authenticated maintenance only pauses router control.
void tick(bool runtimeReady, const CheckCycle& cycle, bool timeSynchronized,
          ErrorReason runtimeError = ErrorReason::None, int routerHttp = 0);
bool sending();

// Wi-Fi OTA support. Every function returns false (or does nothing) outside protected builds.
struct SlotDescription {
    char mac[13];
    char app[65];
    char version[65];
    std::uint32_t address;
    std::uint32_t size;
};
// Describes the running OTA application slot. Fails unless the device is a verified protected build.
bool describeRunningSlot(SlotDescription& out);
// HMAC-SHA256 with the device-bound NVS key over domain (including its NUL) || data, as lowercase hex.
bool deviceTag(const char* domain, const void* data, std::size_t size, char (&tag)[65]);
// Constant-time comparison of deviceTag() with a hex string from the PC.
bool deviceTagMatches(const char* domain, const void* data, std::size_t size, const char (&hexTag)[65]);
// Takes the same router-pause lock as the USB service. Fails while the lock is already held.
bool beginMaintenance();
void endMaintenance();
}
