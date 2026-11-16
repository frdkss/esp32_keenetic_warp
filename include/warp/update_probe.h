#pragma once
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
}
