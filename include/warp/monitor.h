#pragma once
#include "types.h"
#include "recovery_store.h"

namespace warp {
class Network;
class KeeneticClient;
enum class TargetFailurePolicy : std::uint8_t { Any, Half, Majority, All };
inline bool targetFailureThreshold(const CheckSummary& s, TargetFailurePolicy policy) {
    if (!s.total || s.failed > s.total) return false;
    switch (policy) {
    case TargetFailurePolicy::Any: return s.failed != 0;
    case TargetFailurePolicy::Half: return 2U * s.failed >= s.total;
    case TargetFailurePolicy::Majority: return 2U * s.failed > s.total;
    case TargetFailurePolicy::All: return s.failed == s.total;
    }
    return false;
}
struct MonitorSettings {
    bool autoRecovery{true};  // NVS autorecovery / service ENABLE_AUTORECOVERY.
    std::uint32_t disablePauseMs{2000}, warmupMs{30000}, cooldownMs{300000};
    std::uint32_t failureThreshold{5};
    TargetFailurePolicy targetFailurePolicy{TargetFailurePolicy::Majority};
};
inline bool validMonitorSettings(const MonitorSettings& s) {
    return s.failureThreshold >= 1 && s.failureThreshold <= 1000 &&
        static_cast<unsigned>(s.targetFailurePolicy) <= 3 &&
        s.disablePauseMs >= 1000 && s.disablePauseMs <= 3600000 &&
        s.warmupMs >= 1000 && s.warmupMs <= 3600000 && s.cooldownMs >= 1000 && s.cooldownMs <= 86400000;
}
class Monitor {
public:
    Monitor(Network& network, KeeneticClient& router, RecoveryStore& store)
        : network_(network), router_(router), store_(store) {}
    void begin(ErrorReason initializationError, DisplayState display, const MonitorSettings& settings = {});
    void tick(std::uint32_t nowMs);
    RestartDecision requestRestart(RestartReason reason);
    const SystemStatus& status() const { return status_; }
    void setDisplayState(DisplayState state) { status_.display = state; }
    bool ownsRouter() const { return status_.recovery != RecoveryPhase::Idle || pendingRestore_; }

private:
    Network& network_;
    KeeneticClient& router_;
    RecoveryStore& store_;
    MonitorSettings settings_{};
    SystemStatus status_{};
    ErrorReason initializationError_{ErrorReason::NotConfigured}, health_{ErrorReason::Pending};
    RestartReason restartReason_{RestartReason::FailureThreshold};
    std::uint32_t now_{0}, stamp_{0}, sequenceSeen_{0}, securitySeen_{0}, freshSequence_{0};
    std::uint8_t enableAttempts_{0};
    bool pendingRestore_{false}, operationPending_{false}, freshRequested_{false}, retryWaiting_{false};
    void consumeCycle();
    void advance();
    void updateStatus();
    void cooldown(ErrorReason error);
    void enable();
    bool freshCycle();
};
}  // namespace warp
