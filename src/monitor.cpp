#include "warp/monitor.h"
#include "warp/network.h"
#include "warp/keenetic.h"
#include "warp/network_protocol.h"
#include <limits>

namespace warp {
namespace {
constexpr std::uint32_t commandRetryMs = 5000;
constexpr std::uint8_t maxEnableAttempts = 3;
bool fullTargets(const CheckCycle& c, const NetworkSettings& s) {
    if (!c.complete || c.targetSummary.total != s.targetCount || !s.targetCount ||
        c.targetSummary.reachable + c.targetSummary.failed != s.targetCount) return false;
    for (unsigned i = 0; i < s.targetCount; ++i) if (!c.targets[i].attempted) return false;
    return true;
}
}
void Monitor::begin(ErrorReason error, DisplayState display, const MonitorSettings& settings) {
    status_ = {};
    status_.display = display;
    settings_ = settings;
    initializationError_ = validMonitorSettings(settings) ? error : ErrorReason::NotConfigured;
    sequenceSeen_ = network_.checks().sequence;
    securitySeen_ = network_.securityGeneration();
    health_ = ErrorReason::Pending;
    now_ = stamp_ = 0;
    pendingRestore_ = operationPending_ = freshRequested_ = retryWaiting_ = false;
    enableAttempts_ = 0;
    if (initializationError_ == ErrorReason::None) {
        initializationError_ = store_.load(router_.settings_, pendingRestore_).error;
        if (initializationError_ == ErrorReason::None && pendingRestore_) enable();
    }
    updateStatus();
}
void Monitor::consumeCycle() {
    // A normal in-progress cycle revokes the current internet snapshot. It must
    // not break the failure streak; an actual loss/security invalidation must.
    if (!network_.wifiConnected() || !network_.timeSynchronized() || securitySeen_ != network_.securityGeneration()) {
        status_.consecutiveFailures = 0;
        health_ = !network_.wifiConnected() ? ErrorReason::WifiDisconnected : ErrorReason::TimeNotSynchronized;
    }
    securitySeen_ = network_.securityGeneration();
    const auto& cycle = network_.checks();
    if (!cycle.complete || cycle.sequence == sequenceSeen_) return;
    sequenceSeen_ = cycle.sequence;
    status_.controls = cycle.controlSummary;
    status_.targets = cycle.targetSummary;
    if (!network_.internetConfirmed()) {
        health_ = ErrorReason::InternetUnavailable;
        status_.consecutiveFailures = 0;
        return;
    }
    if (!fullTargets(cycle, network_.settings())) {
        health_ = ErrorReason::InvalidResponse;
        status_.consecutiveFailures = 0;
        return;
    }
    health_ = targetFailureThreshold(cycle.targetSummary, settings_.targetFailurePolicy) ? ErrorReason::WarpUnavailable : ErrorReason::None;
    if (health_ == ErrorReason::None) status_.consecutiveFailures = 0;
    if (status_.recovery != RecoveryPhase::Idle && status_.recovery != RecoveryPhase::Cooldown) return;
    if (health_ != ErrorReason::None && status_.consecutiveFailures != std::numeric_limits<std::uint32_t>::max())
        ++status_.consecutiveFailures;
}
void Monitor::tick(std::uint32_t now) {
    now_ = now;
    consumeCycle();
    if (initializationError_ == ErrorReason::None) {
        advance();
        if (status_.recovery == RecoveryPhase::Idle && settings_.autoRecovery &&
            status_.consecutiveFailures >= settings_.failureThreshold && network_.internetConfirmed()) {
            requestRestart(RestartReason::FailureThreshold);
        }
    }
    updateStatus();
}
RestartDecision Monitor::requestRestart(RestartReason reason) {
    if (ownsRouter()) return RestartDecision::Busy;
    if (initializationError_ != ErrorReason::None || router_.blocked()) return RestartDecision::Unavailable;
    if (reason == RestartReason::FailureThreshold && !settings_.autoRecovery) return RestartDecision::Disabled;
    if (reason == RestartReason::WeeklySchedule && !network_.timeSynchronized()) return RestartDecision::TimeUnconfirmed;
    if (!network_.internetConfirmed()) return RestartDecision::InternetUnconfirmed;
    if (reason == RestartReason::FailureThreshold && status_.consecutiveFailures < settings_.failureThreshold)
        return RestartDecision::ThresholdNotReached;
    restartReason_ = reason;
    status_.recovery = RecoveryPhase::ConfirmInternet;
    ++status_.recoveryAttempts;
    status_.lastRecoveryError = ErrorReason::None;
    freshRequested_ = false;
    operationPending_ = false;
    stamp_ = now_;
    updateStatus();
    return RestartDecision::Accepted;
}
void Monitor::cooldown(ErrorReason error) {
    status_.lastRecoveryError = error;
    status_.recovery = RecoveryPhase::Cooldown;
    operationPending_ = freshRequested_ = retryWaiting_ = false;
    stamp_ = now_;
    if (error == ErrorReason::None) status_.consecutiveFailures = 0;
}
void Monitor::enable() {
    status_.recovery = RecoveryPhase::Enable;
    operationPending_ = retryWaiting_ = false;
    enableAttempts_ = 0;
}
bool Monitor::freshCycle() {
    if (!freshRequested_) {
        // Drain an existing cycle; only a cycle explicitly requested after the
        // restart/settling wait may authorize disabling or verify recovery.
        if (network_.busy() || !network_.requestChecks()) return false;
        freshSequence_ = network_.checks().sequence;
        freshRequested_ = true;
        return false;
    }
    return network_.checks().complete && network_.checks().sequence != freshSequence_;
}
void Monitor::advance() {
    switch (status_.recovery) {
    case RecoveryPhase::Idle: return;
    case RecoveryPhase::Cooldown:
        if (net::elapsed(now_, stamp_, settings_.cooldownMs)) {
            if (pendingRestore_) enable();
            else status_.recovery = RecoveryPhase::Idle;
        }
        return;
    case RecoveryPhase::ConfirmInternet:
    case RecoveryPhase::Verify: {
        const bool verifying = status_.recovery == RecoveryPhase::Verify;
        if (!network_.wifiConnected() || !network_.timeSynchronized()) {
            cooldown(ErrorReason::InternetUnavailable); return;
        }
        const auto& s = network_.settings();
        // Bound waiting even for an adapter which cannot queue a probe.
        const auto budget = 2 * (s.controlCount + s.targetCount) * (s.connectTimeoutMs + s.readTimeoutMs + 1000) + 1000;
        if (net::elapsed(now_, stamp_, budget)) { cooldown(ErrorReason::ReadTimeout); return; }
        if (!freshCycle()) return;
        if (!network_.internetConfirmed()) { cooldown(ErrorReason::InternetUnavailable); return; }
        if (!fullTargets(network_.checks(), s)) { cooldown(ErrorReason::InvalidResponse); return; }
        if (verifying) {
            cooldown(targetFailureThreshold(network_.checks().targetSummary, settings_.targetFailurePolicy) ? ErrorReason::WarpUnavailable : ErrorReason::None);
        } else if (restartReason_ == RestartReason::FailureThreshold && !targetFailureThreshold(network_.checks().targetSummary, settings_.targetFailurePolicy)) {
            status_.consecutiveFailures = 0;
            status_.recovery = RecoveryPhase::Idle;
        } else {
            status_.recovery = RecoveryPhase::Inspect;
        }
        return;
    }
    case RecoveryPhase::Inspect:
        if (!network_.internetConfirmed()) { cooldown(ErrorReason::InternetUnavailable); return; }
        if (!operationPending_) {
            if (router_.busy()) return;
            const auto result = router_.readWarpState();
            if (result.error != ErrorReason::Pending) { cooldown(result.error); return; }
            operationPending_ = true; return;
        }
        if (router_.busy()) return;
        operationPending_ = false;
        if (!router_.result().ok()) { cooldown(router_.result().error); return; }
        // Preserve an interface disabled by its owner. Only our own journal may
        // bypass this check after an interrupted operation.
        if (!router_.state().valid || !router_.state().enabled) { cooldown(ErrorReason::InterfaceDisabled); return; }
        if (!store_.arm(router_.settings_).ok()) { cooldown(ErrorReason::StorageFailure); return; }
        pendingRestore_ = true;
        status_.recovery = RecoveryPhase::Disable;
        return;
    case RecoveryPhase::Disable:
        if (!operationPending_) {
            // Any uncertainty goes directly to compensation; Monitor never
            // retries disabling. The journal is already durable.
            if (!network_.internetConfirmed()) { enable(); return; }
            const auto result = router_.setWarpEnabled(false);
            if (result.error != ErrorReason::Pending) { status_.lastRecoveryError = result.error; enable(); return; }
            operationPending_ = true; return;
        }
        if (router_.busy()) return;
        operationPending_ = false;
        if (!router_.result().ok()) { status_.lastRecoveryError = router_.result().error; enable(); return; }
        status_.recovery = RecoveryPhase::WaitDisabled;
        stamp_ = now_;
        return;
    case RecoveryPhase::WaitDisabled:
        if (!network_.wifiConnected() || !network_.timeSynchronized() || net::elapsed(now_, stamp_, settings_.disablePauseMs)) enable();
        return;
    case RecoveryPhase::Enable:
        if (operationPending_) {
            if (router_.busy()) return;
            operationPending_ = false;
            if (router_.result().ok()) {
                // Clear only after verified administrative up. A failed commit
                // retains the obligation; retry only after the cooldown.
                if (!store_.clear().ok()) { cooldown(ErrorReason::StorageFailure); return; }
                pendingRestore_ = false;
                status_.recovery = RecoveryPhase::WaitOnline;
                stamp_ = now_;
                return;
            }
            status_.lastRecoveryError = router_.result().error;
            if (enableAttempts_ >= maxEnableAttempts || router_.blocked()) { cooldown(router_.result().error); return; }
            retryWaiting_ = true; stamp_ = now_;
        }
        // Finishing our own disable needs LAN + trusted TLS time, even without
        // general internet and with autoRecovery disabled in configuration.
        if (!network_.wifiConnected() || !network_.timeSynchronized() || router_.busy()) return;
        if (router_.blocked()) { cooldown(router_.result().error); return; }
        if (retryWaiting_ && !net::elapsed(now_, stamp_, commandRetryMs)) return;
        retryWaiting_ = false;
        ++enableAttempts_;
        {
            const auto result = router_.setWarpEnabled(true);
            if (result.error == ErrorReason::Pending) operationPending_ = true;
            else cooldown(result.error);
        }
        return;
    case RecoveryPhase::WaitOnline:
        if (net::elapsed(now_, stamp_, settings_.warmupMs)) {
            status_.recovery = RecoveryPhase::Verify;
            freshRequested_ = false; stamp_ = now_;
        }
        return;
    }
}
void Monitor::updateStatus() {
    status_.timeSynchronized = network_.timeSynchronized();
    status_.internetConfirmed = network_.internetConfirmed();
    status_.restorePending = pendingRestore_;
    if (initializationError_ != ErrorReason::None) {
        status_.state = SystemState::Error; status_.reason = initializationError_;
    } else if (status_.recovery != RecoveryPhase::Idle && status_.recovery != RecoveryPhase::Cooldown) {
        status_.state = SystemState::Recovering;
        status_.reason = status_.lastRecoveryError != ErrorReason::None ? status_.lastRecoveryError : ErrorReason::Pending;
        if (!status_.timeSynchronized) status_.reason = ErrorReason::TimeNotSynchronized;
        if (!network_.wifiConnected()) status_.reason = ErrorReason::WifiDisconnected;
    } else if (status_.recovery == RecoveryPhase::Cooldown && status_.lastRecoveryError != ErrorReason::None) {
        status_.state = SystemState::Error; status_.reason = status_.lastRecoveryError;
    } else if (router_.blocked()) {
        status_.state = SystemState::Error; status_.reason = router_.result().error;
    } else {
        status_.reason = health_;
        status_.state = health_ == ErrorReason::None ? SystemState::Healthy :
            health_ == ErrorReason::WarpUnavailable ? SystemState::Degraded : SystemState::Waiting;
    }
}
}  // namespace warp
