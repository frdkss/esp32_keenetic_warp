#include "warp/status.h"
#include <Arduino.h>

namespace warp::status {
const char* label(SystemState state) {
    switch (state) {
    case SystemState::Starting: return "START";
    case SystemState::Waiting: return "WAIT";
    case SystemState::Healthy: return "OK";
    case SystemState::Degraded: return "ERR";
    case SystemState::Recovering: return "RECOVER";
    case SystemState::Error: return "ERR";
    }
    return "UNKNOWN";
}
const char* label(ErrorReason reason) {
    switch (reason) {
    case ErrorReason::None: return "NONE";
    case ErrorReason::NotConfigured: return "NO CONFIG";
    case ErrorReason::NotImplemented: return "NOT IMPL";
    case ErrorReason::WifiDisconnected: return "NO WIFI";
    case ErrorReason::TimeNotSynchronized: return "NO TIME";
    case ErrorReason::DnsFailure: return "DNS";
    case ErrorReason::ConnectTimeout: return "CONNECT";
    case ErrorReason::ReadTimeout: return "TIMEOUT";
    case ErrorReason::TlsFailure: return "TLS";
    case ErrorReason::HttpFailure: return "HTTP";
    case ErrorReason::AuthenticationFailed: return "AUTH";
    case ErrorReason::PermissionDenied: return "DENIED";
    case ErrorReason::InvalidJson: return "JSON";
    case ErrorReason::RciFailure: return "RCI";
    case ErrorReason::InterfaceNotFound: return "NO IFACE";
    case ErrorReason::InternetUnavailable: return "NO NET";
    case ErrorReason::DisplayUnconfirmed: return "OLED UNKNOWN";
    case ErrorReason::DisplayUnavailable: return "NO OLED";
    case ErrorReason::ConnectionFailure: return "CONNECT FAIL";
    case ErrorReason::DnsTimeout: return "DNS TIMEOUT";
    case ErrorReason::InvalidUrl: return "URL";
    case ErrorReason::InvalidResponse: return "HTTP FORMAT";
    case ErrorReason::ResponseTooLarge: return "HTTP LIMIT";
    case ErrorReason::ResourceExhausted: return "RESOURCES";
    case ErrorReason::StorageFailure: return "NVS";
    case ErrorReason::Cancelled: return "CANCELLED";
    case ErrorReason::Pending: return "PENDING";
    case ErrorReason::Busy: return "BUSY";
    case ErrorReason::UnsupportedRouter: return "ROUTER PROFILE";
    case ErrorReason::StateMismatch: return "STATE MISMATCH";
    case ErrorReason::WarpUnavailable: return "WARP FAIL";
    case ErrorReason::InterfaceDisabled: return "IFACE DISABLED";
    }
    return "UNKNOWN";
}
const char* label(DisplayState display) {
    switch (display) {
    case DisplayState::Disabled: return "DISABLED";
    case DisplayState::Unconfirmed: return "UNCONFIRMED";
    case DisplayState::Ready: return "READY";
    case DisplayState::Unavailable: return "UNAVAILABLE";
    }
    return "UNKNOWN";
}
const char* label(RecoveryPhase phase) {
    switch (phase) {
    case RecoveryPhase::Idle: return "IDLE";
    case RecoveryPhase::ConfirmInternet: return "CONFIRM";
    case RecoveryPhase::Inspect: return "INSPECT";
    case RecoveryPhase::Disable: return "OFF";
    case RecoveryPhase::WaitDisabled: return "OFF WAIT";
    case RecoveryPhase::Enable: return "ON";
    case RecoveryPhase::WaitOnline: return "WARMUP";
    case RecoveryPhase::Verify: return "VERIFY";
    case RecoveryPhase::Cooldown: return "COOLDOWN";
    }
    return "UNKNOWN";
}
const char* label(ScheduleState state) {
    switch (state) {
    case ScheduleState::Disabled: return "DISABLED";
    case ScheduleState::WaitingTime: return "NO TIME";
    case ScheduleState::Armed: return "ARMED";
    case ScheduleState::Requested: return "REQUESTED";
    case ScheduleState::Skipped: return "SKIPPED";
    case ScheduleState::Error: return "ERROR";
    }
    return "UNKNOWN";
}
const char* label(RestartDecision decision) {
    switch (decision) {
    case RestartDecision::Accepted: return "ACCEPTED";
    case RestartDecision::InternetUnconfirmed: return "NO NET";
    case RestartDecision::TimeUnconfirmed: return "NO TIME";
    case RestartDecision::Busy: return "BUSY";
    case RestartDecision::NotImplemented: return "NOT IMPL";
    case RestartDecision::Disabled: return "DISABLED";
    case RestartDecision::Unavailable: return "UNAVAILABLE";
    case RestartDecision::ThresholdNotReached: return "THRESHOLD";
    case RestartDecision::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}
void writeSerial(Print& output, const SystemStatus& snapshot) {
    output.printf("state=%s reason=%s oled=%s failures=%lu recovery=%s attempts=%lu time=%u internet=%u controls=%u/%u targets=%u/%u restore_pending=%u recovery_error=%s weekly=%s weekly_date=%lu weekly_decision=%s weekly_error=%s\n",
        label(snapshot.state), label(snapshot.reason), label(snapshot.display),
        static_cast<unsigned long>(snapshot.consecutiveFailures),
        label(snapshot.recovery),
        static_cast<unsigned long>(snapshot.recoveryAttempts), snapshot.timeSynchronized,
        snapshot.internetConfirmed, snapshot.controls.reachable, snapshot.controls.total,
        snapshot.targets.reachable, snapshot.targets.total, snapshot.restorePending, label(snapshot.lastRecoveryError),
        label(snapshot.schedule.state), static_cast<unsigned long>(snapshot.schedule.lastDate),
        label(snapshot.schedule.decision), label(snapshot.schedule.error));
}
}  // namespace warp::status
