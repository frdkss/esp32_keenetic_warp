#pragma once

#include <cstdint>
#include <string_view>

namespace warp {
enum class ErrorReason : std::uint8_t {
    None, NotConfigured, NotImplemented, WifiDisconnected, TimeNotSynchronized,
    DnsFailure, ConnectTimeout, ReadTimeout, TlsFailure, HttpFailure,
    AuthenticationFailed, PermissionDenied, InvalidJson, RciFailure,
    InterfaceNotFound, InternetUnavailable, DisplayUnconfirmed, DisplayUnavailable,
    ConnectionFailure, DnsTimeout, InvalidUrl, InvalidResponse, ResponseTooLarge,
    ResourceExhausted, StorageFailure, Cancelled, Pending, Busy, UnsupportedRouter, StateMismatch,
    WarpUnavailable, InterfaceDisabled,
};
enum class SystemState : std::uint8_t { Starting, Waiting, Healthy, Degraded, Recovering, Error };
enum class RecoveryPhase : std::uint8_t {
    Idle, ConfirmInternet, Inspect, Disable, WaitDisabled, Enable, WaitOnline, Verify, Cooldown,
};
enum class RestartReason : std::uint8_t { FailureThreshold, WeeklySchedule };
enum class RestartDecision : std::uint8_t {
    Accepted, InternetUnconfirmed, TimeUnconfirmed, Busy, NotImplemented, Disabled, Unavailable, ThresholdNotReached, Unknown,
};
enum class DisplayState : std::uint8_t { Disabled, Unconfirmed, Ready, Unavailable };
enum class ScheduleState : std::uint8_t { Disabled, WaitingTime, Armed, Requested, Skipped, Error };
struct ScheduleStatus {
    ScheduleState state{ScheduleState::Disabled};
    std::uint32_t lastDate{0};  // Last consumed local calendar date, YYYYMMDD.
    ErrorReason error{ErrorReason::None};
    RestartDecision decision{RestartDecision::Unknown};  // The outcome of a previous boot is not persisted.
};

struct OperationResult {
    ErrorReason error{ErrorReason::NotImplemented};
    constexpr bool ok() const { return error == ErrorReason::None; }
};
struct CheckResult {
    ErrorReason error{ErrorReason::NotImplemented};
    int httpStatus{0};
    std::uint32_t durationMs{0};
    bool reachable{false};
    bool attempted{false};
    int transportCode{0};
    int tlsCode{0};
    int certificateFlags{0};
};
struct CheckSummary {
    std::uint16_t total{0};
    std::uint16_t reachable{0};
    std::uint16_t failed{0};
};
struct SystemStatus {
    SystemState state{SystemState::Starting};
    ErrorReason reason{ErrorReason::None};
    RecoveryPhase recovery{RecoveryPhase::Idle};
    DisplayState display{DisplayState::Disabled};
    CheckSummary targets{};
    CheckSummary controls{};
    std::uint32_t consecutiveFailures{0};
    std::uint32_t recoveryAttempts{0};
    ErrorReason lastRecoveryError{ErrorReason::None};
    bool restorePending{false};
    bool internetConfirmed{false};
    bool timeSynchronized{false};
    ScheduleStatus schedule{};
};
// Views only: owning/erasing credentials belongs to the provisioning/NVS stage.
struct CredentialsView {
    std::string_view wifiSsid;
    std::string_view wifiPassword;
    std::string_view routerLogin;
    std::string_view routerPassword;
};
}  // namespace warp
