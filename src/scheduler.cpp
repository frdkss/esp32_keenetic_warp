#include "warp/scheduler.h"

namespace warp {
OperationResult Scheduler::begin(const SchedulerSettings& settings) {
    settings_ = settings;
    status_ = {};
    if (!validSchedulerSettings(settings)) {
        status_.state = ScheduleState::Error;
        return {status_.error = ErrorReason::NotConfigured};
    }
    if (!settings.enabled) return {ErrorReason::None};
    const auto loaded = store_.load(status_.lastDate);
    if (!loaded.ok() || (status_.lastDate && !validScheduleDate(status_.lastDate))) {
        status_.state = ScheduleState::Error;
        return {status_.error = ErrorReason::StorageFailure};
    }
    status_.state = ScheduleState::WaitingTime;
    return {ErrorReason::None};
}
std::optional<RestartReason> Scheduler::poll(const SystemStatus& status, const std::tm* local) {
    if (!settings_.enabled || status_.state == ScheduleState::Disabled || status_.state == ScheduleState::Error) return std::nullopt;
    if (!status.timeSynchronized || !local || local->tm_year < 124 || local->tm_year > 200 ||
        local->tm_mon < 0 || local->tm_mon > 11 || local->tm_mday < 1 || local->tm_mday > 31 ||
        local->tm_wday < 0 || local->tm_wday > 6 || local->tm_hour < 0 || local->tm_hour > 23 ||
        local->tm_min < 0 || local->tm_min > 59 || local->tm_sec < 0 || local->tm_sec > 60) {
        status_.state = ScheduleState::WaitingTime;
        return std::nullopt;
    }
    const auto date = static_cast<std::uint32_t>((local->tm_year + 1900) * 10000 +
        (local->tm_mon + 1) * 100 + local->tm_mday);
    if (!validScheduleDate(date)) { status_.state = ScheduleState::WaitingTime; return std::nullopt; }
    if (status_.state == ScheduleState::WaitingTime) status_.state = ScheduleState::Armed;
    if (local->tm_wday != settings_.weekday || local->tm_hour != settings_.hour ||
        local->tm_min != settings_.minute || date <= status_.lastDate) return std::nullopt;
    // On a write/commit failure, stop this scheduler until reboot. Never retry
    // writes every tick or risk a duplicate after an uncertain commit.
    if (!store_.consume(date).ok()) {
        status_.state = ScheduleState::Error;
        status_.error = ErrorReason::StorageFailure;
        return std::nullopt;
    }
    status_.lastDate = date;
    if (!status.internetConfirmed) { recordDecision(RestartDecision::InternetUnconfirmed); return std::nullopt; }
    if (status.recovery != RecoveryPhase::Idle || status.restorePending) {
        recordDecision(RestartDecision::Busy); return std::nullopt;
    }
    status_.state = ScheduleState::Requested;
    status_.decision = RestartDecision::Accepted;
    return RestartReason::WeeklySchedule;
}
void Scheduler::recordDecision(RestartDecision decision) {
    status_.decision = decision;
    status_.state = decision == RestartDecision::Accepted ? ScheduleState::Requested : ScheduleState::Skipped;
}
}  // namespace warp
