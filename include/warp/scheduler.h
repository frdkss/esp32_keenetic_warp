#pragma once
#include <optional>
#include <ctime>
#include "types.h"

namespace warp {
struct SchedulerSettings {
    bool enabled{true};  // NVS weekly_restart / ENABLE_WEEKLY_RESTART, independent of autorecovery.
    std::uint8_t weekday{4}, hour{5}, minute{0};  // tm_wday: Sunday = 0.
};
inline bool validSchedulerSettings(const SchedulerSettings& s) {
    return s.weekday <= 6 && s.hour <= 23 && s.minute <= 59;
}
// Calendar dates are ordered independently of UTC offsets and DST folds.
inline bool validScheduleDate(std::uint32_t date) {
    const auto year = date / 10000, month = date / 100 % 100, day = date % 100;
    if (year < 2024 || year > 2100 || month < 1 || month > 12 || day < 1) return false;
    constexpr unsigned lengths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    return day <= lengths[month - 1] + (month == 2 && leap ? 1u : 0u);
}
class ScheduleStore {
public:
    virtual ~ScheduleStore() = default;
    virtual OperationResult load(std::uint32_t& lastDate) = 0;
    virtual OperationResult consume(std::uint32_t date) = 0;
};
class NvsScheduleStore final : public ScheduleStore {
public:
    OperationResult load(std::uint32_t& lastDate) override;
    OperationResult consume(std::uint32_t date) override;
};
class Scheduler {
public:
    explicit Scheduler(ScheduleStore& store) : store_(store) {}
    OperationResult begin(const SchedulerSettings& settings);
    // localTime comes from localtime_r after Network has applied its POSIX TZ.
    // Consume durably BEFORE returning a request, including skipped events.
    std::optional<RestartReason> poll(const SystemStatus& status, const std::tm* localTime);
    void recordDecision(RestartDecision decision);
    const ScheduleStatus& status() const { return status_; }
private:
    ScheduleStore& store_;
    SchedulerSettings settings_{};
    ScheduleStatus status_{};
};
}  // namespace warp
