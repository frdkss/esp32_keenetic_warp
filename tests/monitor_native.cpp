#include "monitor_fixture.h"
void classifier() {
    for (unsigned count = 1; count <= 8; ++count) for (unsigned failed = 0; failed <= count; ++failed) {
        Fixture f(false, count); f.cycle(failed);
        CHECK(f.monitor.status().targets.total == count && f.monitor.status().targets.failed == failed);
        CHECK(f.monitor.status().consecutiveFailures == (failed > count / 2 ? 1u : 0u));
        CHECK(f.monitor.status().state == (failed > count / 2 ? SystemState::Degraded : SystemState::Healthy));
        CHECK(f.transport.mutations.empty() && f.store.arms == 0);
    }
}
void configurableThresholds() {
    for (unsigned policy = 0; policy < 4; ++policy)
        for (unsigned count = 1; count <= 8; ++count)
            for (unsigned failed = 0; failed <= count; ++failed) {
                Fixture f(false, count);
                f.options.targetFailurePolicy = static_cast<TargetFailurePolicy>(policy);
                f.monitor.begin(ErrorReason::None, DisplayState::Disabled, f.options);
                f.cycle(failed);
                const bool expected = policy == 0 ? failed != 0 : policy == 1 ? failed * 2 >= count :
                    policy == 2 ? failed * 2 > count : failed == count;
                CHECK(f.monitor.status().consecutiveFailures == (expected ? 1u : 0u));
            }
    for (unsigned threshold : {1u, 2u, 7u}) {
        Fixture f;
        f.options.failureThreshold = threshold;
        f.monitor.begin(ErrorReason::None, DisplayState::Disabled, f.options);
        for (unsigned cycle = 1; cycle <= threshold; ++cycle) {
            f.cycle();
            CHECK(f.monitor.status().consecutiveFailures == cycle);
            CHECK(f.monitor.status().recovery == (cycle == threshold ? RecoveryPhase::ConfirmInternet : RecoveryPhase::Idle));
        }
    }
    MonitorSettings invalid;
    invalid.failureThreshold = 0; CHECK(!validMonitorSettings(invalid));
    invalid.failureThreshold = 1001; CHECK(!validMonitorSettings(invalid));
    invalid.failureThreshold = 1000; CHECK(validMonitorSettings(invalid));
}
void streak() {
    Fixture f(false);
    for (unsigned i = 1; i <= 4; ++i) { f.cycle(); CHECK(f.monitor.status().consecutiveFailures == i); }
    for (unsigned i = 0; i < 20; ++i) f.step();
    CHECK(f.monitor.status().consecutiveFailures == 4);
    f.cycle(2); CHECK(f.monitor.status().consecutiveFailures == 0);
    f.cycle(); f.cycle(); f.cycle(4, false);
    CHECK(f.monitor.status().consecutiveFailures == 0 && f.monitor.status().reason == ErrorReason::InternetUnavailable);
    f.cycle(); CHECK(f.monitor.status().consecutiveFailures == 1);
    ++f.platform.losses; f.step(); CHECK(f.monitor.status().consecutiveFailures == 0);
    ++f.platform.sync; f.step(); f.cycle(); CHECK(f.monitor.status().consecutiveFailures == 1);
    f.platform.epoch += 100; f.network.tick(f.now); f.router.tick(f.now); f.monitor.tick(f.now);
    CHECK(f.monitor.status().consecutiveFailures == 0);
    Fixture active; active.disabled(); active.cycle(0);
    CHECK(active.monitor.status().consecutiveFailures == 0 && active.monitor.status().recovery == RecoveryPhase::WaitDisabled);
}
void fullCycle() {
    Fixture f; for (unsigned i = 0; i < 4; ++i) f.cycle();
    CHECK(f.monitor.status().consecutiveFailures == 4 && f.transport.mutations.empty());
    CHECK(f.network.requestChecks()); f.platform.pollBudget = 4;
    for (unsigned i = 0; i < 20; ++i) f.step();
    CHECK(!f.network.checks().complete && f.network.checks().targetSummary.failed == 3);
    CHECK(f.monitor.status().consecutiveFailures == 4 && f.monitor.status().recovery == RecoveryPhase::Idle);
    f.platform.pollBudget = -1; f.step();
    CHECK(f.monitor.status().consecutiveFailures == 5 && f.monitor.status().recovery == RecoveryPhase::ConfirmInternet);
}
void freshInternet() {
    Fixture f; f.threshold(); f.platform.controlOnline = false; f.phase(RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().reason == ErrorReason::InternetUnavailable && f.transport.mutations.empty() && f.store.arms == 0);
    CHECK(f.monitor.status().consecutiveFailures == 0);
    Fixture healed; healed.threshold(); healed.platform.failedTargets = 0; healed.phase(RecoveryPhase::Idle);
    CHECK(healed.monitor.status().consecutiveFailures == 0 && healed.transport.mutations.empty());
}
void success() {
    Fixture f; f.disabled();
    CHECK(f.transport.downs() == 1 && f.transport.ups() == 0 && f.store.arms == 1);
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Busy);
    f.step(1999); CHECK(f.monitor.status().recovery == RecoveryPhase::WaitDisabled && f.transport.ups() == 0);
    f.step(); f.phase(RecoveryPhase::WaitOnline);
    CHECK(f.transport.ups() == 1 && f.store.clears == 1 && !f.monitor.status().restorePending);
    f.platform.failedTargets = 0;
    f.step(29999); CHECK(f.monitor.status().recovery == RecoveryPhase::WaitOnline);
    f.step(); CHECK(f.monitor.status().recovery == RecoveryPhase::Verify);
    f.phase(RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::None && f.monitor.status().consecutiveFailures == 0);
    CHECK(f.monitor.status().state == SystemState::Healthy && f.monitor.status().recoveryAttempts == 1);
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Busy);
    f.step(299999); CHECK(f.monitor.status().recovery == RecoveryPhase::Cooldown);
    f.step(); CHECK(f.monitor.status().recovery == RecoveryPhase::Idle);
}
void failedVerify() {
    Fixture f; f.enabled(); f.step(30000); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::WarpUnavailable && f.monitor.status().consecutiveFailures == 5);
    f.cycle(); CHECK(f.monitor.status().consecutiveFailures == 6);
    CHECK(f.transport.downs() == 1 && !f.store.pending);
    f.step(299000); CHECK(f.transport.downs() == 1);
    f.step(1000); CHECK(f.monitor.status().recovery == RecoveryPhase::ConfirmInternet);
}
void disabledOption() {
    Fixture f(false); for (unsigned i = 0; i < 7; ++i) f.cycle();
    CHECK(f.monitor.status().consecutiveFailures == 7 && f.monitor.status().state == SystemState::Degraded);
    CHECK(f.monitor.requestRestart(RestartReason::FailureThreshold) == RestartDecision::Disabled);
    CHECK(f.transport.mutations.empty());
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Accepted);
    f.phase(RecoveryPhase::WaitDisabled); CHECK(f.transport.downs() == 1);
}
void scheduleGuard() {
    Fixture f(false, 4, false, true, false);
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::TimeUnconfirmed);
    ++f.platform.sync; f.step();
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::InternetUnconfirmed);
    f.cycle(0); CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Accepted);
    CHECK(f.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Busy);
    f.platform.controlOnline = false; f.phase(RecoveryPhase::Cooldown);
    CHECK(f.transport.mutations.empty() && f.monitor.status().reason == ErrorReason::InternetUnavailable);
    Fixture belowThreshold; belowThreshold.cycle(0);
    CHECK(belowThreshold.monitor.requestRestart(RestartReason::FailureThreshold) == RestartDecision::ThresholdNotReached);
}
struct WeeklyStore : ScheduleStore {
    std::uint32_t date{0}; unsigned writes{0};
    OperationResult load(std::uint32_t& out) override { out = date; return {ErrorReason::None}; }
    OperationResult consume(std::uint32_t value) override { date = value; ++writes; return {ErrorReason::None}; }
};
void scheduledEvent() {
    WeeklyStore store; Scheduler scheduler(store); CHECK(scheduler.begin({}).ok());
    std::tm local{}; local.tm_year = 126; local.tm_mon = 10; local.tm_mday = 12; local.tm_wday = 4; local.tm_hour = 5;
    Fixture f(false); f.cycle(0);
    const auto request = scheduler.poll(f.monitor.status(), &local);
    CHECK(request && *request == RestartReason::WeeklySchedule && store.writes == 1);
    scheduler.recordDecision(f.monitor.requestRestart(*request));
    CHECK(scheduler.status().decision == RestartDecision::Accepted);
    f.phase(RecoveryPhase::WaitDisabled); CHECK(f.transport.downs() == 1);
    Scheduler reboot(store); CHECK(reboot.begin({}).ok());
    CHECK(!reboot.poll(f.monitor.status(), &local) && store.writes == 1);
    // Next occurrence collides with an existing recovery; consume once, without
    // queuing another restart after that recovery ends.
    local.tm_mday = 19;
    CHECK(!reboot.poll(f.monitor.status(), &local) && store.writes == 2);
    CHECK(reboot.status().decision == RestartDecision::Busy);
    f.step(f.options.disablePauseMs); f.phase(RecoveryPhase::WaitOnline);
    f.step(f.options.warmupMs); f.phase(RecoveryPhase::Cooldown);
    f.step(f.options.cooldownMs); f.phase(RecoveryPhase::Idle);
    CHECK(!reboot.poll(f.monitor.status(), &local) && f.transport.downs() == 1 && store.writes == 2);
}
void manualDown() {
    Fixture f; f.transport.enabled = false; f.threshold(); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::InterfaceDisabled && !f.store.pending && f.transport.mutations.empty());
}
void uncertainDisable() {
    Fixture f; f.transport.downErrors.push_back(ErrorReason::ReadTimeout); f.threshold();
    f.phase(RecoveryPhase::WaitOnline);
    CHECK(f.transport.enabled && !f.store.pending && f.transport.downs() == 1 && f.transport.ups() == 1);
}
void lostDisable() {
    Fixture f; f.transport.holdDown = true; f.threshold(); f.until([&] { return f.transport.downs() == 1; });
    CHECK(!f.transport.enabled && f.store.pending);
    f.platform.wifi = false; ++f.platform.losses; f.step();
    CHECK(f.transport.cancels == 1 && f.monitor.status().recovery == RecoveryPhase::Enable);
    const auto count = f.transport.requests.size(); f.step(1000); CHECK(f.transport.requests.size() == count);
    f.platform.controlOnline = false; f.reconnect(); f.phase(RecoveryPhase::WaitOnline);
    CHECK(f.transport.enabled && !f.store.pending && f.transport.downs() == 1);
}
void lossInPause() {
    Fixture f; f.disabled(); f.platform.wifi = false; ++f.platform.losses; f.step();
    CHECK(f.monitor.status().recovery == RecoveryPhase::Enable && f.store.pending);
    f.platform.controlOnline = false; f.reconnect(); f.phase(RecoveryPhase::WaitOnline);
    CHECK(f.transport.enabled && !f.store.pending);
    f.platform.wifi = false; ++f.platform.losses; f.step(); f.step(30000); f.step();
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::InternetUnavailable && !f.store.pending);
}
void reboot() {
    // New Network, KeeneticClient, Monitor and RAM; only journal + router state survive.
    for (bool alreadyUp : {false, true}) {
        Fixture f(false, 4, true, alreadyUp);
        CHECK(f.monitor.status().restorePending);
        f.platform.controlOnline = false; f.phase(RecoveryPhase::WaitOnline);
        CHECK(!f.store.pending && f.transport.enabled && f.transport.downs() == 0);
        CHECK(f.transport.ups() == (alreadyUp ? 0u : 1u));
    }
}
void boundedRetry() {
    Fixture f; for (unsigned i = 0; i < 3; ++i) f.transport.upErrors.push_back(ErrorReason::ConnectionFailure);
    f.disabled(); f.step(2000);
    f.until([&] { return f.monitor.status().lastRecoveryError == ErrorReason::ConnectionFailure; });
    CHECK(f.transport.ups() == 1 && !f.transport.enabled);
    f.step(4999); CHECK(f.transport.ups() == 1);
    f.step(); f.until([&] { return f.transport.ups() == 2 && !f.router.busy(); });
    f.step(5000); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.transport.ups() == 3 && f.store.pending && f.monitor.status().restorePending);
    f.step(299999); CHECK(f.transport.ups() == 3);
    f.platform.controlOnline = false; f.step(); f.phase(RecoveryPhase::WaitOnline);
    CHECK(f.transport.ups() == 4 && f.transport.downs() == 1 && !f.store.pending);
}
void storageFailures() {
    Fixture f; f.store.armError = ErrorReason::StorageFailure; f.threshold(); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.transport.mutations.empty() && f.monitor.status().reason == ErrorReason::StorageFailure);
    Fixture c; c.store.clearError = ErrorReason::StorageFailure; c.disabled(); c.step(2000); c.phase(RecoveryPhase::Cooldown);
    CHECK(c.store.pending && c.transport.enabled && c.monitor.status().reason == ErrorReason::StorageFailure);
    c.store.clearError = ErrorReason::None; c.step(300000); c.phase(RecoveryPhase::WaitOnline);
    CHECK(!c.store.pending && c.store.clears == 2 && c.transport.mutations.size() == 2);
    Fixture load; load.store.loadError = ErrorReason::StorageFailure;
    load.monitor.begin(ErrorReason::None, DisplayState::Disabled);
    CHECK(load.monitor.status().reason == ErrorReason::StorageFailure);
    CHECK(load.monitor.requestRestart(RestartReason::WeeklySchedule) == RestartDecision::Unavailable);
}
void fatalEnable() {
    Fixture f; f.transport.upErrors.push_back(ErrorReason::TlsFailure); f.disabled(); f.step(2000); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.router.blocked() && f.store.pending && f.monitor.status().lastRecoveryError == ErrorReason::TlsFailure);
    const auto requests = f.transport.requests.size(); f.step(300000); f.step();
    CHECK(f.transport.requests.size() == requests && f.store.pending);
}
void wrapTimers() {
    Fixture f(true, 4, false, true, true, 0xfffff000u); f.enabled();
    f.platform.failedTargets = 0; f.step(30000); f.phase(RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::None && f.now < 0xfffff000u);
    f.step(300000); CHECK(f.monitor.status().recovery == RecoveryPhase::Idle);
}
void freshnessTimeout() {
    Fixture f; f.threshold(); f.platform.pollBudget = 0;
    f.step(111001); CHECK(f.monitor.status().recovery == RecoveryPhase::Cooldown);
    CHECK(f.monitor.status().lastRecoveryError == ErrorReason::ReadTimeout && f.transport.mutations.empty());
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2); const std::string name = argv[1];
        if (name == "classifier") classifier(); else if (name == "configurable") configurableThresholds(); else if (name == "streak") streak();
        else if (name == "full_cycle") fullCycle(); else if (name == "fresh_internet") freshInternet();
        else if (name == "success") success(); else if (name == "failed_verify") failedVerify();
        else if (name == "disabled_option") disabledOption(); else if (name == "schedule_guard") scheduleGuard();
        else if (name == "scheduled_event") scheduledEvent();
        else if (name == "manual_down") manualDown(); else if (name == "uncertain_disable") uncertainDisable();
        else if (name == "lost_disable") lostDisable(); else if (name == "loss_in_pause") lossInPause();
        else if (name == "reboot") reboot(); else if (name == "bounded_retry") boundedRetry();
        else if (name == "storage_failures") storageFailures(); else if (name == "fatal_enable") fatalEnable();
        else if (name == "wrap") wrapTimers(); else if (name == "freshness_timeout") freshnessTimeout();
        else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
