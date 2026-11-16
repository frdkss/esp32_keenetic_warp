#include "monitor_fixture.h"
#include <crtdbg.h>
#include <ctime>

struct WeeklyStore : ScheduleStore {
    std::uint32_t date{0}; unsigned writes{0};
    OperationResult load(std::uint32_t& value) override { value = date; return {ErrorReason::None}; }
    OperationResult consume(std::uint32_t value) override { date = value; ++writes; return {ErrorReason::None}; }
};
void reach(Fixture& f, RecoveryPhase phase) {
    if (phase == RecoveryPhase::Idle) { f.cycle(0); return; }
    f.threshold();
    if (phase == RecoveryPhase::ConfirmInternet) return;
    if (phase == RecoveryPhase::Inspect || phase == RecoveryPhase::Disable || phase == RecoveryPhase::WaitDisabled) {
        f.phase(phase); return;
    }
    f.phase(RecoveryPhase::WaitDisabled); f.step(f.options.disablePauseMs);
    if (phase == RecoveryPhase::Enable) { CHECK(f.monitor.status().recovery == phase); return; }
    f.phase(RecoveryPhase::WaitOnline);
    if (phase == RecoveryPhase::WaitOnline) return;
    f.step(f.options.warmupMs);
    if (phase == RecoveryPhase::Verify) { CHECK(f.monitor.status().recovery == phase); return; }
    f.phase(RecoveryPhase::Cooldown);
}
void loss(unsigned index, const std::string& mode) {
    CHECK(index <= static_cast<unsigned>(RecoveryPhase::Cooldown));
    Fixture f; reach(f, static_cast<RecoveryPhase>(index));
    const bool obligation = f.store.pending;
    const auto requests = f.transport.requests.size();
    if (mode == "wifi") { f.platform.wifi = false; ++f.platform.losses; }
    else if (mode == "time") f.epochOffset = 100;
    else { f.transport.offline = true; f.transport.hold = true; }
    f.step();
    for (unsigned i = 0; i < 20; ++i) f.step();
    if (mode != "lan") CHECK(f.transport.requests.size() == requests);
    // Give any outstanding router operation its whole timeout. A lost reply
    // cannot erase a durable obligation or cause a second disable.
    if (mode == "lan") { f.step(11001); f.transport.hold = false; }
    if (obligation) CHECK(f.store.pending);
    CHECK(f.transport.downs() <= 1);
    f.platform.failedTargets = 0;
    f.transport.offline = f.transport.hold = false;
    f.epochOffset = 0;
    if (mode == "wifi") f.reconnect();
    else { ++f.platform.sync; f.step(); }
    for (unsigned i = 0; i < 100 && f.store.pending; ++i) f.step(10000);
    CHECK(!f.store.pending && f.transport.enabled);
    CHECK(f.transport.downs() <= 1);
    if (obligation) CHECK(f.store.clears == 1);
}
void rebootMatrix() {
    for (unsigned phase = 0; phase <= static_cast<unsigned>(RecoveryPhase::Cooldown); ++phase) {
        Fixture before; reach(before, static_cast<RecoveryPhase>(phase));
        const bool obligation = before.store.pending;
        // Only the persisted intent and external router state survive reset.
        Fixture after(false, 4, obligation, before.transport.enabled);
        after.platform.controlOnline = false;
        if (obligation) after.phase(RecoveryPhase::WaitOnline);
        else for (unsigned i = 0; i < 40; ++i) after.step();
        CHECK(after.transport.enabled && !after.store.pending && after.transport.downs() == 0);
        CHECK(after.store.arms == 0 && after.store.clears == (obligation ? 1u : 0u));
    }
}
void soak() {
    Fixture f; WeeklyStore store; Scheduler scheduler(store); CHECK(scheduler.begin({}).ok());
    // Warm up every router path before comparing native CRT live allocations.
    f.enabled(); f.platform.failedTargets = 0; f.step(30000); f.phase(RecoveryPhase::Cooldown);
    f.step(f.options.cooldownMs); f.phase(RecoveryPhase::Idle);
    unsigned scheduled = 0, outages = 0, reconnects = 0, completed = 0;
    auto run = [&](unsigned begin, unsigned minutes) {
        for (unsigned i = begin; i < begin + minutes; ++i) {
            f.transport.requests.clear(); f.transport.mutations.clear();
            if (i % 300 == 0) ++f.platform.sync;  // periodic SNTP, < six-hour expiry
            f.step(60000);
            if (i % 97 == 0) {
                f.platform.wifi = false; ++f.platform.losses; f.step(); f.reconnect(); ++reconnects;
            }
            const bool online = i % 37 != 0;
            if (!online) ++outages;
            f.cycle(i % 23 < 4 ? 3 : 0, online);  // bursts below the agreed five-cycle threshold
            const std::time_t epoch = static_cast<std::time_t>(f.platform.epoch + 10800);
            std::tm local{}; CHECK(gmtime_s(&local, &epoch) == 0);
            if (const auto request = scheduler.poll(f.monitor.status(), &local)) {
                const auto result = f.monitor.requestRestart(*request); scheduler.recordDecision(result);
                CHECK(result == RestartDecision::Accepted); ++scheduled;
                f.phase(RecoveryPhase::WaitDisabled); f.step(f.options.disablePauseMs);
                f.phase(RecoveryPhase::WaitOnline); f.platform.failedTargets = 0;
                f.step(f.options.warmupMs); f.phase(RecoveryPhase::Cooldown); ++completed;
            }
            CHECK(f.transport.downs() <= 1 && f.transport.enabled && !f.store.pending);
            CHECK(f.monitor.status().recoveryAttempts == scheduled + 1);
            CHECK(f.store.arms == completed + 1 && f.store.clears == completed + 1);
            CHECK(f.transport.requests.size() < 32);
        }
    };
    run(0, 1440);  // one virtual day for runtime/library lazy allocations
    _CrtMemState before{}, after{}, difference{};
    _CrtMemCheckpoint(&before);
    run(1440, 90 * 1440);
    _CrtMemCheckpoint(&after);
    _CrtMemDifference(&difference, &before, &after);
    CHECK(after.lCounts[_NORMAL_BLOCK] == before.lCounts[_NORMAL_BLOCK]);
    CHECK(after.lSizes[_NORMAL_BLOCK] == before.lSizes[_NORMAL_BLOCK]);
    CHECK(scheduled >= 12 && reconnects > 1300 && outages > 3500);
    std::cout << "virtual_minutes=131040 reconnects=" << reconnects << " outages=" << outages
              << " scheduled=" << scheduled << " recovery_writes=" << f.store.arms + f.store.clears
              << " schedule_writes=" << store.writes << " live_heap_delta=0\n";
}
int main(int argc, char** argv) {
    try {
        CHECK(argc >= 2); const std::string mode = argv[1];
        if (mode == "reboot") rebootMatrix();
        else if (mode == "soak") soak();
        else { CHECK(argc == 3); loss(static_cast<unsigned>(std::stoul(argv[2])), mode); }
        std::cout << mode << " passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << "\n"; return 1; }
}
