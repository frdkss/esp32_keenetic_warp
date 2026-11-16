#include "warp/scheduler.h"
#include "warp/display.h"
#include "warp/status.h"
#include "nvs.h"
#include <Arduino.h>
#if OLED_ENABLED
#include <U8g2lib.h>
#include <Wire.h>
#endif
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string(__func__) + ": " + #x); } while (false)

struct MemoryStore : ScheduleStore {
    std::uint32_t date{0};
    unsigned loads{0}, writes{0};
    bool failLoad{false}, failWrite{false};
    OperationResult load(std::uint32_t& out) override { ++loads; out = date; return {failLoad ? ErrorReason::StorageFailure : ErrorReason::None}; }
    OperationResult consume(std::uint32_t value) override {
        ++writes;
        if (failWrite) return {ErrorReason::StorageFailure};
        date = value; return {ErrorReason::None};
    }
};
SystemStatus healthy() { SystemStatus s; s.state = SystemState::Healthy; s.timeSynchronized = s.internetConfirmed = true; return s; }
std::tm due(int day = 12) {
    std::tm t{}; t.tm_year = 126; t.tm_mon = 10; t.tm_mday = day; t.tm_wday = 4; t.tm_hour = 5; return t;
}
void minute() {
    MemoryStore store; Scheduler s(store); CHECK(s.begin({}).ok()); auto t = due(); auto status = healthy();
    t.tm_hour = 4; t.tm_min = 59; CHECK(!s.poll(status, &t));
    t = due(); t.tm_wday = 3; CHECK(!s.poll(status, &t));
    t = due(); t.tm_min = 1; CHECK(!s.poll(status, &t) && !store.writes);
    t = due(); CHECK(s.poll(status, &t) == RestartReason::WeeklySchedule);
    for (int sec = 0; sec < 60; ++sec) { t.tm_sec = sec; CHECK(!s.poll(status, &t)); }
    CHECK(store.writes == 1 && store.date == 20261112 && s.status().lastDate == store.date);
    t = due(19); CHECK(s.poll(status, &t) && store.writes == 2);
}
void correction() {
    MemoryStore store; Scheduler s(store); CHECK(s.begin({}).ok()); auto t = due(); auto status = healthy();
    CHECK(s.poll(status, &t));
    Scheduler reboot(store); CHECK(reboot.begin({}).ok());
    CHECK(!reboot.poll(status, &t));  // Power loss after consume, before request is also suppressed.
    t = due(5); CHECK(!reboot.poll(status, &t));
    t = due(); CHECK(!reboot.poll(status, &t));  // Backward correction / DST fold.
    status.timeSynchronized = false; t = due(19); CHECK(!reboot.poll(status, &t));
    status.timeSynchronized = true; CHECK(reboot.poll(status, &t));
    t = due(26); t.tm_min = 1; CHECK(!reboot.poll(status, &t));  // Forward step skips the minute.
    t.tm_min = 2; CHECK(!reboot.poll(status, &t) && store.writes == 2);
    // A forward jump landing in a future event permits one event, then keeps
    // the high watermark even when the clock is corrected backward.
    t = due(26); CHECK(reboot.poll(status, &t));
    t = due(19); CHECK(!reboot.poll(status, &t) && store.writes == 3);
}
void gates() {
    MemoryStore store; Scheduler s(store); CHECK(s.begin({}).ok()); auto t = due(); auto status = healthy();
    status.timeSynchronized = false; CHECK(!s.poll(status, &t) && !store.writes);
    status.timeSynchronized = true; CHECK(!s.poll(status, nullptr) && !store.writes);
    status.internetConfirmed = false; CHECK(!s.poll(status, &t) && store.writes == 1);
    CHECK(s.status().state == ScheduleState::Skipped && s.status().decision == RestartDecision::InternetUnconfirmed);
    status.internetConfirmed = true; CHECK(!s.poll(status, &t));
    Scheduler reboot(store); CHECK(reboot.begin({}).ok()); CHECK(!reboot.poll(status, &t));
    t = due(19); status.recovery = RecoveryPhase::ConfirmInternet;
    CHECK(!reboot.poll(status, &t) && reboot.status().decision == RestartDecision::Busy);
    status.recovery = RecoveryPhase::Idle; CHECK(!reboot.poll(status, &t));
    t = due(26); status.restorePending = true; CHECK(!reboot.poll(status, &t));
    CHECK(reboot.status().decision == RestartDecision::Busy && store.writes == 3);
}
void settings() {
    MemoryStore store; Scheduler s(store); auto status = healthy(); auto t = due();
    CHECK(!s.poll(status, &t));
    CHECK(s.begin({false, 4, 5, 0}).ok() && !store.loads);
    CHECK(!s.poll(status, &t) && !store.writes);
    CHECK(!s.begin({true, 7, 5, 0}).ok()); CHECK(!s.begin({true, 4, 24, 0}).ok());
    CHECK(!s.begin({true, 4, 5, 60}).ok());
    CHECK(s.begin({true, 0, 23, 59}).ok());
    t = due(15); t.tm_wday = 0; t.tm_hour = 23; t.tm_min = 59;
    CHECK(s.poll(status, &t)); s.recordDecision(RestartDecision::Unavailable);
    CHECK(s.status().state == ScheduleState::Skipped && s.status().decision == RestartDecision::Unavailable);
}
void dates() {
    CHECK(validScheduleDate(20240229) && !validScheduleDate(20250229) && !validScheduleDate(21000229));
    CHECK(!validScheduleDate(20260431) && !validScheduleDate(20260001) && !validScheduleDate(20261301));
    MemoryStore store; Scheduler s(store); CHECK(s.begin({}).ok()); auto status = healthy(); auto t = due();
    t.tm_mon = 1; t.tm_mday = 30; CHECK(!s.poll(status, &t));
    t = due(); t.tm_year = -1; CHECK(!s.poll(status, &t));
    t = due(); t.tm_sec = -1; CHECK(!s.poll(status, &t));
    CHECK(!store.writes);
}
void schedulerFailure() {
    MemoryStore store; store.failLoad = true; Scheduler s(store); CHECK(!s.begin({}).ok());
    auto status = healthy(); auto t = due(); CHECK(!s.poll(status, &t) && !store.writes);
    store.failLoad = false; store.failWrite = true; CHECK(s.begin({}).ok());
    for (int i = 0; i < 10000; ++i) CHECK(!s.poll(status, &t));
    CHECK(store.writes == 1 && s.status().state == ScheduleState::Error && s.status().error == ErrorReason::StorageFailure);
    store.date = 20260230; CHECK(!s.begin({}).ok());
}

std::vector<unsigned char> durableBlob;
unsigned writes = 0, commits = 0, closes = 0;
int openError = ESP_OK, readError = ESP_OK, writeError = ESP_OK, commitError = ESP_OK;
int nvs_open(const char* name, int, nvs_handle_t* handle) { CHECK(std::string(name) == "warp"); *handle = 1; return openError; }
void nvs_close(nvs_handle_t) { ++closes; }
int nvs_get_blob(nvs_handle_t, const char* key, void* out, std::size_t* size) {
    CHECK(std::string(key) == "weekly_date");
    if (readError != ESP_OK) return readError;
    if (durableBlob.empty()) return ESP_ERR_NVS_NOT_FOUND;
    if (*size < durableBlob.size()) return -10;
    std::memcpy(out, durableBlob.data(), durableBlob.size()); *size = durableBlob.size(); return ESP_OK;
}
int nvs_set_blob(nvs_handle_t, const char* key, const void* value, std::size_t size) {
    CHECK(std::string(key) == "weekly_date"); ++writes;
    if (writeError != ESP_OK) return writeError;
    const auto* bytes = static_cast<const unsigned char*>(value); durableBlob.assign(bytes, bytes + size); return ESP_OK;
}
int nvs_commit(nvs_handle_t) { ++commits; return commitError; }
void durable() {
    NvsScheduleStore store; std::uint32_t date = 999;
    CHECK(store.load(date).ok() && date == 0 && writes == 0 && commits == 0);
    CHECK(store.consume(20261112).ok() && writes == 1 && commits == 1 && durableBlob.size() == 8);
    NvsScheduleStore reboot; CHECK(reboot.load(date).ok() && date == 20261112);
    for (int i = 0; i < 100; ++i) CHECK(reboot.consume(20261112).ok() && reboot.consume(20261105).ok());
    CHECK(writes == 1 && commits == 1);
    CHECK(reboot.consume(20261119).ok() && writes == 2 && commits == 2);
    Scheduler scheduler(reboot); CHECK(scheduler.begin({}).ok()); auto t = due(19);
    CHECK(!scheduler.poll(healthy(), &t) && writes == 2);
}
void corrupt() {
    NvsScheduleStore store; CHECK(store.consume(20261112).ok()); const auto original = durableBlob; std::uint32_t date;
    for (unsigned pos = 0; pos < 4; ++pos) {
        durableBlob = original; durableBlob[pos] ^= 0xff;
        CHECK(!store.load(date).ok() && date == 0 && !store.consume(20261119).ok());
    }
    durableBlob = original; durableBlob.resize(7); CHECK(!store.load(date).ok());
    durableBlob = original; durableBlob.push_back(0); CHECK(!store.load(date).ok());
    durableBlob = original; for (unsigned i = 4; i < 8; ++i) durableBlob[i] = 0;
    CHECK(!store.load(date).ok() && !store.consume(20261119).ok() && writes == 1);
    CHECK(!store.consume(20260230).ok() && writes == 1);
}
void nvsFailures() {
    NvsScheduleStore store; std::uint32_t date = 123;
    openError = -1; CHECK(!store.load(date).ok() && !date && !closes);
    openError = ESP_ERR_NVS_NOT_FOUND; CHECK(store.load(date).ok() && !date);
    openError = ESP_OK; readError = -1; CHECK(!store.consume(20261112).ok() && !writes);
    readError = ESP_OK; writeError = -1; CHECK(!store.consume(20261112).ok() && !commits);
    writeError = ESP_OK; commitError = -1;
    Scheduler s(store); CHECK(s.begin({}).ok()); auto t = due(); CHECK(!s.poll(healthy(), &t));
    CHECK(s.status().error == ErrorReason::StorageFailure && commits == 1);
    // Model a power loss with an uncertain commit visible on reboot.
    commitError = ESP_OK; Scheduler reboot(store); CHECK(reboot.begin({}).ok());
    CHECK(!reboot.poll(healthy(), &t) && writes == 2 && commits == 1);
}

void serial() {
    Print output; auto s = healthy(); s.recovery = RecoveryPhase::WaitDisabled; s.recoveryAttempts = 3;
    s.consecutiveFailures = 5; s.restorePending = true; s.schedule.state = ScheduleState::Skipped;
    s.schedule.lastDate = 20261112; s.schedule.decision = RestartDecision::Busy;
    status::writeSerial(output, s);
    for (const auto* expected : {"state=OK", "failures=5", "recovery=OFF WAIT", "attempts=3", "time=1", "internet=1",
         "restore_pending=1", "weekly=SKIPPED", "weekly_date=20261112", "weekly_decision=BUSY"})
        CHECK(output.text.find(expected) != output.text.npos);
    CHECK(output.text.find("SYNTHETIC_PASSWORD") == output.text.npos);
    for (unsigned i = 0; i <= static_cast<unsigned>(RecoveryPhase::Cooldown); ++i)
        CHECK(std::string(status::label(static_cast<RecoveryPhase>(i))) != "UNKNOWN");
}
void displayGate() {
    Display display; board::DisplayProfile p{false, board::DisplayDriver::Unconfirmed, -1, -1, 0, 255, 72, 40};
    CHECK(display.begin(p, false) == DisplayState::Disabled);
#if OLED_ENABLED
    CHECK(display.begin(p) == DisplayState::Unconfirmed && fakeWire::begins == 0);
    p = {true, board::DisplayDriver::Ssd1306_72x40, 8, 9, 0x3c, 0, 72, 40};  // Synthetic pins only.
    auto bad = p; bad.scl = bad.sda; CHECK(display.begin(bad) == DisplayState::Unconfirmed);
    bad = p; bad.address = 0; CHECK(display.begin(bad) == DisplayState::Unconfirmed);
    bad = p; bad.rotation = 4; CHECK(display.begin(bad) == DisplayState::Unconfirmed);
    bad = p; bad.width = 128; CHECK(display.begin(bad) == DisplayState::Unconfirmed);
    CHECK(fakeWire::begins == 0);
    fakeWire::ack = false; CHECK(display.begin(p) == DisplayState::Unavailable);
    const auto frames = fakeOled::frames; display.render(healthy()); CHECK(fakeOled::frames == frames);
    fakeWire::ack = true; CHECK(display.begin(p) == DisplayState::Ready && fakeWire::timeout == 20);
    fakeWire::ack = false; CHECK(display.check() == DisplayState::Unavailable);
    const auto probes = fakeWire::probes;
    for (int i = 0; i < 100; ++i) { display.check(); display.render(healthy()); }
    CHECK(fakeWire::probes == probes && fakeOled::frames == frames);
#else
    CHECK(display.begin(p) == DisplayState::Disabled && display.check() == DisplayState::Disabled);
    display.render(healthy());
#endif
}
void layout() {
#if OLED_ENABLED
    Display display; board::DisplayProfile p{true, board::DisplayDriver::Ssd1306_72x40, 8, 9, 0x3c, 0, 72, 40};
    for (unsigned rotation = 0; rotation < 4; ++rotation) {
        p.rotation = static_cast<std::uint8_t>(rotation); CHECK(display.begin(p) == DisplayState::Ready);
        for (auto state : {SystemState::Starting, SystemState::Waiting, SystemState::Healthy, SystemState::Degraded, SystemState::Recovering, SystemState::Error}) {
            auto s = healthy(); s.state = state; s.reason = state == SystemState::Recovering ? ErrorReason::Pending : ErrorReason::InterfaceDisabled;
            s.recovery = RecoveryPhase::WaitDisabled; display.render(s);
            CHECK(fakeOled::draws.size() == 2 && fakeOled::draws[0].text == status::label(state));
            if (state == SystemState::Recovering) CHECK(fakeOled::draws[1].text == "OFF WAIT");
            for (const auto& draw : fakeOled::draws) CHECK(draw.x >= 0 && draw.y < fakeOled::height && draw.x + draw.width <= fakeOled::width);
            if (rotation % 2 == 0 && (state == SystemState::Healthy || state == SystemState::Degraded)) CHECK(fakeOled::draws[0].font == 18);
        }
    }
#endif
}
void boardDisplay() {
    Display display;
#if OLED_ENABLED
    CHECK(display.begin(board::current().display) == DisplayState::Ready);
    CHECK(fakeWire::sda == 5 && fakeWire::scl == 6 && fakeWire::address == 0x3C);
    const auto frames = fakeOled::frames;
    display.render(healthy());
    CHECK(fakeOled::frames == frames + 1 && fakeOled::draws.size() == 2);
    CHECK(fakeOled::draws[0].text == "OK");
#else
    CHECK(display.begin(board::current().display) == DisplayState::Disabled);
#endif
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2); const std::string name = argv[1];
        if (name == "minute") minute(); else if (name == "correction") correction(); else if (name == "gates") gates();
        else if (name == "settings") settings(); else if (name == "dates") dates(); else if (name == "scheduler_failure") schedulerFailure();
        else if (name == "durable") durable(); else if (name == "corrupt") corrupt(); else if (name == "nvs_failures") nvsFailures();
        else if (name == "serial") serial(); else if (name == "display_gate") displayGate(); else if (name == "layout") layout();
        else if (name == "board_display") boardDisplay();
        else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
