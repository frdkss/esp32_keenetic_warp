#pragma once
#include "warp/monitor.h"
#include "warp/network.h"
#include "warp/keenetic.h"
#include "warp/scheduler.h"
#include "native_crypto.h"
#include <cstring>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string(__func__) + ": " + #x); } while (false)

struct Store : RecoveryStore {
    bool pending{false};
    ErrorReason loadError{ErrorReason::None}, armError{ErrorReason::None}, clearError{ErrorReason::None};
    unsigned arms{0}, clears{0};
    OperationResult load(const keenetic::Settings&, bool& value) override { value = pending; return {loadError}; }
    OperationResult arm(const keenetic::Settings&) override { ++arms; if (armError == ErrorReason::None) pending = true; return {armError}; }
    OperationResult clear() override { ++clears; if (clearError == ErrorReason::None) pending = false; return {clearError}; }
};
struct Platform : NetworkPlatform {
    bool wifi{true}, controlOnline{true}, active{false};
    unsigned sync{0}, losses{0}, failedTargets{3};
    int pollBudget{-1};
    std::int64_t epoch{1794614400};
    std::string url;
    unsigned probes{0};
    bool beginWifi(CredentialsView) override { return true; }
    void connectWifi() override {}
    void disconnectWifi() override {}
    bool wifiConnected() const override { return wifi; }
    std::uint32_t wifiLossGeneration() const override { return losses; }
    bool startTimeSync(const char*) override { return true; }
    std::uint32_t timeSyncGeneration() const override { return sync; }
    std::int64_t epochSeconds() const override { return epoch; }
    bool startProbe(std::string_view value, std::uint32_t, std::uint32_t) override {
        CHECK(!active); active = true; url = value; ++probes; return true;
    }
    bool pollProbe(CheckResult& result) override {
        if (!active || pollBudget == 0) return false;
        if (pollBudget > 0) --pollBudget;
        active = false;
        const bool control = url.find("control") != url.npos;
        const auto index = control ? 0u : static_cast<unsigned>(url[url.find("target-") + 7] - '0');
        const bool good = control ? controlOnline : index >= failedTargets;
        result = {good ? ErrorReason::None : ErrorReason::HttpFailure, good ? 302 : 503, 1, good, true};
        return true;
    }
    void cancelProbe() override { active = false; }
};
struct Transport : KeeneticTransport {
    Store& store;
    keenetic::Response response{};
    std::vector<bool> mutations;
    std::vector<std::string> requests;
    std::deque<ErrorReason> upErrors, downErrors;
    bool enabled{true}, active{false}, holdDown{false}, hold{false}, offline{false};
    unsigned cancels{0};
    explicit Transport(Store& value) : store(value) {}
    bool start(const keenetic::Settings&, std::string_view request) override {
        CHECK(!active); active = true; requests.emplace_back(request); response.clear();
        response.diagnostic.error = ErrorReason::None; response.diagnostic.httpStatus = 200;
        if (offline) { response.diagnostic.error = ErrorReason::ConnectionFailure; return true; }
        std::string body;
        if (request.substr(0, 10) == "GET /auth ") {
            response.diagnostic.httpStatus = 401;
            std::strcpy(response.authScheme.data(), "x-ndw2-interactive");
            std::strcpy(response.realm.data(), "synthetic-realm"); std::strcpy(response.challenge.data(), "synthetic-challenge");
        } else if (request.substr(0, 11) == "POST /auth ") {
            response.cookieSeen = true; std::strcpy(response.cookie.data(), "sid=synthetic-session");
        } else if (request.find("GET /rci/show/version ") == 0) {
            body = R"({"hw_id":"KN-4010","title":"5.1.8"})";
        } else if (request.find("GET /rci/show/interface ") == 0) {
            body = std::string(R"({"Wireguard7":{"id":"Wireguard7","type":"Wireguard","state":")") +
                (enabled ? "up" : "down") + R"(","link":"up","connected":"yes"}})";
        } else if (request.find("POST /rci/interface ") == 0) {
            CHECK(store.pending);  // Every changing command follows durable intent.
            CHECK(request.find("\"name\":\"Wireguard7\"") != request.npos);
            const bool up = request.find("\"up\":true") != request.npos;
            mutations.push_back(up);
            auto& errors = up ? upErrors : downErrors;
            const auto error = errors.empty() ? ErrorReason::None : errors.front();
            if (!errors.empty()) errors.pop_front();
            // A lost disable reply may hide a successful side effect. Failed
            // enabling remains off, to exercise actual retry/compensation.
            if (!up || error == ErrorReason::None) enabled = up;
            response.diagnostic.error = error;
            body = R"({"up":{"status":[{"status":"message","code":"72155286","ident":"Network::Interface::Base","message":"synthetic"}]}})";
            if (!up && holdDown) hold = true;
        } else throw std::runtime_error("Unexpected router request");
        std::memcpy(response.body.data(), body.data(), body.size()); response.bodySize = body.size();
        return true;
    }
    const keenetic::Response* poll() override { if (hold) return nullptr; CHECK(active); active = false; return &response; }
    void cancel() override { ++cancels; active = hold = false; }
    unsigned ups() const { unsigned count = 0; for (bool value : mutations) if (value) ++count; return count; }
    unsigned downs() const { return static_cast<unsigned>(mutations.size()) - ups(); }
};
struct Fixture {
    Platform platform;
    Network network{platform};
    Store store;
    Transport transport{store};
    KeeneticClient router{network, transport};
    Monitor monitor{network, router, store};
    MonitorSettings options{};
    std::uint32_t now{0}, start{0};
    std::uint64_t elapsedMs{0};
    std::int64_t epochOffset{0};
    explicit Fixture(bool automatic = true, unsigned targets = 4, bool pending = false, bool enabled = true,
                     bool online = true, std::uint32_t initialMs = 0) {
        now = start = initialMs;
        NetworkSettings s; s.controlCount = 1; s.targetCount = static_cast<std::uint8_t>(targets); s.checkIntervalMs = 86400000;
        std::strcpy(s.controls[0].data(), "https://control.invalid/"); std::strcpy(s.timezone.data(), "MSK-3");
        for (unsigned i = 0; i < targets; ++i) {
            const auto text = "https://target-" + std::to_string(i) + ".invalid/";
            std::strcpy(s.targets[i].data(), text.c_str());
        }
        CHECK(network.begin({"synthetic", "", "synthetic", "synthetic"}, s, now).ok());
        keenetic::Settings rs;
        std::strcpy(rs.address.data(), "192.0.2.1"); std::strcpy(rs.tlsName.data(), "router.invalid");
        std::strcpy(rs.interfaceName.data(), "Wireguard7");
        CHECK(router.begin({"", "", "synthetic", "synthetic"}, rs).ok());
        store.pending = pending; transport.enabled = enabled; options.autoRecovery = automatic;
        monitor.begin(ErrorReason::None, DisplayState::Disabled, options);
        step();
        if (online) { ++platform.sync; step(); }
    }
    void step(std::uint32_t delta = 1) {
        now += delta;
        elapsedMs += delta;
        platform.epoch = 1794614400 + static_cast<std::int64_t>(elapsedMs / 1000) + epochOffset;
        network.tick(now); router.tick(now); monitor.tick(now);
    }
    template<class Predicate> void until(Predicate condition) {
        for (unsigned i = 0; i < 300; ++i) { if (condition()) return; step(); }
        throw std::runtime_error("Fixture deadline, phase=" + std::to_string(static_cast<unsigned>(monitor.status().recovery)));
    }
    void phase(RecoveryPhase target) { until([&] { return monitor.status().recovery == target; }); }
    void cycle(unsigned failed = 3, bool internet = true) {
        platform.failedTargets = failed; platform.controlOnline = internet;
        const auto previous = network.checks().sequence;
        if (!network.busy()) CHECK(network.requestChecks());
        until([&] { return network.checks().sequence != previous; });
    }
    void threshold() { for (unsigned i = 0; i < 5; ++i) cycle(); CHECK(monitor.status().recovery == RecoveryPhase::ConfirmInternet); }
    void disabled() { threshold(); phase(RecoveryPhase::WaitDisabled); CHECK(!transport.enabled && store.pending); }
    void enabled() { disabled(); step(options.disablePauseMs); phase(RecoveryPhase::WaitOnline); CHECK(transport.enabled && !store.pending); }
    void reconnect() { platform.wifi = true; step(); ++platform.sync; step(); }
};
