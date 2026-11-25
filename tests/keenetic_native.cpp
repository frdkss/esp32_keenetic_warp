#include "warp/keenetic.h"
#include "warp/network.h"
#include "native_crypto.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)

// Test access uses the same sole command owner as the firmware; no public write API.
namespace warp { class Monitor { public:
    static OperationResult set(KeeneticClient& client, bool enabled) { return client.setWarpEnabled(enabled); }
}; }
struct NetworkFake : NetworkPlatform {
    bool wifi{true}; unsigned sync{0}, losses{0};
    std::int64_t epoch{1794614400};
    bool beginWifi(CredentialsView) override { return true; }
    void connectWifi() override {}
    void disconnectWifi() override {}
    bool wifiConnected() const override { return wifi; }
    std::uint32_t wifiLossGeneration() const override { return losses; }
    bool startTimeSync(const char*) override { return true; }
    std::uint32_t timeSyncGeneration() const override { return sync; }
    std::int64_t epochSeconds() const override { return epoch; }
    bool startProbe(std::string_view, std::uint32_t, std::uint32_t) override { return true; }
    bool pollProbe(CheckResult&) override { return false; }
    void cancelProbe() override {}
};
struct TransportFake : KeeneticTransport {
    keenetic::Response response{};
    std::vector<std::string> requests;
    bool ready{false}, active{false}; unsigned cancels{0};
    bool start(const keenetic::Settings& s, std::string_view request) override {
        CHECK(!active && keenetic::validSettings(s));
        CHECK(std::string(s.address.data()) == "192.0.2.1" && std::string(s.tlsName.data()) == "router.invalid");
        CHECK(request.find("Host: router.invalid:443\r\n") != request.npos);
        requests.emplace_back(request); active = true; return true;
    }
    const keenetic::Response* poll() override {
        if (!ready) return nullptr;
        ready = active = false; return &response;
    }
    void cancel() override { ++cancels; active = ready = false; response.clear(); }
    void reply(int status, std::string_view body = "", ErrorReason error = ErrorReason::None,
               std::string_view headers = "") {
        CHECK(active); response.clear();
        if (error == ErrorReason::None) {
            const auto wire = "HTTP/1.1 " + std::to_string(status) + " Reason\r\n" + std::string(headers) +
                "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
            keenetic::ResponseParser parser(response);
            for (char ch : wire) parser.feed(ch);
            CHECK(parser.done() && parser.error() == ErrorReason::None);
        }
        response.diagnostic.error = error; ready = true;
    }
};
keenetic::Settings settings() {
    keenetic::Settings s;
    std::strcpy(s.address.data(), "192.0.2.1"); std::strcpy(s.tlsName.data(), "router.invalid");
    std::strcpy(s.interfaceName.data(), "Wireguard7"); return s;
}
constexpr auto identity = R"({"hw_id":"KN-4010","title":"5.1.8"})";
constexpr auto ack = R"({"up":{"status":[{"status":"message","code":"72155286","ident":"Network::Interface::Base","message":"synthetic ack"}]}})";
std::string state(bool enabled) {
    return std::string(R"({"Wireguard7":{"id":"Wireguard7","type":"Wireguard","state":")") +
        (enabled ? "up" : "down") + R"(","link":"down","connected":"no"},"Wireguard1":{"id":"Wireguard1","state":"up"}})";
}
struct Fixture {
    NetworkFake platform;
    Network network{platform};
    TransportFake transport;
    KeeneticClient client{network, transport};
    std::uint32_t now{10};
    Fixture() {
        NetworkSettings s; s.controlCount = s.targetCount = 1;
        std::strcpy(s.controls[0].data(), "https://control.invalid/");
        std::strcpy(s.targets[0].data(), "https://target.invalid/"); std::strcpy(s.timezone.data(), "MSK-3");
        CHECK(network.begin({"test", "", "test", "test"}, s, 0).ok());
        network.tick(1); ++platform.sync; network.tick(2);
        CHECK(client.begin({"", "", "test\"\\login", "synthetic:password"}, settings()).ok());
    }
    void tick() { client.tick(now++); }
    void reply(int http, std::string_view body = "", std::string_view headers = "") {
        transport.reply(http, body, ErrorReason::None, headers); tick();
    }
    void expect(std::string_view prefix) {
        tick(); CHECK(transport.active); CHECK(transport.requests.back().substr(0, prefix.size()) == prefix);
        CHECK(transport.requests.back().find("synthetic:password") == std::string::npos);
    }
    void auth() {
        expect("GET /auth ");
        reply(401, "", "WWW-Authenticate: x-ndw2-interactive\r\nX-NDM-Realm: test:realm\r\n"
            "X-NDM-Challenge: SYNTHETIC_CHALLENGE\r\nSet-Cookie: sid=challenge; HttpOnly; Secure\r\n");
        expect("POST /auth ");
        CHECK(transport.requests.back().find("Cookie: sid=challenge\r\n") != std::string::npos);
        reply(200, "", "Set-Cookie: sid=authenticated; HttpOnly; Secure\r\n");
        expect("GET /rci/show/version "); reply(200, identity);
    }
    void read(bool enabled = true) {
        CHECK(client.readWarpState().error == ErrorReason::Pending); auth();
        expect("GET /rci/show/interface "); reply(200, state(enabled));
        CHECK(!client.busy() && client.result().ok() && client.state().valid && client.state().enabled == enabled);
    }
};
void proofTest(const char* expected) {
    std::array<char, 65> proof{};
    CHECK(keenetic::makeProof("test\"\\login", "synthetic:password", "test:realm", "SYNTHETIC_CHALLENGE", proof));
    CHECK(std::string(proof.data()) == expected);
    std::array<char, 1025> body{};
    CHECK(keenetic::makeLoginBody("test\"\\login", proof.data(), body));
    CHECK(std::string(body.data()).find(R"(test\"\\login)") != std::string::npos);
    CHECK(!keenetic::makeProof("", "test", "test", "test", proof));
    for (char ch : proof) CHECK(ch == 0);
}
void settingsTest() {
    CHECK(keenetic::validSettings(settings()));
    auto upper = settings(); std::strcpy(upper.tlsName.data(), "ROUTER.invalid"); CHECK(keenetic::validSettings(upper));
    for (const auto* bad : {"", "host.invalid", "192.168.01.1", "1.2.3.256", "1.2.3.", "1.2.3.4:443"}) {
        auto s = settings(); s.address.fill(0); std::strcpy(s.address.data(), bad); CHECK(!keenetic::validSettings(s));
    }
    for (const auto* bad : {"http://host.invalid", "https://host.invalid", "host.invalid/path", "host:8443", "host\r\nx"}) {
        auto s = settings(); s.tlsName.fill(0); std::strcpy(s.tlsName.data(), bad); CHECK(!keenetic::validSettings(s));
    }
    for (const auto* bad : {"GigabitEthernet0", "Wireguard", "Wireguard1\"", "Wireguard1/down", "Bridge0"}) {
        auto s = settings(); s.interfaceName.fill(0); std::strcpy(s.interfaceName.data(), bad); CHECK(!keenetic::validSettings(s));
    }
}
void httpTest() {
    keenetic::Response r;
    keenetic::ResponseParser p(r);
    for (char ch : std::string("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: sid=one; Secure\r\n"
         "Set-Cookie: other=two; HttpOnly\r\n\r\n2\r\n{}\r\n0\r\n\r\n")) p.feed(ch);
    CHECK(p.done() && p.error() == ErrorReason::None && std::string(r.body.data()) == "{}");
    CHECK(std::string(r.cookie.data()) == "sid=one; other=two");
    CHECK(keenetic::mergeCookies(r.cookie, "sid=new; other=")); CHECK(std::string(r.cookie.data()) == "sid=new");
    r.clear(); keenetic::ResponseParser close(r);
    for (char ch : std::string("HTTP/1.0 200 OK\r\n\r\n{}")) close.feed(ch);
    CHECK(!close.done()); close.eof(); CHECK(close.done() && close.error() == ErrorReason::None);
    r.clear(); keenetic::ResponseParser interim(r);
    for (char ch : std::string("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")) interim.feed(ch);
    CHECK(interim.done() && interim.error() == ErrorReason::None);
}
void httpBadTest() {
    for (const auto* wire : {
        "HTTP/1.1 200 OK\n\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{",
        "HTTP/1.1 200 OK\r\nContent-Length: 32769\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nX-NDM-Realm: one\r\nX-NDM-Realm: two\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: \"invalid\"\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: x-ndw2-interactive\r\nWWW-Authenticate: Basic\r\n\r\n",
        "HTTP/1.1 100 Continue\r\nX-NDM-Realm: interim\r\n\r\nHTTP/1.1 401 Unauthorized\r\n\r\n",
        "HTTP/1.1 200 OK\r\nSet-Cookie: bad name=value\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{X\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nSet-Cookie: sid=evil\r\n\r\n"}) {
        keenetic::Response r; keenetic::ResponseParser p(r);
        for (char ch : std::string(wire)) p.feed(ch);
        p.eof(); CHECK(p.error() != ErrorReason::None);
    }
    keenetic::Response r; keenetic::ResponseParser p(r);
    for (char ch : std::string("HTTP/1.1 200 OK\r\nX: ") + std::string(8193, 'a')) p.feed(ch);
    CHECK(p.error() == ErrorReason::ResponseTooLarge);
}
void longAuthenticateTest() {
    const auto challenge = std::string("WWW-Authenticate: x-ndw2-interactive realm=\"test:realm\", opaque=\"") +
        std::string(160, 'a') + "\"\r\nX-NDM-Realm: test:realm\r\nX-NDM-Challenge: SYNTHETIC_CHALLENGE\r\n";
    keenetic::Response response;
    keenetic::ResponseParser parser(response);
    for (char ch : "HTTP/1.1 401 Unauthorized\r\n" + challenge + "Content-Length: 0\r\n\r\n") parser.feed(ch);
    CHECK(parser.done() && parser.error() == ErrorReason::None);
    CHECK(std::string(response.authScheme.data()) == "x-ndw2-interactive");
    CHECK(std::string(response.realm.data()) == "test:realm");
    CHECK(std::string(response.challenge.data()) == "SYNTHETIC_CHALLENGE");
    Fixture f;
    CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /auth "); f.reply(401, "", challenge);
    f.expect("POST /auth "); f.reply(200, "", "Set-Cookie: sid=authenticated; HttpOnly; Secure\r\n");
    f.expect("GET /rci/show/version "); f.reply(200, identity);
    f.expect("GET /rci/show/interface "); f.reply(200, state(true));
    CHECK(f.client.result().ok() && f.client.state().valid);
}
void schemaTest() {
    keenetic::WarpState s;
    keenetic::Identity id;
    CHECK(keenetic::parseIdentity(identity, id) == ErrorReason::None && std::string(id.model.data()) == "KN-4010" && std::string(id.version.data()) == "5.1.8");
    CHECK(keenetic::parseIdentity(R"({"hw_id":"KN-4010","title":"5.2"})", id) == ErrorReason::None);
    CHECK(keenetic::parseIdentity(R"({"hw_id":"KN-9999","title":"6.0.1"})", id) == ErrorReason::None && std::string(id.model.data()) == "KN-9999");
    CHECK(keenetic::parseIdentity(R"({"hw_id":"KN-4010","title":"5.0.9"})", id) == ErrorReason::UnsupportedRouter && std::string(id.version.data()) == "5.0.9");
    CHECK(keenetic::parseIdentity(R"({"hw_id":"KN-4010","title":"4.3"})", id) == ErrorReason::UnsupportedRouter);
    CHECK(keenetic::parseIdentity(R"({"title":"5.1.8"})", id) == ErrorReason::UnsupportedRouter);
    CHECK(keenetic::parseIdentity(R"({"hw_id":"KN<x>","title":"5.1.8"})", id) == ErrorReason::UnsupportedRouter && !id.model[0]);
    CHECK(keenetic::parseIdentity(std::string(identity) + " garbage", id) == ErrorReason::InvalidJson);
    CHECK(keenetic::parseState(state(true), "Wireguard7", s) == ErrorReason::None && s.valid && s.enabled && !s.connected);
    CHECK(keenetic::parseState(state(true), "Wireguard8", s) == ErrorReason::InterfaceNotFound && !s.valid);
    CHECK(keenetic::parseState(R"({"Wireguard7":{"id":"Wireguard8","state":"up"}})", "Wireguard7", s) == ErrorReason::InvalidResponse);
    CHECK(keenetic::parseCommand(ack) == ErrorReason::None);
    CHECK(keenetic::parseCommand("{}") == ErrorReason::InvalidResponse);
    CHECK(keenetic::parseCommand(R"({"up":{"status":[{"status":"error","message":"synthetic denial"}]}})") == ErrorReason::RciFailure);
    CHECK(keenetic::parseCommand(std::string(ack) + "{}") == ErrorReason::InvalidJson);
    CHECK(keenetic::parseState("[]", "Wireguard7", s) == ErrorReason::InvalidResponse);
}
void readTest() {
    Fixture f; f.read();
    CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface ");
    CHECK(f.transport.requests.back().find("Cookie: sid=authenticated\r\n") != std::string::npos);
    f.reply(200, state(false)); CHECK(f.client.result().ok() && !f.client.state().enabled);
    CHECK(f.transport.requests.size() == 5);
}
void changeTest() {
    Fixture f; f.read();
    for (bool enable : {false, true}) {
        CHECK(Monitor::set(f.client, enable).error == ErrorReason::Pending);
        f.expect("GET /rci/show/interface "); f.reply(200, state(!enable));
        f.expect("POST /rci/interface ");
        const auto& request = f.transport.requests.back();
        CHECK(request.find(std::string("{\"name\":\"Wireguard7\",\"up\":") + (enable ? "true}" : "false}")) != std::string::npos);
        CHECK(request.find("Wireguard1") == request.npos);
        f.reply(200, ack); CHECK(f.client.busy());
        f.expect("GET /rci/show/interface "); f.reply(200, state(enable));
        CHECK(f.client.result().ok() && f.client.state().enabled == enable);
    }
    CHECK(Monitor::set(f.client, true).error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface "); f.reply(200, state(true)); CHECK(f.client.result().ok());
}
void expiryTest() {
    Fixture f; f.read();
    CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface "); f.reply(401);
    f.auth(); f.expect("GET /rci/show/interface "); f.reply(401);
    CHECK(f.client.blocked() && f.client.result().error == ErrorReason::AuthenticationFailed);
    CHECK(f.transport.requests.size() == 9);
    Fixture g; g.read(); CHECK(Monitor::set(g.client, false).error == ErrorReason::Pending);
    g.expect("GET /rci/show/interface "); g.reply(200, state(true));
    g.expect("POST /rci/interface "); g.reply(200, ack);
    g.expect("GET /rci/show/interface "); g.reply(401);
    g.auth(); g.expect("GET /rci/show/interface "); g.reply(200, state(false));
    CHECK(g.client.result().ok());
    unsigned changes = 0;
    for (const auto& request : g.transport.requests) if (request.find("POST /rci/interface ") == 0) ++changes;
    CHECK(changes == 1);
}
void authTlsTest() {
    Fixture f; CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /auth ");
    f.reply(401, "", "WWW-Authenticate: x-ndw2-interactive\r\nX-NDM-Realm: test\r\nX-NDM-Challenge: test\r\n");
    f.expect("POST /auth "); f.reply(401);
    CHECK(f.client.blocked() && f.client.result().error == ErrorReason::AuthenticationFailed);
    CHECK(Monitor::set(f.client, false).error == ErrorReason::AuthenticationFailed);
    Fixture g; CHECK(g.client.readWarpState().error == ErrorReason::Pending); g.expect("GET /auth ");
    g.transport.reply(0, "", ErrorReason::TlsFailure); g.transport.response.diagnostic.certificateFlags = 8; g.tick();
    CHECK(g.client.blocked() && g.client.result().error == ErrorReason::TlsFailure && g.client.diagnostic().certificateFlags == 8);
    CHECK(g.transport.requests.size() == 1);
}
void blockedTest() {
    for (const auto error : {ErrorReason::PermissionDenied, ErrorReason::InterfaceNotFound, ErrorReason::RciFailure,
                            ErrorReason::InvalidJson, ErrorReason::InvalidResponse, ErrorReason::UnsupportedRouter}) {
        Fixture f; f.read(); CHECK(Monitor::set(f.client, false).error == ErrorReason::Pending);
        f.expect("GET /rci/show/interface ");
        if (error == ErrorReason::PermissionDenied) f.reply(403);
        else if (error == ErrorReason::InterfaceNotFound) f.reply(200, "{}");
        else if (error == ErrorReason::RciFailure) f.reply(200, R"({"status":[{"status":"error"}]})");
        else if (error == ErrorReason::InvalidJson) f.reply(200, "{");
        else if (error == ErrorReason::UnsupportedRouter) f.reply(404);
        else f.reply(200, R"({"Wireguard7":{"id":"Wireguard7","type":"Ethernet"}})");
        CHECK(f.client.result().error == error && f.client.blocked());
        CHECK(Monitor::set(f.client, true).error == error); CHECK(f.transport.requests.size() == 5);
    }
    Fixture f; CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /auth ");
    f.reply(401, "", "WWW-Authenticate: x-ndw2-interactive\r\nX-NDM-Realm: test\r\nX-NDM-Challenge: test\r\n");
    f.expect("POST /auth "); f.reply(200, "", "Set-Cookie: sid=authenticated\r\n");
    f.expect("GET /rci/show/version "); f.reply(200, R"({"hw_id":"KN-4010","title":"5.0.9"})");
    CHECK(f.client.blocked() && f.client.result().error == ErrorReason::UnsupportedRouter);
    CHECK(std::string(f.client.identity().version.data()) == "5.0.9");
    Fixture v; CHECK(v.client.readWarpState().error == ErrorReason::Pending);
    v.expect("GET /auth ");
    v.reply(401, "", "WWW-Authenticate: x-ndw2-interactive\r\nX-NDM-Realm: test\r\nX-NDM-Challenge: test\r\n");
    v.expect("POST /auth "); v.reply(200, "", "Set-Cookie: sid=authenticated\r\n");
    v.expect("GET /rci/show/version "); v.reply(404);
    CHECK(v.client.blocked() && v.client.result().error == ErrorReason::UnsupportedRouter);
    for (const auto* body : {"{}", R"({"up":{"status":[{"status":"error"}]}})"}) {
        Fixture g; g.read(); CHECK(Monitor::set(g.client, false).error == ErrorReason::Pending);
        g.expect("GET /rci/show/interface "); g.reply(200, state(true));
        g.expect("POST /rci/interface "); g.reply(200, body);
        CHECK(g.client.blocked() && !g.client.result().ok() && g.transport.requests.size() == 6);
    }
}
void mismatchTest() {
    Fixture f; f.read(); CHECK(Monitor::set(f.client, false).error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface "); f.reply(200, state(true));
    f.expect("POST /rci/interface "); f.reply(200, ack);
    f.expect("GET /rci/show/interface "); f.reply(200, state(true));
    CHECK(f.client.result().error == ErrorReason::StateMismatch && f.client.blocked() && !f.client.state().valid);
}
void lossTest() {
    Fixture f; f.read(); CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface "); f.platform.wifi = false; ++f.platform.losses; f.network.tick(20); f.tick();
    CHECK(!f.client.busy() && f.transport.cancels == 1 && !f.client.state().valid);
    CHECK(f.client.result().error == ErrorReason::WifiDisconnected);
    f.platform.wifi = true; f.network.tick(21);
    CHECK(f.client.readWarpState().error == ErrorReason::TimeNotSynchronized);
    ++f.platform.sync; f.network.tick(22);
    CHECK(f.client.readWarpState().error == ErrorReason::Pending); f.expect("GET /auth ");
    CHECK(f.transport.requests.back().find("Cookie:") == std::string::npos);
    // A large unsynchronized clock step cancels the router operation as well.
    f.network.tick(30000); f.tick();
    CHECK(f.client.result().error == ErrorReason::TimeNotSynchronized && f.transport.cancels == 2);
    Fixture g; g.read(); CHECK(g.client.readWarpState().error == ErrorReason::Pending);
    g.expect("GET /rci/show/interface ");
    g.platform.epoch += 100; ++g.platform.sync; g.network.tick(30);
    CHECK(g.network.timeSynchronized()); g.tick();
    CHECK(!g.client.busy() && g.transport.cancels == 1 && g.client.result().error == ErrorReason::TimeNotSynchronized);
}
void timeoutTest() {
    Fixture f; CHECK(f.client.readWarpState().error == ErrorReason::Pending);
    CHECK(Monitor::set(f.client, false).error == ErrorReason::Busy);
    f.now = 0xfffffff0; f.expect("GET /auth ");
    f.now = static_cast<std::uint32_t>(0xfffffff0U + 11000); f.tick();
    CHECK(!f.client.busy() && f.client.result().error == ErrorReason::ReadTimeout && f.transport.cancels == 1);
}
void uncertainTest() {
    Fixture f; f.read(); CHECK(Monitor::set(f.client, false).error == ErrorReason::Pending);
    f.expect("GET /rci/show/interface "); f.reply(200, state(true));
    f.expect("POST /rci/interface "); f.transport.reply(0, "", ErrorReason::ReadTimeout); f.tick();
    CHECK(!f.client.busy() && f.client.result().error == ErrorReason::ReadTimeout && !f.client.state().valid);
    for (unsigned i = 0; i < 20; ++i) f.tick();
    CHECK(f.transport.requests.size() == 6);
}
int main(int argc, char** argv) {
    try {
        CHECK(argc >= 2); const std::string name = argv[1];
        if (name == "proof") { CHECK(argc == 3); proofTest(argv[2]); }
        else if (name == "settings") settingsTest(); else if (name == "http") httpTest();
        else if (name == "http_bad") httpBadTest(); else if (name == "schema") schemaTest();
        else if (name == "long_authenticate") longAuthenticateTest();
        else if (name == "read") readTest(); else if (name == "change") changeTest();
        else if (name == "expiry") expiryTest(); else if (name == "auth_tls") authTlsTest();
        else if (name == "blocked") blockedTest(); else if (name == "mismatch") mismatchTest();
        else if (name == "loss") lossTest(); else if (name == "timeout") timeoutTest();
        else if (name == "uncertain") uncertainTest(); else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << "\n"; return 1; }
}
