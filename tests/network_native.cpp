#include "warp/network.h"
#include "warp/network_protocol.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
struct Fake : NetworkPlatform {
    bool wifi{false}, ready{false}, active{false};
    unsigned connects{0}, disconnects{0}, syncStarts{0}, cancels{0};
    std::uint32_t sync{0}, losses{0};
    std::int64_t epoch{1794614400};
    CheckResult next{};
    std::vector<std::string> requests;
    bool beginWifi(CredentialsView) override { return true; }
    void connectWifi() override { ++connects; }
    void disconnectWifi() override { ++disconnects; }
    bool wifiConnected() const override { return wifi; }
    std::uint32_t wifiLossGeneration() const override { return losses; }
    bool startTimeSync(const char*) override { ++syncStarts; return true; }
    std::uint32_t timeSyncGeneration() const override { return sync; }
    std::int64_t epochSeconds() const override { return epoch; }
    bool startProbe(std::string_view url, std::uint32_t a, std::uint32_t b) override {
        CHECK(a == 5000 && b == 5000);
        CHECK(!active); active = true;
        requests.emplace_back(url); return true;
    }
    bool pollProbe(CheckResult& result) override {
        if (!ready) return false;
        result = next; ready = active = false; return true;
    }
    void cancelProbe() override { ++cancels; active = ready = false; }
    void finish(int status, ErrorReason error = ErrorReason::None) {
        next = {error, status, 42, false, true, 123, -321, 8}; ready = true;
    }
};
NetworkSettings settings() {
    NetworkSettings s;
    s.controlCount = s.targetCount = 2;
    std::strcpy(s.controls[0].data(), "https://control-a.invalid/");
    std::strcpy(s.controls[1].data(), "http://control-b.invalid/resource");
    std::strcpy(s.targets[0].data(), "https://target-a.invalid/");
    std::strcpy(s.targets[1].data(), "https://target-b.invalid/");
    std::strcpy(s.timezone.data(), "MSK-3");
    return s;
}
const CredentialsView credentials{"TEST_WIFI", "", "login", "password"};
void online(Network& n, Fake& p, std::uint32_t now = 100) {
    p.wifi = true; n.tick(now); CHECK(!n.timeSynchronized());
    ++p.sync; n.tick(now + 1); CHECK(n.timeSynchronized());
}
void finish(Network& n, Fake& p, int status, ErrorReason error = ErrorReason::None, std::uint32_t now = 102) {
    p.finish(status, error); n.tick(now);
}
void urlTest() {
    net::Url u;
    CHECK(net::parseUrl("https://example.invalid:8443/a?b=c", u));
    CHECK(u.secure && u.port == 8443 && std::string(u.host.data()) == "example.invalid");
    CHECK(std::string(u.path.data()) == "/a?b=c");
    CHECK(net::parseUrl("http://example.invalid?x", u));
    CHECK(!u.secure && u.port == 80 && std::string(u.path.data()) == "/?x");
    CHECK(net::parseUrl("https://[2001:db8::1]:443/", u) && u.ipv6);
    for (const auto* bad : {"https://", "ftp://a/", "https://a:0/", "https://a:65536/", "https://a:/",
         "https://u:p@a/", "https://a/#frag", "https://a/\r\nx", "https://a/ space", "https://a\\evil/",
         "https://a:12x/", "https://[bad]/", "https://[::1]oops/", "https://a/\x7f"}) CHECK(!net::parseUrl(bad, u));
    CHECK(!net::parseUrl("https://a/" + std::string(513, 'a'), u));
    auto s = settings(); CHECK(net::validSettings(s));
    s.controlCount = 0; CHECK(!net::validSettings(s));
    s = settings(); s.targets[0] = s.controls[0]; CHECK(!net::validSettings(s));
    s = settings(); std::strcpy(s.targets[0].data(), "https://CONTROL-a.invalid:443/"); CHECK(!net::validSettings(s));
    s = settings(); s.readTimeoutMs = 0; CHECK(!net::validSettings(s));
    s = settings(); s.targets[0].fill('a'); CHECK(!net::validSettings(s));
}
net::ResponseHeaders headers(std::string_view text) {
    net::ResponseHeaders parser;
    for (char ch : text) parser.feed(ch);
    return parser;
}
void httpTest() {
    for (int code : {200, 204, 299, 301, 302, 399, 400, 404, 429, 500, 599}) {
        const auto h = headers("HTTP/1.1 " + std::to_string(code) + " Reason\r\nContent-Length: 999999999\r\n\r\nbody");
        CHECK(h.done() && h.status() == code && h.error() == ErrorReason::None);
    }
    CHECK(headers("HTTP/1.0 200 \r\n\r\n").done());
    CHECK(headers("HTTP/1.1 103 Early\r\n\r\nHTTP/1.1 200 OK\r\n\r\n").status() == 200);
    for (const auto* invalid : {"HTTP/1.1 200Xbad\r\n\r\n", "HTTP/2 200 OK\r\n\r\n", "HTTP/1.1 600 Bad\r\n\r\n",
         "HTTP/1.1 200 OK\n\n", "HTTP/1.1 101 Switching\r\n\r\n"}) {
        const auto h = headers(invalid); CHECK(!h.done() && h.error() == ErrorReason::InvalidResponse);
    }
    CHECK(!headers("HTTP/1.1 200 OK\r\nX: unfinished").done());
    CHECK(headers("HTTP/1.1 200 OK\r\nX: broken\n\r\n").error() == ErrorReason::InvalidResponse);
    CHECK(headers(std::string("HTTP/1.1 200 OK\r\nX: ") + '\0' + "\r\n\r\n").error() == ErrorReason::InvalidResponse);
    CHECK(headers("HTTP/1.1 200 OK\r\nX: " + std::string(4096, 'a')).error() == ErrorReason::ResponseTooLarge);
    CHECK(headers("HTTP/1.1 200 " + std::string(128, 'a')).error() == ErrorReason::InvalidResponse);
    std::string interim;
    for (int i = 0; i < 5; ++i) interim += "HTTP/1.1 100 Continue\r\n\r\n";
    CHECK(headers(interim).error() == ErrorReason::InvalidResponse);
}
void wifiTest() {
    Fake p; Network n(p); auto s = settings();
    CHECK(n.begin(credentials, s, 0xfffffff0).ok()); CHECK(p.connects == 1);
    n.tick(static_cast<std::uint32_t>(0xfffffff0 + 14999)); CHECK(p.disconnects == 0);
    n.tick(static_cast<std::uint32_t>(0xfffffff0 + 15000)); CHECK(p.disconnects == 1);
    n.tick(static_cast<std::uint32_t>(0xfffffff0 + 19999)); CHECK(p.connects == 1);
    n.tick(static_cast<std::uint32_t>(0xfffffff0 + 20000)); CHECK(p.connects == 2);
    CHECK(p.requests.empty() && !n.internetConfirmed());
}
void timeTest() {
    Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok());
    p.wifi = true; n.tick(1); CHECK(n.reason() == ErrorReason::TimeNotSynchronized);
    n.tick(30001); CHECK(p.syncStarts == 2 && p.requests.empty());
    p.epoch = 0; ++p.sync; n.tick(30002); CHECK(!n.timeSynchronized());
    p.epoch = 1794614400; ++p.sync; n.tick(30003); CHECK(n.timeSynchronized() && p.active);
    p.epoch += 100; n.tick(30004); CHECK(!n.timeSynchronized() && !p.active && p.cancels == 1);
    CHECK(!n.internetConfirmed());
    ++p.sync; n.tick(30005); CHECK(n.timeSynchronized());
    p.epoch -= 1000; n.tick(30006); CHECK(!n.timeSynchronized());
}
void orderTest() {
    Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
    CHECK(p.requests.size() == 1 && p.requests[0] == settings().controls[0].data());
    finish(n, p, 200); CHECK(p.requests.size() == 2 && p.requests[1] == settings().controls[1].data());
    finish(n, p, 503); CHECK(p.requests.size() == 3 && p.requests[2] == settings().targets[0].data());
    finish(n, p, 302); finish(n, p, 404);
    const auto& c = n.checks();
    CHECK(c.complete && c.internetConfirmed && n.internetConfirmed() && !n.busy());
    CHECK(c.controlSummary.reachable == 1 && c.targetSummary.reachable == 1 && c.targetSummary.failed == 1);
    CHECK(c.targets[1].httpStatus == 404 && c.targets[1].error == ErrorReason::HttpFailure);
    CHECK(c.targets[0].durationMs == 42 && c.targets[0].attempted);
    CHECK(c.targets[0].transportCode == 123 && c.targets[0].tlsCode == -321 && c.targets[0].certificateFlags == 8);
    CHECK(n.requestChecks() && !n.internetConfirmed() && !n.checks().complete);
}
void controlsFailTest() {
    Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
    finish(n, p, 0, ErrorReason::DnsFailure); finish(n, p, 0, ErrorReason::ReadTimeout);
    CHECK(p.requests.size() == 2 && !n.internetConfirmed() && n.checks().complete);
    CHECK(n.checks().targets[0].error == ErrorReason::InternetUnavailable && !n.checks().targets[0].attempted);
    CHECK(n.checks().targetSummary.total == 2 && n.checks().targetSummary.failed == 2);
    CHECK(n.checks().controls[0].error == ErrorReason::DnsFailure);
    CHECK(n.checks().controls[1].error == ErrorReason::ReadTimeout);
}
void lossTest() {
    Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
    p.wifi = false; ++p.losses; n.tick(102);
    CHECK(p.cancels == 1 && !n.busy() && !n.internetConfirmed() && !n.timeSynchronized());
    p.wifi = true; n.tick(103); CHECK(!n.timeSynchronized());
    ++p.sync; n.tick(104); CHECK(n.timeSynchronized() && p.requests.size() == 2);
    // Loss and return between loop ticks must still invalidate results.
    ++p.losses; n.tick(105); CHECK(!n.timeSynchronized() && !n.internetConfirmed() && p.cancels == 2);
}
void intervalTest() {
    Fake p; Network n(p); const std::uint32_t start = 0xfffffff0;
    CHECK(n.begin(credentials, settings(), start).ok()); online(n, p, start);
    for (int i = 0; i < 4; ++i) finish(n, p, 200, ErrorReason::None, start + 2);
    CHECK(n.checks().sequence == 1);
    p.epoch += 59; n.tick(start + 60001); CHECK(p.requests.size() == 4);
    p.epoch += 1; n.tick(start + 60002); CHECK(p.requests.size() == 5);
    CHECK(!n.internetConfirmed());
    CHECK(!n.requestChecks());
}
void freshnessTest() {
    Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
    p.epoch += 21600; n.tick(21600101);
    CHECK(!n.timeSynchronized() && !n.internetConfirmed() && p.cancels == 1);
    ++p.sync; n.tick(21600102); CHECK(n.timeSynchronized());
    ++p.sync; n.tick(21600103); CHECK(p.cancels == 1 && n.timeSynchronized());
    p.epoch += 60; ++p.sync; n.tick(21600104); CHECK(p.cancels == 2 && n.timeSynchronized());
}
void errorsTest() {
    for (const auto error : {ErrorReason::DnsFailure, ErrorReason::DnsTimeout, ErrorReason::ConnectionFailure,
         ErrorReason::ConnectTimeout, ErrorReason::TlsFailure, ErrorReason::ReadTimeout,
         ErrorReason::InvalidResponse, ErrorReason::ResponseTooLarge, ErrorReason::ResourceExhausted}) {
        Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
        finish(n, p, 200); finish(n, p, 200); finish(n, p, 0, error); finish(n, p, 399);
        CHECK(n.checks().targets[0].error == error && !n.checks().targets[0].reachable);
        const auto& diagnostic = n.checks().targets[0];
        CHECK(diagnostic.httpStatus == 0 && diagnostic.durationMs == 42 && diagnostic.attempted);
        CHECK(diagnostic.transportCode == 123 && diagnostic.tlsCode == -321 && diagnostic.certificateFlags == 8);
        CHECK(n.checks().targets[1].reachable && n.internetConfirmed());
    }
}
void statusMatrixTest() {
    for (int code = 200; code <= 599; ++code) {
        Fake p; Network n(p); CHECK(n.begin(credentials, settings(), 0).ok()); online(n, p);
        finish(n, p, 204); finish(n, p, 302); finish(n, p, code); finish(n, p, code);
        const auto& c = n.checks();
        CHECK(c.complete && n.internetConfirmed() && c.targets[0].httpStatus == code);
        CHECK(c.targets[0].reachable == (code < 400));
        CHECK(c.targets[0].error == (code < 400 ? ErrorReason::None : ErrorReason::HttpFailure));
        CHECK(c.targetSummary.reachable == (code < 400 ? 2 : 0));
    }
}
void maxListTest() {
    Fake p; Network n(p); auto s = settings(); s.controlCount = s.targetCount = 8;
    for (unsigned i = 0; i < 8; ++i) {
        const auto c = "https://control-" + std::to_string(i) + ".invalid/";
        const auto t = "https://target-" + std::to_string(i) + ".invalid/";
        std::strcpy(s.controls[i].data(), c.c_str()); std::strcpy(s.targets[i].data(), t.c_str());
    }
    CHECK(n.begin(credentials, s, 0).ok()); online(n, p);
    for (unsigned i = 0; i < 16; ++i) finish(n, p, 204);
    CHECK(n.checks().complete && p.requests.size() == 16 && n.checks().controlSummary.reachable == 8);
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        const std::string name = argv[1];
        if (name == "urls") urlTest();
        else if (name == "http") httpTest();
        else if (name == "wifi") wifiTest();
        else if (name == "time") timeTest();
        else if (name == "order") orderTest();
        else if (name == "controls_fail") controlsFailTest();
        else if (name == "loss") lossTest();
        else if (name == "interval") intervalTest();
        else if (name == "freshness") freshnessTest();
        else if (name == "errors") errorsTest();
        else if (name == "max_list") maxListTest();
        else if (name == "status_matrix") statusMatrixTest();
        else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
