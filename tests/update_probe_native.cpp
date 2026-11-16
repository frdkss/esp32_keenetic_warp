#include "probe_fakes.h"
#include "warp/update_probe.h"
#include <cassert>
#include <iostream>
static unsigned acquired = 0, released = 0;
static bool allowAcquire = true;
static bool acquire() { ++acquired; return allowAcquire; }
static void release() { ++released; }
static std::uint32_t date() { return 20261112; }

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "proof";
    warp::CheckCycle cycle{};
    cycle.complete = true; cycle.sequence = 42; cycle.internetConfirmed = true;
    cycle.controlSummary.total = 2; cycle.targetSummary.total = 3;
    if (mode == "in_progress") cycle.complete = false;
    const auto runtimeError = mode == "runtime_error" ? warp::ErrorReason::InvalidResponse : warp::ErrorReason::None;
    const int routerHttp = mode == "runtime_error" ? 401 : 0;
    const std::string request = "WARP9 " + std::string(64, 'a') + "\n";
    const bool maintenance = mode.find("maintenance_") == 0;
    const std::string configTag(64, 'a');
    if (maintenance) warp::update::configureService({configTag.c_str(), acquire, release, date});
    if (mode == "unprotected") fakeProtected = false;
    if (mode == "missing_key") fakeMissingKey = true;
    if (mode == "overflow") Serial.input = std::string(100, 'x') + request;
    else if (mode == "bad_nonce") Serial.input = "WARP9 " + std::string(64, 'z') + "\n";
    else if (mode == "partial") Serial.input = request.substr(0, 30);
    else Serial.input = request;
    fakeMillis = 2000;
    warp::update::tick(true, cycle, true, runtimeError, routerHttp);
    if (mode == "partial") {
        fakeMillis += 3000;
        Serial.input += request.substr(30);
    }
    if (mode == "stalled") Serial.room = 0;
    for (int i = 0; i < 200; ++i) {
        fakeMillis += 20;
        warp::update::tick(true, cycle, true, runtimeError, routerHttp);
    }
    assert(!warp::update::sending());
    if (maintenance) {
        Serial.output.clear();
        std::string challenge;
        for (unsigned i = 0; i < 32; ++i) challenge += "56";
        constexpr char domain[] = "WARP-USB-LOCK-1";
        std::vector<unsigned char> payload(domain, domain + sizeof(domain)), key;
        payload.insert(payload.end(), challenge.begin(), challenge.end());
        for (unsigned i = 0; i < 64; ++i) key.push_back(static_cast<unsigned char>(i));
        unsigned char tag[32]{};
        assert(nativeDigest(key, payload.data(), payload.size(), tag) == 0);
        std::string tagHex;
        for (unsigned char b : tag) { tagHex += "0123456789abcdef"[b >> 4]; tagHex += "0123456789abcdef"[b & 15]; }
        if (mode == "maintenance_bad") tagHex[0] = tagHex[0] == '0' ? '1' : '0';
        if (mode == "maintenance_expired") fakeMillis += 11000;
        if (mode == "maintenance_busy") allowAcquire = false;
        const auto lock = "WARPLOCK " + challenge + " " + tagHex + "\n";
        Serial.input = lock;
        for (unsigned i = 0; i < 200; ++i) { fakeMillis += 20; warp::update::tick(true, cycle, true); }
        if (mode == "maintenance_bad" || mode == "maintenance_expired") {
            assert(acquired == 0 && Serial.output.empty());
        } else {
            assert(acquired == 1);
            const bool busy = mode == "maintenance_busy";
            assert(Serial.output.find(busy ? "\"locked\":0" : "\"locked\":1") != std::string::npos);
            Serial.input = lock;
            for (unsigned i = 0; i < 200; ++i) { fakeMillis += 20; warp::update::tick(true, cycle, true); }
            assert(acquired == 1);
            if (!busy) { fakeMillis += 300001; warp::update::tick(true, cycle, true); assert(released == 1); }
        }
    } else if (mode == "proof" || mode == "in_progress" || mode == "runtime_error") {
        assert(Serial.output.find("WARP9 ") != std::string::npos);
        std::cout << Serial.output;
    } else if (mode == "stalled") assert(Serial.output.empty());
    else assert(Serial.output.empty());
    // Keys returned by the fake reader must have been erased by production code.
    if (fakeKeyPointer) {
        // The pointer itself is no longer dereferenced after the function returns.
        assert(fakeZeroized >= 2);
    }
    return 0;
}
