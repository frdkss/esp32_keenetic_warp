#include "warp/recovery_store.h"
#include "nvs.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace warp;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
std::vector<unsigned char> blob;
unsigned writes = 0, erases = 0, commits = 0, closes = 0;
int openError = ESP_OK, readError = ESP_OK, writeError = ESP_OK, eraseError = ESP_OK, commitError = ESP_OK;
int nvs_open(const char* name, int, nvs_handle_t* handle) { CHECK(std::string(name) == "warp"); *handle = 1; return openError; }
void nvs_close(nvs_handle_t) { ++closes; }
int nvs_get_blob(nvs_handle_t, const char* key, void* out, std::size_t* size) {
    CHECK(std::string(key) == "recovery");
    if (readError != ESP_OK) return readError;
    if (blob.empty()) return ESP_ERR_NVS_NOT_FOUND;
    if (*size < blob.size()) return -10;
    std::memcpy(out, blob.data(), blob.size()); *size = blob.size(); return ESP_OK;
}
int nvs_set_blob(nvs_handle_t, const char*, const void* value, std::size_t size) {
    ++writes; if (writeError != ESP_OK) return writeError;
    const auto* bytes = static_cast<const unsigned char*>(value); blob.assign(bytes, bytes + size); return ESP_OK;
}
int nvs_erase_key(nvs_handle_t, const char*) {
    ++erases; if (eraseError != ESP_OK) return eraseError;
    if (blob.empty()) return ESP_ERR_NVS_NOT_FOUND;
    blob.clear(); return ESP_OK;
}
int nvs_commit(nvs_handle_t) { ++commits; return commitError; }
keenetic::Settings settings() {
    keenetic::Settings s;
    std::strcpy(s.address.data(), "192.0.2.1"); std::strcpy(s.tlsName.data(), "router.invalid");
    std::strcpy(s.interfaceName.data(), "Wireguard7"); return s;
}
void durable() {
    NvsRecoveryStore s; bool pending = true; const auto router = settings();
    CHECK(s.load(router, pending).ok() && !pending && writes == 0 && commits == 0);
    CHECK(s.arm(router).ok() && writes == 1 && commits == 1 && blob.size() == 341);
    CHECK(s.load(router, pending).ok() && pending);
    CHECK(s.arm(router).ok() && writes == 1 && commits == 1);
    NvsRecoveryStore afterReboot;
    CHECK(afterReboot.load(router, pending).ok() && pending);
    auto changedTimeout = router; changedTimeout.readMs = 60000;
    CHECK(afterReboot.load(changedTimeout, pending).ok() && pending);
    CHECK(afterReboot.clear().ok() && erases == 1 && commits == 2);
    CHECK(s.load(router, pending).ok() && !pending);
    CHECK(afterReboot.clear().ok());
}
void binding() {
    NvsRecoveryStore s; auto router = settings(); CHECK(s.arm(router).ok()); const auto original = blob;
    for (unsigned field = 0; field < 4; ++field) {
        auto changed = router;
        if (field == 0) std::strcpy(changed.address.data(), "192.0.2.2");
        if (field == 1) std::strcpy(changed.tlsName.data(), "other.invalid");
        if (field == 2) std::strcpy(changed.interfaceName.data(), "Wireguard8");
        if (field == 3) changed.port = 8443;
        bool pending = false;
        CHECK(!s.load(changed, pending).ok() && !pending);
        CHECK(!s.arm(changed).ok() && blob == original && writes == 1);
    }
    bool pending;
    blob[3] = 2; CHECK(!s.load(router, pending).ok()); blob = original;
    blob.resize(340); CHECK(!s.load(router, pending).ok()); blob = original;
    blob.push_back(0); CHECK(!s.load(router, pending).ok()); blob = original;
    blob[50] ^= 0xff; CHECK(!s.load(router, pending).ok());
}
void failures() {
    NvsRecoveryStore s; auto router = settings(); bool pending = true;
    openError = -1; CHECK(!s.load(router, pending).ok() && !pending && closes == 0);
    openError = ESP_ERR_NVS_NOT_FOUND; CHECK(s.load(router, pending).ok() && !pending);
    openError = ESP_OK; readError = -1; CHECK(!s.arm(router).ok() && writes == 0);
    readError = ESP_OK; writeError = -1; CHECK(!s.arm(router).ok() && commits == 0);
    writeError = ESP_OK; commitError = -1; CHECK(!s.arm(router).ok());
    // A failed commit is uncertain; a new reader may see the intent. It is never
    // treated as permission to disable by Monitor.
    CHECK(s.load(router, pending).ok() && pending);
    eraseError = -1; CHECK(!s.clear().ok() && !blob.empty());
    eraseError = ESP_OK; CHECK(!s.clear().ok());
    router.address.fill('x'); CHECK(!s.load(router, pending).ok() && !s.arm(router).ok());
}
int main(int argc, char** argv) {
    try {
        CHECK(argc == 2); const std::string name = argv[1];
        if (name == "durable") durable(); else if (name == "binding") binding(); else if (name == "failures") failures();
        else throw std::runtime_error("Unknown scenario");
        std::cout << name << " passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
}
