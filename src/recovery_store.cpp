#include "warp/recovery_store.h"
#include "nvs.h"
#include <algorithm>
#include <array>

namespace warp {
namespace {
constexpr const char* key = "recovery";
// Explicit byte format: magic/version, port LE, IPv4, TLS name, interface.
using Record = std::array<std::uint8_t, 4 + 2 + 16 + 254 + 65>;
Record record(const keenetic::Settings& router) {
    Record bytes{};
    bytes[0] = 'W'; bytes[1] = 'R'; bytes[2] = 'P'; bytes[3] = 1;
    bytes[4] = static_cast<std::uint8_t>(router.port);
    bytes[5] = static_cast<std::uint8_t>(router.port >> 8);
    std::copy_n(router.address.begin(), std::char_traits<char>::length(router.address.data()), bytes.begin() + 6);
    std::copy_n(router.tlsName.begin(), std::char_traits<char>::length(router.tlsName.data()), bytes.begin() + 22);
    std::copy_n(router.interfaceName.begin(), std::char_traits<char>::length(router.interfaceName.data()), bytes.begin() + 276);
    return bytes;
}
}
OperationResult NvsRecoveryStore::load(const keenetic::Settings& router, bool& pending) {
    pending = false;
    if (!keenetic::validSettings(router)) return {ErrorReason::StorageFailure};
    nvs_handle_t handle;
    auto error = nvs_open("warp", NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) return {ErrorReason::None};
    if (error != ESP_OK) return {ErrorReason::StorageFailure};
    Record bytes{};
    std::size_t size = bytes.size();
    error = nvs_get_blob(handle, key, bytes.data(), &size);
    nvs_close(handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) return {ErrorReason::None};
    if (error != ESP_OK || size != bytes.size() || bytes != record(router)) return {ErrorReason::StorageFailure};
    pending = true;
    return {ErrorReason::None};
}
OperationResult NvsRecoveryStore::arm(const keenetic::Settings& router) {
    bool pending = false;
    const auto loaded = load(router, pending);
    if (!loaded.ok() || pending) return loaded;  // Never replace a foreign/corrupt obligation.
    nvs_handle_t handle;
    if (nvs_open("warp", NVS_READWRITE, &handle) != ESP_OK) return {ErrorReason::StorageFailure};
    const auto bytes = record(router);
    auto error = nvs_set_blob(handle, key, bytes.data(), bytes.size());
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return {error == ESP_OK ? ErrorReason::None : ErrorReason::StorageFailure};
}
OperationResult NvsRecoveryStore::clear() {
    nvs_handle_t handle;
    if (nvs_open("warp", NVS_READWRITE, &handle) != ESP_OK) return {ErrorReason::StorageFailure};
    auto error = nvs_erase_key(handle, key);
    if (error == ESP_ERR_NVS_NOT_FOUND) error = ESP_OK;
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return {error == ESP_OK ? ErrorReason::None : ErrorReason::StorageFailure};
}
}  // namespace warp
