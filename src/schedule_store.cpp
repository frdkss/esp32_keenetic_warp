#include "warp/scheduler.h"
#include "nvs.h"
#include <array>

namespace warp {
namespace {
constexpr const char* key = "weekly_date";
using Record = std::array<std::uint8_t, 8>;
}
OperationResult NvsScheduleStore::load(std::uint32_t& date) {
    date = 0;
    nvs_handle_t handle;
    auto error = nvs_open("warp", NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) return {ErrorReason::None};
    if (error != ESP_OK) return {ErrorReason::StorageFailure};
    Record bytes{};
    std::size_t size = bytes.size();
    error = nvs_get_blob(handle, key, bytes.data(), &size);
    nvs_close(handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) return {ErrorReason::None};
    if (error != ESP_OK || size != bytes.size() || bytes[0] != 'W' || bytes[1] != 'S' ||
        bytes[2] != 'D' || bytes[3] != 1) return {ErrorReason::StorageFailure};
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>(bytes[4 + i]) << (8 * i);
    if (!validScheduleDate(value)) return {ErrorReason::StorageFailure};
    date = value;
    return {ErrorReason::None};
}
OperationResult NvsScheduleStore::consume(std::uint32_t date) {
    if (!validScheduleDate(date)) return {ErrorReason::StorageFailure};
    std::uint32_t previous = 0;
    const auto loaded = load(previous);
    if (!loaded.ok() || date <= previous) return loaded;
    nvs_handle_t handle;
    if (nvs_open("warp", NVS_READWRITE, &handle) != ESP_OK) return {ErrorReason::StorageFailure};
    Record bytes{'W', 'S', 'D', 1};
    for (unsigned i = 0; i < 4; ++i) bytes[4 + i] = static_cast<std::uint8_t>(date >> (8 * i));
    auto error = nvs_set_blob(handle, key, bytes.data(), bytes.size());
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return {error == ESP_OK ? ErrorReason::None : ErrorReason::StorageFailure};
}
}  // namespace warp
