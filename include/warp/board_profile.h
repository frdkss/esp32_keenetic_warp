#pragma once

#include <cstdint>

namespace warp::board {
enum class DisplayDriver : std::uint8_t { Unconfirmed, Ssd1306_72x40 };
struct DisplayProfile {
    bool confirmed;
    DisplayDriver driver;
    int sda;
    int scl;
    std::uint8_t address;
    std::uint8_t rotation;
    std::uint8_t width;
    std::uint8_t height;
};
struct Profile {
    const char* name;
    std::uint32_t flashBytes;
    std::uint32_t crystalHz;
    std::uint16_t minimumChipRevision;
    DisplayProfile display;
};
const Profile& current();
}  // namespace warp::board
