#include "warp/board_profile.h"

#if !defined(WARP_BOARD_C3_SUPERMINI)
#error Select an explicit supported project board profile
#endif

namespace warp::board {
const Profile& current() {
    // Flash/crystal/revision: STAGE1.md. The 0.42-inch OLED wiring follows
    // 01Space's ESP32-C3-0.42LCD HelloWorld: SDA=5, SCL=6, SSD1306 72x40.
    // https://github.com/01Space/ESP32-C3-0.42LCD/blob/main/HelloWorld/HelloWorld.ino
    // Display::begin requires an ACK at the explicit address before drawing.
    static constexpr Profile profile{
        "esp32-c3-supermini-oled-72x40", 4 * 1024 * 1024, 40'000'000, 3,
        {true, DisplayDriver::Ssd1306_72x40, 5, 6, 0x3C, 0, 72, 40}};
    return profile;
}
}  // namespace warp::board
