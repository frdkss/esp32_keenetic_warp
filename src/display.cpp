#include "warp/display.h"
#include "warp/build_profile.h"
#include "warp/status.h"
#include <cstring>

#if OLED_ENABLED
#include <U8g2lib.h>
#include <Wire.h>
namespace {
U8G2_SSD1306_72X40_ER_F_HW_I2C oled(U8G2_R0, U8X8_PIN_NONE);
}
#endif

namespace warp {
DisplayState Display::begin(const board::DisplayProfile& profile, bool enabled) {
    ready_ = false;
    state_ = DisplayState::Disabled;
    if (!enabled) return state_;
#if OLED_ENABLED
    if (!profile.confirmed || profile.driver != board::DisplayDriver::Ssd1306_72x40 ||
        profile.sda < 0 || profile.scl < 0 || profile.sda == profile.scl ||
        profile.address < 0x08 || profile.address > 0x77 || profile.rotation > 3 ||
        profile.width != 72 || profile.height != 40) {
        return state_ = DisplayState::Unconfirmed;
    }
    if (!Wire.begin(profile.sda, profile.scl)) return state_ = DisplayState::Unavailable;
    Wire.setTimeOut(20);
    address_ = profile.address;
    Wire.beginTransmission(profile.address);
    if (Wire.endTransmission() != 0) return state_ = DisplayState::Unavailable;
    const u8g2_cb_t* rotations[] = {U8G2_R0, U8G2_R1, U8G2_R2, U8G2_R3};
    oled.setDisplayRotation(rotations[profile.rotation]);
    oled.setI2CAddress(profile.address << 1);
    if (!oled.begin()) return state_ = DisplayState::Unavailable;
    ready_ = true;
    return state_ = DisplayState::Ready;
#else
    (void)profile;
    return state_;
#endif
}
DisplayState Display::check() {
#if OLED_ENABLED
    if (ready_) {
        Wire.beginTransmission(address_);
        if (Wire.endTransmission() != 0) {
            ready_ = false;
            state_ = DisplayState::Unavailable;  // No automatic bus/reinitialization loop.
        }
    }
#endif
    return state_;
}
void Display::render(const SystemStatus& snapshot) {
#if OLED_ENABLED
    if (!ready_) return;
    oled.clearBuffer();
    const auto width = oled.getDisplayWidth();
    const auto height = oled.getDisplayHeight();
    const char* title = status::label(snapshot.state);
    oled.setFont(u8g2_font_helvB18_tf);
    if (oled.getStrWidth(title) > width) oled.setFont(u8g2_font_helvB10_tf);
    if (oled.getStrWidth(title) > width) oled.setFont(u8g2_font_5x8_tf);
    oled.drawStr((width - oled.getStrWidth(title)) / 2, 23, title);
    const auto* reason = snapshot.state == SystemState::Recovering && snapshot.reason == ErrorReason::Pending ?
        status::label(snapshot.recovery) : status::label(snapshot.reason);
    char detail[24]{};
    std::strncpy(detail, reason, sizeof(detail) - 1);
    oled.setFont(u8g2_font_5x8_tf);
    for (auto length = std::strlen(detail); length && oled.getStrWidth(detail) > width; --length) detail[length - 1] = 0;
    oled.drawStr((width - oled.getStrWidth(detail)) / 2, height - 2, detail);
    oled.sendBuffer();
#else
    (void)snapshot;
#endif
}
}  // namespace warp
