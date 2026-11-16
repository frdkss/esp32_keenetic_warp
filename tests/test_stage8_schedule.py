"""Execute production scheduler/store/display/status C++ with synthetic time/NVS/I2C.
No physical display, ESP32, router or owner configuration is used.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_stage5_network import ROOT, compile_native


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class ScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-schedule-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake"
        fake.mkdir()
        (fake / "nvs.h").write_text("""#pragma once
#include <cstddef>
constexpr int ESP_OK = 0, ESP_ERR_NVS_NOT_FOUND = -2, NVS_READONLY = 1, NVS_READWRITE = 2;
using nvs_handle_t = unsigned;
int nvs_open(const char*, int, nvs_handle_t*);
void nvs_close(nvs_handle_t);
int nvs_get_blob(nvs_handle_t, const char*, void*, std::size_t*);
int nvs_set_blob(nvs_handle_t, const char*, const void*, std::size_t);
int nvs_commit(nvs_handle_t);
""")
        (fake / "Arduino.h").write_text("""#pragma once
#include <string>
#include <cstdio>
class Print {
public:
    std::string text;
    template<class... Args> void printf(const char* format, Args... args) {
        char buffer[2048]{}; std::snprintf(buffer, sizeof(buffer), format, args...); text += buffer;
    }
};
""")
        # Compile the no-OLED variant before providing any Wire/U8g2 headers.
        sources = [ROOT / "tests/stage8_native.cpp"] + [ROOT / "src" / name for name in
            ("scheduler.cpp", "schedule_store.cpp", "display.cpp", "status.cpp", "board_profile.cpp")]
        cls.no_oled = compile_native(cls.work, "stage8_no_oled", sources, includes=[fake],
                                     defines=["OLED_ENABLED=0", "WARP_PROTECTED_BUILD=0", "WARP_BOARD_C3_SUPERMINI=1"])
        (fake / "Wire.h").write_text("""#pragma once
#include <cstdint>
namespace fakeWire {
inline bool ack = true;
inline unsigned begins = 0, probes = 0, timeout = 0;
inline int sda = -1, scl = -1, address = -1;
}
class FakeWire {
public:
    bool begin(int sda, int scl) { ++fakeWire::begins; fakeWire::sda=sda; fakeWire::scl=scl; return true; }
    void setTimeOut(unsigned value) { fakeWire::timeout = value; }
    void beginTransmission(std::uint8_t address) { ++fakeWire::probes; fakeWire::address=address; }
    unsigned endTransmission() { return fakeWire::ack ? 0 : 1; }
};
inline FakeWire Wire;
""")
        (fake / "U8g2lib.h").write_text("""#pragma once
#include <string>
#include <vector>
#include <cstring>
struct u8g2_cb_t { unsigned rotation; };
inline constexpr u8g2_cb_t fakeRotations[] = {{0}, {1}, {2}, {3}};
inline constexpr const u8g2_cb_t *U8G2_R0 = &fakeRotations[0], *U8G2_R1 = &fakeRotations[1], *U8G2_R2 = &fakeRotations[2], *U8G2_R3 = &fakeRotations[3];
inline constexpr int U8X8_PIN_NONE = 255;
inline constexpr unsigned char u8g2_font_helvB18_tf[] = {18}, u8g2_font_helvB10_tf[] = {10}, u8g2_font_5x8_tf[] = {5};
namespace fakeOled {
struct Draw { int x, y, width; unsigned font; std::string text; };
inline std::vector<Draw> draws;
inline unsigned frames = 0, font = 0;
inline int width = 72, height = 40;
}
class U8G2_SSD1306_72X40_ER_F_HW_I2C {
public:
    U8G2_SSD1306_72X40_ER_F_HW_I2C(const u8g2_cb_t*, int) {}
    void setDisplayRotation(const u8g2_cb_t* r) { fakeOled::width = r->rotation % 2 ? 40 : 72; fakeOled::height = r->rotation % 2 ? 72 : 40; }
    void setI2CAddress(unsigned) {}
    bool begin() { return true; }
    void clearBuffer() { fakeOled::draws.clear(); }
    int getDisplayWidth() { return fakeOled::width; }
    int getDisplayHeight() { return fakeOled::height; }
    void setFont(const unsigned char* font) { fakeOled::font = font[0]; }
    int getStrWidth(const char* value) { return static_cast<int>(std::strlen(value) * (fakeOled::font == 18 ? 16 : fakeOled::font == 10 ? 7 : 5)); }
    void drawStr(int x, int y, const char* text) { fakeOled::draws.push_back({x, y, getStrWidth(text), fakeOled::font, text}); }
    void sendBuffer() { ++fakeOled::frames; }
};
""")
        cls.oled = compile_native(cls.work, "stage8_oled", sources, includes=[fake],
                                  defines=["OLED_ENABLED=1", "WARP_PROTECTED_BUILD=0", "WARP_BOARD_C3_SUPERMINI=1"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name, oled=False):
        result = subprocess.run([str(self.oled if oled else self.no_oled), name],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exact_minute_once_and_next_week(self): self.scenario("minute")
    def test_reboot_backward_steps_folds_and_forward_steps(self): self.scenario("correction")
    def test_unconfirmed_time_internet_busy_and_restore_obligation(self): self.scenario("gates")
    def test_independent_disable_and_configurable_day_time(self): self.scenario("settings")
    def test_invalid_calendar_dates_and_leap_years(self): self.scenario("dates")
    def test_failed_store_blocks_scheduler_without_write_loop(self): self.scenario("scheduler_failure")
    def test_real_nvs_store_deduplication_reboot_and_minimal_writes(self): self.scenario("durable")
    def test_corrupt_version_date_and_blob_size_preserved(self): self.scenario("corrupt")
    def test_nvs_read_write_commit_errors_and_uncertain_commit(self): self.scenario("nvs_failures")
    def test_serial_contains_safe_states_phases_counters_and_schedule(self): self.scenario("serial")
    def test_no_oled_compiles_without_u8g2_or_wire(self): self.scenario("display_gate")
    def test_actual_board_profile_initializes_oled_on_documented_pins(self):
        self.scenario("board_display", oled=True)
        self.scenario("board_display")
    def test_unconfirmed_missing_disabled_and_disconnected_display(self): self.scenario("display_gate", oled=True)
    def test_titles_reason_clipping_and_rotations(self): self.scenario("layout", oled=True)


if __name__ == "__main__":
    unittest.main()
