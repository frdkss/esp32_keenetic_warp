"""Execute real C++ network state-machine/protocol code with a deterministic fake I/O adapter.
No real credentials, sites or serial ports are used. MSVC Build Tools required on Windows.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def vcvars():
    base = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio"
    found = sorted(base.glob("*/BuildTools/VC/Auxiliary/Build/vcvars64.bat"))
    if not found:
        raise RuntimeError("MSVC Build Tools with the C++ workload required")
    return found[-1]

def compile_native(work, name, sources, includes=(), defines=(), flags=()):
    binary = work / (name + ".exe")
    args = ["cl", "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX", "/Zc:__cplusplus", "/D_CRT_SECURE_NO_WARNINGS",
            "/I" + str(ROOT / "include")]
    args += ["/I" + str(path) for path in includes]
    args += ["/D" + value for value in defines]
    args += list(flags)
    args += [str(path) for path in sources] + ["/Fe:" + str(binary), "/Fo:" + str(work) + "\\"]
    command = work / (name + ".cmd")
    command.write_text('@echo off\ncall "' + str(vcvars()) + '" >nul\n' +
                       subprocess.list2cmdline(args) + "\nexit /b %errorlevel%\n", encoding="utf-8")
    result = subprocess.run(["cmd.exe", "/d", "/c", str(command)], cwd=work, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return binary

@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-network-")
        cls.work = Path(cls.temporary.name)
        cls.binary = compile_native(cls.work, "network",
            [ROOT / "tests/network_native.cpp", ROOT / "src/network.cpp", ROOT / "src/network_protocol.cpp"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_url_validation(self): self.run_scenario("urls")
    def test_http_status_and_stream_limits(self): self.run_scenario("http")
    def test_wifi_bounded_retry_across_millis_wrap(self): self.run_scenario("wifi")
    def test_time_requires_sync_and_detects_clock_steps(self): self.run_scenario("time")
    def test_controls_before_targets_and_one_success_is_enough(self): self.run_scenario("order")
    def test_all_controls_fail_blocks_targets_and_internet(self): self.run_scenario("controls_fail")
    def test_wifi_loss_cancels_and_requires_new_time_sync(self): self.run_scenario("loss")
    def test_cycle_interval_across_millis_wrap(self): self.run_scenario("interval")
    def test_expired_sync_and_time_correction_cancel_checks(self): self.run_scenario("freshness")
    def test_diagnostics_remain_distinct(self): self.run_scenario("errors")
    def test_request_count_bounded_by_full_lists(self): self.run_scenario("max_list")
    def test_all_http_codes_200_through_599_preserve_status_and_classification(self): self.run_scenario("status_matrix")

@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class RuntimeConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-nvs-reader-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake"
        (fake / "mbedtls").mkdir(parents=True)
        declarations = """#pragma once
#include <cstddef>
#include <cstdint>
constexpr int ESP_OK = 0, NVS_READONLY = 1;
constexpr int ESP_PARTITION_TYPE_DATA = 1, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS = 4;
using nvs_handle_t = unsigned;
struct esp_partition_t {};
struct nvs_sec_cfg_t { unsigned char bytes[64]; };
bool esp_flash_encryption_enabled();
bool esp_secure_boot_enabled();
const esp_partition_t* esp_partition_find_first(int, int, const char*);
int nvs_flash_read_security_cfg(const esp_partition_t*, nvs_sec_cfg_t*);
int nvs_flash_secure_init(nvs_sec_cfg_t*);
int nvs_open(const char*, int, nvs_handle_t*);
void nvs_close(nvs_handle_t);
int nvs_get_u32(nvs_handle_t, const char*, std::uint32_t*);
int nvs_get_str(nvs_handle_t, const char*, char*, std::size_t*);
inline void mbedtls_platform_zeroize(void* pointer, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(pointer);
    while (size--) *bytes++ = 0;
}
"""
        (fake / "fake_runtime.h").write_text(declarations)
        for header in ("nvs.h", "nvs_flash.h", "esp_flash_encrypt.h", "esp_secure_boot.h", "mbedtls/platform_util.h"):
            (fake / header).write_text('#include "fake_runtime.h"\n')
        cls.binary = compile_native(cls.work, "runtime",
            [ROOT / "tests/runtime_config_native.cpp", ROOT / "src/runtime_config.cpp", ROOT / "src/network_protocol.cpp",
             ROOT / "src/keenetic_settings.cpp"],
            includes=[fake, ROOT / ".pio/libdeps/c3-production-no-oled/ArduinoJson/src"],
            defines=["WARP_PROTECTED_BUILD=1", "OLED_ENABLED=0"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_valid_schema_and_credential_erasure(self): self.run_scenario("valid")
    def test_schema2_thresholds_and_schema1_compatibility(self): self.run_scenario("schema2")
    def test_corrupt_or_incomplete_configuration_fails_closed(self): self.run_scenario("invalid")
    def test_nvs_url_json_memory_and_count_limits(self): self.run_scenario("limits")
    def test_storage_requires_protection_and_existing_keys(self): self.run_scenario("storage")

if __name__ == "__main__":
    unittest.main()
