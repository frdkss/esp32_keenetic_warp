"""Real Windows PowerShell 5.1 tests, synthetic secrets only; no attached devices."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICE_PYTHON = ROOT / ".local/service-tools/Scripts/python.exe"
IDF = Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio")) / "packages/framework-espidf"
COMPILER = IDF.parent / "toolchain-riscv32-esp/bin/riscv32-esp-elf-g++.exe"
POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(POWERSHELL and SERVICE_PYTHON.is_file() and IDF.is_dir(),
                     "Requires Windows PowerShell 5.1 and pinned local service tools")
class ServiceTests(unittest.TestCase):
    def run_case(self, name, work):
        result = subprocess.run([
            POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(ROOT / "tests/verify_stage3.ps1"), "-Case", name,
            "-WorkRoot", str(work), "-PythonPath", str(SERVICE_PYTHON), "-IdfPath", str(IDF),
        ], capture_output=True, timeout=60, cwd=work)
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        # Never dump whole output on failure: that would hide a secret-leak regression.
        for sentinel in (b"TEST-password", b"TEST-SSID", b"TEST-login", b"wifi", b"synthetic", b"INVALID-SECRET"):
            self.assertFalse(sentinel in result.stdout + result.stderr, "Synthetic secret leaked to output")
        self.assertEqual(result.returncode, 0, "PowerShell case failed: " + name)
        self.assertIn("PASS " + name, output)

    def test_validation(self):
        with tempfile.TemporaryDirectory() as work:
            self.run_case("Validation", work)

    def test_hidden_password_input_and_cancellation(self):
        with tempfile.TemporaryDirectory() as work:
            self.run_case("Input", work)

    def test_failed_nvs_generation_keeps_existing_files(self):
        with tempfile.TemporaryDirectory() as work:
            self.run_case("GeneratorFailure", work)

    def test_replacement_failure_rolls_back_both_headers(self):
        with tempfile.TemporaryDirectory() as work:
            self.run_case("Rollback", work)

    def test_invalid_input_preserves_existing_headers_and_encrypted_nvs(self):
        with tempfile.TemporaryDirectory() as work:
            self.run_case("InvalidInput", work)

    def test_real_nvs_roundtrip_and_cpp_headers(self):
        # Include a space and Cyrillic in paths to exercise PS/native argument handling.
        with tempfile.TemporaryDirectory(prefix="service test-\u0436-") as temporary:
            work = Path(temporary)
            self.run_case("Generate", work)
            project = work / "project"
            encrypted = project / ".local/service/nvs.encrypted.bin"
            plain = work / "roundtrip.bin"
            result = subprocess.run([
                str(SERVICE_PYTHON), str(IDF / "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py"),
                "decrypt", str(encrypted), str(work / "nvs-key.bin"), str(plain),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            # Parse the decrypted NVS with Espressif's parser, independent of our adapter.
            parser_spec = importlib.util.spec_from_file_location(
                "nvs_parser", IDF / "components/nvs_flash/nvs_partition_tool/nvs_parser.py")
            parser = importlib.util.module_from_spec(parser_spec)
            parser_spec.loader.exec_module(parser)
            partition = parser.NVS_Partition("roundtrip", bytearray(plain.read_bytes()))
            values = {}
            for page in partition.pages:
                if page.is_empty:
                    continue
                for entry in page.entries:
                    if entry.metadata["namespace"] == 1 and entry.state == "Written":
                        values[entry.key] = entry
            expected_strings = {
                "wifi_ssid": "TEST-SSID-\u0436\u044f",
                "wifi_pass": '  wifi"\\,$`\u0436\u044f  ',
                "router_login": 'TEST-login"\\,\u0436\u044f',
                "router_pass": '  TEST-password"\\,$`\u0436\u044f  ',
                "router_addr": "192.0.2.1", "router_tls": "router.example.invalid",
                "warp_iface": "Wireguard7", "timezone": "MSK-3", "schedule_time": "05:00",
                "target_urls": json.dumps(["https://target.example.invalid/", "https://target.example.invalid/Case?q=A"], separators=(",", ":")),
                "control_urls": '["https://control.example.invalid/"]',
            }
            for key, expected in expected_strings.items():
                entry = values[key]
                raw = b"".join(bytes(child.raw) for child in entry.children)[:entry.data["size"]]
                self.assertTrue(raw.rstrip(b"\0").decode("utf-8") == expected,
                                "NVS string roundtrip failed: " + key)
                if key in ("wifi_ssid", "wifi_pass", "router_login", "router_pass"):
                    self.assertNotIn(expected.encode(), encrypted.read_bytes())
            expected_numbers = {"schema": 2, "router_port": 443, "schedule_day": 4, "fail_threshold": 5, "target_policy": 2,
                                "check_secs": 60, "connect_secs": 5, "read_secs": 5, "disable_secs": 2,
                                "warmup_secs": 30, "cooldown_secs": 300, "autorecovery": 1,
                                "weekly_restart": 0, "oled_enabled": 0}
            for key, expected in expected_numbers.items():
                self.assertTrue(values[key].data["value"] == expected, "NVS integer roundtrip failed: " + key)
            self.assertEqual(set(values), set(expected_strings) | set(expected_numbers))
            public = (project / "include/config.h").read_text(encoding="utf-8")
            for key in ("wifi_ssid", "wifi_pass", "router_login", "router_pass"):
                self.assertNotIn(expected_strings[key], public)
            self.assertIn("std::array<const char*, 2>", public)
            self.assertFalse((project / "include/config.h").read_bytes().startswith(b"\xef\xbb\xbf"))
            if COMPILER.is_file():
                self.check_cpp(project, expected_strings)

    def check_cpp(self, project, values):
        source = project / "verify.cpp"
        def literal(text):
            return '"' + "".join("\\%03o" % byte for byte in text.encode("utf-8")) + '"'
        assertions = []
        for field, key in (("wifiSsid", "wifi_ssid"), ("wifiPassword", "wifi_pass"),
                           ("routerLogin", "router_login"), ("routerPassword", "router_pass")):
            assertions.append(f"static_assert(eq(warp::provisioning::{field}, {literal(values[key])}));")
        source.write_text(
            '#define WARP_PROVISIONING_SECRETS 1\n#include "config.h"\n#include "service_secrets.h"\n'
            'constexpr bool eq(const char* a, const char* b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }\n'
            + "\n".join(assertions) + '\nstatic_assert(warp::config::targetUrls.size() == 2);\n', encoding="utf-8")
        command = [str(COMPILER), "-std=gnu++17", "-fsyntax-only", "-I", str(project / "include"), str(source)]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        self.assertEqual(result.returncode, 0, "Generated C++17 headers failed byte-for-byte static assertions")
        source.write_text('#include "service_secrets.h"\n', encoding="utf-8")
        result = subprocess.run(command, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"only for an explicitly selected provisioning tool", result.stderr)

    def test_action_boundaries(self):
        for action, expected_code, message in (("Help", 0, b"PowerShell 5.1"),
                                                ("Provision", 1, b"stage 4"),
                                                ("PrepareUpdate", 1, b"PrepareUpdate requires"),
                                                ("Update", 1, b"Update requires")):
            result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                     "-File", str(ROOT / "service.ps1"), "-Action", action],
                                    cwd=ROOT, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, expected_code)
            self.assertIn(message, result.stdout + result.stderr)

    def test_git_excludes_all_service_material(self):
        paths = ["include/config.h", "include/service_secrets.h", "secret.txt", ".local/service/request.json",
                 "private.nvs.csv", "private.secrets.json", "nvs.encrypted.bin", "keys/nvs.bin",
                 "owner.pem", "owner.key", "owner.pfx", "owner.p12", "config.h.backup", ".pio/build/artifact.elf"]
        result = subprocess.run(["git", "check-ignore", "--stdin", "-z"], input=("\0".join(paths) + "\0").encode(),
                                cwd=ROOT, capture_output=True, check=True)
        self.assertEqual(set(result.stdout.decode().rstrip("\0").split("\0")), set(paths))
        source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src").rglob("*.cpp"))
        self.assertNotIn('include "service_secrets.h"', source)


if __name__ == "__main__":
    unittest.main()
