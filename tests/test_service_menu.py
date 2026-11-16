"""Menu/DPAPI/child-process tests; no installation or attached hardware."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".local/service-tools/Scripts/python.exe"


@unittest.skipUnless(os.name == "nt" and PYTHON.is_file(), "Windows service tools required")
class MenuTests(unittest.TestCase):
    def test_initial_flash_reads_mac_without_a_prompt_and_rejects_changed_device(self):
        with tempfile.TemporaryDirectory(prefix="warp-auto-mac-") as work:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(ROOT / "tests/verify_provision_menu.ps1"), "-WorkRoot", work],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))
            self.assertIn(b"PASS automatic MAC", result.stdout)

    def test_state_editor_validation_dpapi_and_child_argument_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix="warp-menu-") as work:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(ROOT / "tests/verify_menu.ps1"), "-WorkRoot", work, "-PythonPath", str(PYTHON)],
                capture_output=True, timeout=60)
            output = result.stdout + result.stderr
            self.assertNotIn(b"SYNTHETIC", output, "Credential leaked to console")
            self.assertEqual(result.returncode, 0, output.decode(errors="replace"))
            self.assertIn(b"PASS menu/state/process", output)

    def test_redirected_default_menu_fails_without_waiting_or_uac(self):
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(ROOT / "service.ps1")], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"interactive Windows console", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
