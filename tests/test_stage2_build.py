"""Stage 2 contracts independent of hardware and real credentials."""
import csv
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_guard", ROOT / "scripts/build_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class BuildBoundaryTests(unittest.TestCase):
    def test_protected_device_targets_are_rejected(self):
        for environment in ("c3-production-no-oled", "c3-production-oled"):
            for target in ("upload", "uploadfs", "erase", "program", "debug", "sign", "encrypt", "__upload-app"):
                with self.subTest(environment=environment, target=target):
                    with self.assertRaisesRegex(ValueError, "BUILD ONLY"):
                        guard.validate_targets(True, [target])

    def test_protected_build_targets_are_allowed(self):
        guard.validate_targets(True, [])
        guard.validate_targets(True, ["buildprog", "size"])

    def test_partition_layout_has_room_for_signed_bootloader_and_app(self):
        rows = list(csv.reader(line for line in (ROOT / "partitions.csv").read_text().splitlines()
                               if line.strip() and not line.lstrip().startswith("#")))
        previous_end = 0x10000  # Table at 0xF000 occupies one sector.
        partitions = {}
        for row in rows:
            name, kind, subtype, offset, size, flags = (value.strip() for value in row)
            offset, size = int(offset, 0), int(size, 0)
            self.assertGreaterEqual(offset, previous_end)
            self.assertEqual(offset % 0x1000, 0)
            self.assertEqual(size % 0x1000, 0)
            if kind == "app":
                self.assertEqual(offset % 0x10000, 0)
                self.assertEqual(size % 0x10000, 0)  # V2 signature alignment.
            previous_end = offset + size
            partitions[name] = (kind, subtype, offset, size, flags)
        self.assertLessEqual(previous_end, 4 * 1024 * 1024)
        self.assertEqual(partitions["nvs_keys"][3:], (0x1000, "encrypted"))
        self.assertEqual(partitions["nvs"][4], "")  # NVS XTS, not flash-encrypted pages.

    def test_generated_and_secret_files_are_ignored(self):
        paths = ["secret.txt", "include/config.h", "include/service_secrets.h",
                 ".pio/build/c3-test-no-oled/firmware.bin", "sdkconfig.c3-production-oled",
                 ".local/stage2/private.json", "keys/device.pem", "nvs.bin"]
        result = subprocess.run(["git", "check-ignore", "--stdin", "-z"],
                                input=("\0".join(paths) + "\0").encode(),
                                cwd=ROOT, capture_output=True, check=True)
        self.assertEqual(set(result.stdout.decode().rstrip("\0").split("\0")), set(paths))
        result = subprocess.run(["git", "check-ignore", "sdkconfig.defaults", "sdkconfig.production.defaults"],
                                cwd=ROOT, capture_output=True)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
