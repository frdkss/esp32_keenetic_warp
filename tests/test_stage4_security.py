"""Synthetic owner keys only. Real official signing/encryption; no device writes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import security_store as security
except ImportError:
    security = None

IDF = Path(os.environ.get("PLATFORMIO_CORE_DIR", Path.home() / ".platformio")) / "packages/framework-espidf"
SERVICE_PYTHON = ROOT / ".local/service-tools/Scripts/python.exe"
PASSWORD = "SYNTHETIC-backup-passphrase-\u0436-2026"


def evidence(mac="020000000001"):
    return {"schema": 1, "profile": security.PROFILE, "observed_utc": "2026-11-14T00:00:00+00:00",
            "identity": {"chip": "esp32c3", "revision": 4, "flash_bytes": 4194304,
                         "mac": mac, "usb_vid": 0x303A, "usb_pid": 0x1001},
            "efuses": {name: "USER" if name.startswith("KEY_PURPOSE_") else 0 for name in security.FIELDS},
            "key_blocks_empty": {"BLOCK_KEY0": True, "BLOCK_KEY1": True}}


@unittest.skipUnless(security and os.name == "nt" and SERVICE_PYTHON.is_file() and IDF.is_dir(),
                     "Windows and pinned security-requirements.txt are required")
class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        security.check_security_tools(IDF)
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp security-\u0436-")
        cls.work = Path(cls.temporary.name)
        cls.vault = cls.work / "owner"
        cls.other = cls.work / "other"
        security.new_vault(cls.vault, evidence())
        security.new_vault(cls.other, evidence("020000000002"))
        cls.bundle = security.load_vault(cls.vault)
        cls.backup = cls.work / "portable.warpbackup"
        security.backup_vault(cls.vault, cls.backup, PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_unique_device_keys_and_owner_only_dpapi_storage(self):
        second = security.load_vault(self.other)
        self.assertNotEqual(self.bundle["identity"], second["identity"])
        for kind in ("flash", "nvs", "signing"):
            self.assertNotEqual(security.raw(self.bundle, kind), security.raw(second, kind))
            self.assertNotIn(security.raw(self.bundle, kind), (self.vault / "owner.warpkeys").read_bytes())
        security.assert_private(self.vault)
        for item in self.vault.iterdir():
            security.assert_private(item)
        self.assertEqual({p.name for p in self.vault.iterdir()}, {"manifest.json", "owner.warpkeys"})

    def test_private_file_owner_batch_preserves_data_and_rejects_shared_permissions(self):
        directory = security.private_directory(self.work / "ownership-batch")
        paths = [directory / "one.dat", directory / "two.dat"]
        for index, path in enumerate(paths):
            path.write_bytes(b"SYNTHETIC-owner-test-" + bytes([index]))
        original = [path.read_bytes() for path in paths]
        security.seal_private_files(paths)
        for path in paths:
            security.assert_private(path)
        self.assertEqual([path.read_bytes() for path in paths], original)
        # Simulate an unsafe file: migration must never hide or replace a shared DACL.
        script = r"""
        $ErrorActionPreference='Stop'
        $p=$env:WARP_TEST_ACL_FILE
        $acl=Get-Acl -LiteralPath $p
        $sid=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Read','Allow'))
        Set-Acl -LiteralPath $p -AclObject $acl
        """
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=dict(os.environ, WARP_TEST_ACL_FILE=str(paths[1])), check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        with self.assertRaises(security.VaultOwnershipError):
            security.seal_private_files(paths)
        self.assertEqual([path.read_bytes() for path in paths], original)
        with self.assertRaises(subprocess.CalledProcessError):
            security.assert_private(paths[1])

    def test_private_file_owner_batch_rejects_hardlinks(self):
        directory = security.private_directory(self.work / "ownership-link")
        path = directory / "one.dat"
        path.write_bytes(b"SYNTHETIC-non-secret")
        os.link(path, directory / "alias.dat")
        with self.assertRaises(security.VaultOwnershipError):
            security.seal_private_files([path])

    def test_rejects_bad_revision_dirty_efuses_occupied_blocks_and_missing_fields(self):
        mutations = []
        for name in security.FIELDS:
            candidate = evidence()
            candidate["efuses"][name] = "XTS_AES_128_KEY" if name.startswith("KEY_PURPOSE_") else 1
            mutations.append(candidate)
        for revision in (0, 2, 3, 5):
            candidate = evidence()
            candidate["identity"]["revision"] = revision
            mutations.append(candidate)
        candidate = evidence()
        candidate["key_blocks_empty"]["BLOCK_KEY0"] = False
        mutations.append(candidate)
        candidate = evidence()
        candidate["efuses"].pop("DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE")
        mutations.append(candidate)
        for candidate in mutations:
            with self.assertRaises(ValueError):
                security.preflight(candidate)
        self.assertFalse((self.work / "bad").exists())

    def test_portable_backup_restore_and_wrong_password_or_tampering(self):
        recovered = security.open_backup(self.backup, PASSWORD)
        self.assertEqual(recovered, self.bundle)
        restored = self.work / "restored"
        security.save_vault(restored, recovered)
        self.assertEqual(security.load_vault(restored), self.bundle)
        for password in ("short", "wrong-but-long-enough-passphrase"):
            with self.assertRaises(Exception):
                security.open_backup(self.backup, password)
        corrupt = self.work / "corrupt.warpbackup"
        data = bytearray(self.backup.read_bytes())
        data[-1] ^= 1
        corrupt.write_bytes(data)
        with self.assertRaises(Exception):
            security.open_backup(corrupt, PASSWORD)
        for value in self.bundle["keys"].values():
            self.assertNotIn(value.encode(), self.backup.read_bytes())

    def test_no_overwrite_and_no_owner_material_inside_repository(self):
        previous = (self.vault / "owner.warpkeys").read_bytes()
        with self.assertRaises(ValueError):
            security.save_vault(self.vault, self.bundle)
        with self.assertRaises(ValueError):
            security.backup_vault(self.vault, self.backup, PASSWORD)
        with self.assertRaises(ValueError):
            security.plain_path(ROOT / ".local/forbidden-vault", external=True)
        self.assertEqual(previous, (self.vault / "owner.warpkeys").read_bytes())

    def test_real_signature_and_encryption_rehearsal_uses_restored_keys(self):
        with security.transaction(self.work) as work:
            key = work / "nvs.bin"
            key.write_bytes(security.raw(self.bundle, "nvs"))
            request = work / "input.csv"
            request.write_text(
                "key,type,encoding,value\nwarp,namespace,,\nschema,data,u32,1\n"
                "wifi_ssid,data,string,SYNTHETIC-private-SSID\n"
                "wifi_pass,data,string,SYNTHETIC-private-WiFi\n"
                "router_login,data,string,SYNTHETIC-login\n"
                "router_pass,data,string,SYNTHETIC-private-router\n", encoding="utf-8")
            nvs = work / "nvs.encrypted.bin"
            security.run_official(("encrypt", request, nvs, "0x6000", "--inputkey", key, "--version", "2"))
            package = work / "package"
            plan = security.prepare(ROOT, self.vault, self.backup, PASSWORD, evidence(), package,
                                    "c3-production-no-oled", IDF, nvs)
            self.assertEqual(plan["backup_recovery"], "passed")
            self.assertEqual(plan["sign_verify_encrypt_roundtrip"], "passed")
            self.assertFalse(plan["provision_allowed"])
            self.assertEqual([s["address"] for s in plan["segments"]], [0, 0xF000, 0x10000, 0x16000, 0x20000, 0x3E0000])
            self.assertEqual(len(bytes.fromhex(plan["secure_boot_digest_hex"])), 32)
            self.assertEqual((package / "nvs.encrypted.bin").read_bytes(), nvs.read_bytes())
            for path in package.iterdir():
                data = path.read_bytes()
                self.assertNotIn(b"SYNTHETIC-private", data)
                self.assertNotIn(b"PRIVATE KEY", data)
                self.assertNotIn(security.raw(self.bundle, "flash"), data)
                security.assert_private(path)
            # Even an edited approval flag cannot enable the absent hardware executor.
            plan["provision_allowed"] = True
            (package / "plan.json").write_bytes(security.encoded(plan))
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(ROOT / "service.ps1"), "-Action", "Provision", "-PackageDirectory", str(package)],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"No flash/eFuse operation", result.stdout + result.stderr)
            self.assertNotIn(b"SYNTHETIC-private", result.stdout + result.stderr)
            self.assertFalse(any(p.name.endswith((".pem", ".key")) for p in package.iterdir()))

    def test_device_or_backup_mismatch_cannot_create_package(self):
        for vault, backup, proof in ((self.other, self.backup, evidence()),
                                    (self.vault, self.backup, evidence("020000000002"))):
            output = self.work / "must-not-exist"
            with self.assertRaises(ValueError):
                security.prepare(ROOT, vault, backup, PASSWORD, proof, output,
                                 "c3-production-no-oled", IDF, self.work / "missing-nvs.bin")
            self.assertFalse(output.exists())

    def test_wrong_nvs_key_fails_without_publishing_or_retaining_raw_keys(self):
        with security.transaction(self.work) as work:
            source = work / "nvs.csv"
            source.write_text("key,type,encoding,value\nwarp,namespace,,\nschema,data,u32,1\n", encoding="utf-8")
            key = work / "key.bin"
            key.write_bytes(security.raw(self.bundle, "nvs"))
            encrypted = work / "nvs.encrypted.bin"
            security.run_official(("encrypt", source, encrypted, "0x6000", "--inputkey", key, "--version", "2"))
            key.write_bytes(security.raw(security.load_vault(self.other), "nvs"))
            with self.assertRaises(Exception):
                security.verify_nvs(encrypted, key, work, IDF)
            self.assertFalse((work / "nvs.decrypted.bin").exists())
            output = work / "failed-package"
            with self.assertRaises(Exception):
                security.prepare(ROOT, self.vault, self.backup, PASSWORD, evidence(), output,
                                 "c3-production-no-oled", IDF, encrypted)
            self.assertFalse(output.exists())
            self.assertFalse(any(p.name.startswith(".warp-private-") for p in work.iterdir()))

    def test_runtime_security_exceptions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sdkconfig.c3-production-no-oled"
            original = (ROOT / path.name).read_text(encoding="utf-8")
            for name in ("SECURE_BOOT_ALLOW_JTAG", "AUTOSTART_ARDUINO", "ESP_TLS_INSECURE", "ESP_TLS_SKIP_SERVER_CERT_VERIFY"):
                path.write_text(original + f"\nCONFIG_{name}=y\n", encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    security.sdk_configuration(root, "c3-production-no-oled")
            for name in ("MBEDTLS_CERTIFICATE_BUNDLE", "MBEDTLS_HAVE_TIME_DATE"):
                path.write_text(original.replace(f"CONFIG_{name}=y", f"# CONFIG_{name} is not set"), encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    security.sdk_configuration(root, "c3-production-no-oled")
            with self.assertRaises(ValueError):
                security.sdk_configuration(ROOT, "c3-test-no-oled")

    def test_service_new_actions_validate_before_writing_and_ignore_keys(self):
        for action in ("NewDeviceKeys", "BackupKeys", "RestoreKeys", "PrepareProvision", "InspectProtection"):
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                     "-File", str(ROOT / "service.ps1"), "-Action", action],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"requires", result.stdout + result.stderr)
        result = subprocess.run(["git", "check-ignore", "--stdin", "-z"], cwd=ROOT,
                                input=b"owner.warpkeys\0portable.warpbackup\0", capture_output=True, check=True)
        self.assertEqual(set(result.stdout.split(b"\0")) - {b""}, {b"owner.warpkeys", b"portable.warpbackup"})

    def test_powershell_backup_restore_and_device_bound_configuration(self):
        with tempfile.TemporaryDirectory(prefix="warp PS security-\u0436-") as temporary:
            work = Path(temporary)
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(ROOT / "tests/verify_stage4.ps1"), "-WorkRoot", str(work),
                "-Vault", str(self.vault), "-PythonPath", str(SERVICE_PYTHON), "-IdfPath", str(IDF)],
                capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, "PowerShell vault lifecycle failed (diagnostics suppressed)")
            self.assertNotIn(b"SYNTHETIC", result.stdout + result.stderr)
            self.assertIn(b"PASS bound", result.stdout)
            with security.transaction(work) as private:
                key = private / "nvs.bin"
                key.write_bytes(security.raw(self.bundle, "nvs"))
                security.verify_nvs(work / "project/.local/service/nvs.encrypted.bin", key, private, IDF)


if __name__ == "__main__":
    unittest.main()
