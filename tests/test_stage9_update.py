"""Real crypto/DPAPI and bounded fake USB/ROM. Never opens a physical serial port."""
import contextlib
import copy
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_stage4_security import IDF, ROOT, SERVICE_PYTHON, evidence, security

sys.path.insert(0, str(ROOT / "scripts"))
import secure_update as update
import wifi_update


def rom_info():
    return {"chip_id": 5, "flash_crypt_cnt": 7, "flags": 0x4F5,
            "key_purposes": [4, 9, 0, 0, 0, 0, 0]}


class FakeRom:
    CHIP_NAME, IS_STUB, secure_download_mode, FLASH_WRITE_SIZE = "ESP32-C3", False, True, 1024

    def __init__(self):
        self.info = rom_info()
        self.calls = []
        self.memory = bytearray(b"\xA5" * 4194304)

    def get_security_info(self, cache=False): return copy.deepcopy(self.info)
    def flash_spi_attach(self, value): self.calls.append(("attach", value))
    def flash_set_parameters(self, value): self.calls.append(("size", value))
    def flash_begin(self, size, address, begin_rom_encrypted=False):
        self.calls.append(("begin", size, address, begin_rom_encrypted))
        self.address = address
        self.memory[address:address + size] = b"\xff" * size
    def flash_block(self, data, seq):
        offset = self.address + seq * self.FLASH_WRITE_SIZE
        self.memory[offset:offset + len(data)] = data
    def flash_finish(self, reboot=False): raise AssertionError("FLASH_END must not exit ROM between segments")
    def hard_reset(self, uses_usb=False): self.calls.append(("reset", uses_usb))


@unittest.skipUnless(security and os.name == "nt" and SERVICE_PYTHON.is_file() and IDF.is_dir(),
                     "Windows with pinned security tools required")
class WifiUpdateTests(unittest.TestCase):
    KEY = bytes(range(64))

    def signed_reply(self, nonce, **changes):
        import json as _json
        reply = {"schema": 1, "nonce": nonce, "mac": "020000000001", "model": "esp32c3", "tls_port": 8443,
                 "tls_sha256": "ab" * 32, "slot": 0x20000, "target": 0x200000, "target_size": 0x1E0000,
                 "app_sha": "cd" * 32, "version_hex": "ef" * 32, **changes}
        payload = _json.dumps(reply, separators=(",", ":")).encode()
        tag = hmac.digest(self.KEY, wifi_update.DISCOVER_DOMAIN + payload, "sha256").hex().encode()
        return b"WARP-HERE-1 " + payload + b" " + tag + b"\n"

    def test_discovery_reply_is_bound_to_nonce_and_device_key(self):
        nonce = "12" * 32
        with patch.object(wifi_update, "device_key", return_value=self.KEY):
            self.assertEqual(wifi_update.parse_reply(self.signed_reply(nonce), nonce, None)["target"], 0x200000)
            self.assertIsNone(wifi_update.parse_reply(self.signed_reply("34" * 32), nonce, None))
            tampered = self.signed_reply(nonce).replace(b'"target":2097152', b'"target":2097153')
            self.assertIsNone(wifi_update.parse_reply(tampered, nonce, None))
            self.assertIsNone(wifi_update.parse_reply(self.signed_reply(nonce, schema=2), nonce, None))

    def test_tls_record_fingerprint_matches_the_certificate_it_carries(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        record, fingerprint = wifi_update.tls_identity("020000000001")
        self.assertEqual(len(record), 0x1000)
        self.assertEqual(record[:8], b"WARPTLS1")
        cert_size = int.from_bytes(record[8:12], "little")
        certificate = x509.load_pem_x509_certificate(record[80:80 + cert_size])
        der = certificate.public_bytes(serialization.Encoding.DER)
        self.assertEqual(fingerprint, security.sha(der))
        self.assertEqual(record[16:80].decode(), fingerprint)

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-update-\u0436-")
        cls.work = Path(cls.temporary.name)
        cls.vault = cls.work / "owner"
        security.new_vault(cls.vault, evidence())
        cls.bundle = security.load_vault(cls.vault)
        cls.package = cls.work / "package"
        cls.plan = update.prepare(ROOT, cls.vault, cls.package, "c3-production-no-oled", IDF)
        with security.transaction(cls.work) as work:
            cls.plan, cls.cipher = update.load_package(cls.package, cls.bundle, work)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def proof(self, plan=None, **changes):
        plan = plan or self.plan
        source = (ROOT / ".pio/build/c3-production-no-oled/firmware.bin").read_bytes()
        return {"schema": 1, "nonce": "12" * 32, "mac": self.bundle["identity"]["mac"], "slot": 0x20000,
                "revision": 4, "flash_bytes": 4194304, "secure": 1,
                **{k: plan[k] for k in ("app_sha", "image_sha", "version_hex", "boot_digest", "table_sha")},
                "cipher": self.cipher[:128].hex(), "plain_sha": security.sha(source[:128]),
                "cycle": 1, "controls": 1, "targets": 2, "ready": 1, "internet": 1, "time": 1, **changes}

    def frame(self, proof, key=None):
        payload = security.encoded(proof)
        tag = hmac.digest(key or security.raw(self.bundle, "nvs")[:64], update.DOMAIN + payload, "sha256").hex()
        return b"WARP9 " + payload + b" " + tag.encode() + b"\n"

    def test_real_signed_encrypted_application_and_no_overwrite(self):
        self.assertEqual({p.name for p in self.package.iterdir()}, {"update.json", "update.sig", "firmware.encrypted.bin"})
        self.assertEqual(self.plan["address"], 0x20000)
        self.assertEqual(bytes.fromhex(self.plan["version_hex"]).split(b"\0")[0], b"0.3.0")
        with self.assertRaises(ValueError):
            update.prepare(ROOT, self.vault, self.package, "c3-production-no-oled", IDF)
        for item in self.package.iterdir():
            data = item.read_bytes()
            for kind in ("flash", "nvs", "signing"):
                self.assertNotIn(security.raw(self.bundle, kind), data)
            security.assert_private(item)

    def test_manifest_cipher_corruption_extra_segments_and_wrong_keys_fail(self):
        with security.transaction(self.work) as work:
            candidate = work / "package"
            shutil.copytree(self.package, candidate)
            for filename in ("update.sig", "update.json", "firmware.encrypted.bin"):
                path = candidate / filename
                original = path.read_bytes()
                changed = bytearray(original)
                changed[len(changed) // 2] ^= 1
                path.write_bytes(changed)
                with self.assertRaises(Exception): update.load_package(candidate, self.bundle, work)
                path.write_bytes(original)
            (candidate / "nvs.encrypted.bin").write_bytes(b"unexpected")
            with self.assertRaisesRegex(update.UpdateError, "contents"):
                update.load_package(candidate, self.bundle, work)
            (candidate / "nvs.encrypted.bin").unlink()
            other = copy.deepcopy(self.bundle)
            other["identity"]["mac"] = "020000000002"
            with self.assertRaisesRegex(update.UpdateError, "mismatch"):
                update.load_package(candidate, other, work)

    def test_authenticated_probe_fresh_nonce_nvs_flash_signing_and_device_binding(self):
        with security.transaction(self.work) as work:
            update.key_files(self.bundle, work)
            proof = self.proof()
            self.assertEqual(update.validate_probe(self.frame(proof), proof["nonce"], self.bundle, self.plan, work), proof)
            for changed in ({"nonce": "ab" * 32}, {"mac": "020000000002"}, {"revision": 3},
                            {"flash_bytes": 2097152}, {"secure": 0}, {"boot_digest": "00" * 32},
                            {"table_sha": "00" * 32}, {"plain_sha": "00" * 32}, {"cipher": "00" * 128},
                            {"cycle": -1}, {"ready": True}, {"image_sha": "bad"}):
                with self.subTest(changed=changed), self.assertRaises(update.UpdateError):
                    update.validate_probe(self.frame(self.proof(**changed)), proof["nonce"], self.bundle, self.plan, work)
            with self.assertRaisesRegex(update.UpdateError, "NVS key"):
                update.validate_probe(self.frame(proof, b"bad-key"), proof["nonce"], self.bundle, self.plan, work)
            wrong = copy.deepcopy(self.bundle)
            import base64
            wrong["keys"]["flash"] = base64.b64encode(b"\xCC" * 32).decode()
            update.key_files(wrong, work)
            with self.assertRaisesRegex(update.UpdateError, "flash encryption key"):
                update.validate_probe(self.frame(proof), proof["nonce"], self.bundle, self.plan, work)

    def test_secure_rom_rejects_every_unknown_protection_flag_and_key_purpose(self):
        esp = FakeRom()
        update.validate_rom(esp)
        for flag in range(32):
            esp.info = rom_info()
            esp.info["flags"] ^= 1 << flag
            with self.subTest(flag=flag), self.assertRaises(update.UpdateError): update.validate_rom(esp)
        for field, value in (("chip_id", 4), ("flash_crypt_cnt", 1), ("key_purposes", [4, 9, 0, 0, 0, 0])):
            esp.info = rom_info(); esp.info[field] = value
            with self.assertRaises(update.UpdateError): update.validate_rom(esp)
        for index in range(6):
            esp.info = rom_info(); esp.info["key_purposes"][index] ^= 1
            with self.assertRaises(update.UpdateError): update.validate_rom(esp)
        for reserved in (0, 12, 255):
            esp.info = rom_info(); esp.info['key_purposes'][6] = reserved
            update.validate_rom(esp)
        self.assertEqual(esp.calls, [])

    def test_optional_runtime_diagnostics_are_authenticated_and_strictly_typed(self):
        with security.transaction(self.work) as work:
            update.key_files(self.bundle, work)
            proof = self.proof(runtime_error=21, router_http=401)
            accepted = update.validate_probe(self.frame(proof), proof['nonce'], self.bundle, self.plan, work)
            self.assertIn('runtime=HTTP_FORMAT', update.monitoring_summary(accepted))
            self.assertIn('router_http=401', update.monitoring_summary(accepted))
            for values in ({'runtime_error':32,'router_http':401}, {'runtime_error':21,'router_http':True},
                           {'runtime_error':21,'router_http':99}, {'runtime_error':True,'router_http':401},
                           {'runtime_error':21}):
                candidate = self.proof(**values)
                with self.subTest(values=values), self.assertRaisesRegex(update.UpdateError, 'runtime diagnostics'):
                    update.validate_probe(self.frame(candidate), candidate['nonce'], self.bundle, self.plan, work)

    def test_timeout_distinguishes_running_authenticated_image_from_runtime_failure(self):
        device, _ = self.device(after=self.proof(ready=0, runtime_error=21, router_http=401))
        with self.assertRaises(update.UpdateError) as failure:
            update.execute(self.package, self.vault, IDF, device, timeout=.05)
        self.assertIn('Firmware is authenticated', str(failure.exception))
        self.assertIn('runtime=HTTP_FORMAT', str(failure.exception))
        self.assertIn('router_http=401', str(failure.exception))

    def test_rom_writer_preserves_all_other_sectors_and_bounds(self):
        esp = FakeRom()
        update.write_ciphertext(esp, self.cipher)
        self.assertEqual(esp.memory[:0x20000], b"\xA5" * 0x20000)
        self.assertEqual(esp.memory[0x20000:0x20000 + len(self.cipher)], self.cipher)
        self.assertEqual(esp.memory[0x20000 + len(self.cipher):], b"\xA5" * (4194304 - 0x20000 - len(self.cipher)))
        self.assertEqual(esp.calls[2], ("begin", len(self.cipher), 0x20000, False))
        self.assertEqual(esp.calls[-1], ("reset", True))
        for data in (b"", b"x" * 4095, b"x" * (update.LIMIT + 4096)):
            candidate = FakeRom()
            with self.assertRaises(update.UpdateError): update.write_ciphertext(candidate, data)
            self.assertEqual(candidate.calls, [])
        for name, value in (("IS_STUB", True), ("secure_download_mode", False), ("CHIP_NAME", "ESP32")):
            candidate = FakeRom(); setattr(candidate, name, value)
            with self.assertRaises(update.UpdateError): update.write_ciphertext(candidate, b"x" * 4096)
            self.assertEqual(candidate.calls, [])

    def device(self, after=None, before=None):
        esp = FakeRom()
        @contextlib.contextmanager
        def rom(mac):
            self.assertEqual(mac, self.bundle["identity"]["mac"])
            yield esp
        device = Mock()
        device.rom.side_effect = rom
        device.probe.side_effect = [before or self.proof(), after or self.proof()]
        return device, esp

    def test_update_requires_exact_booted_image_and_working_monitoring(self):
        device, esp = self.device()
        result = update.execute(self.package, self.vault, IDF, device, timeout=1)
        self.assertEqual(result["result"], "verified")
        self.assertFalse(result["nvs_targeted"])
        self.assertEqual(esp.memory[0x10000:0x17000], b"\xA5" * 0x7000)
        for after in (self.proof(app_sha="00" * 32), self.proof(image_sha="00" * 32), self.proof(version_hex="00" * 32)):
            device, esp = self.device(after=after)
            with self.assertRaisesRegex(update.UpdateError, "did not start"):
                update.execute(self.package, self.vault, IDF, device, timeout=1)
        device, esp = self.device(after=self.proof(cycle=0))
        with self.assertRaisesRegex(update.UpdateError, "not verified"):
            update.execute(self.package, self.vault, IDF, device, timeout=0.05)

    def test_preflight_failure_cannot_start_write_or_reset(self):
        device, esp = self.device(before=self.proof(ready=0))
        with self.assertRaisesRegex(update.UpdateError, "not ready"):
            update.execute(self.package, self.vault, IDF, device)
        device.rom.assert_not_called()
        self.assertEqual(esp.calls, [])
        device = Mock()
        with self.assertRaisesRegex(update.UpdateError, "keys are missing"):
            update.execute(self.package, self.work / "missing", IDF, device)
        device.probe.assert_not_called()

    def test_native_usb_identity_is_required_across_reset(self):
        port = Mock(device="COM4", vid=0x303A, pid=0x1001, serial_number="02:00:00:00:00:01")
        with patch("serial.tools.list_ports.comports", return_value=[port]):
            self.assertEqual(update.usb_serial("COM4", "020000000001"), "020000000001")
            for field, value in (("serial_number", None), ("serial_number", "02:00:00:00:00:02"), ("vid", 0x1234)):
                old = getattr(port, field); setattr(port, field, value)
                with self.assertRaises(update.UpdateError): update.usb_serial("COM4", "020000000001")
                setattr(port, field, old)

    def test_powershell_prepare_and_safe_missing_keys_error(self):
        destination = self.work / "powershell-package"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            str(ROOT / "service.ps1"), "-Action", "PrepareUpdate", "-KeyStore", str(self.vault),
            "-PackageDirectory", str(destination)], capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, "PowerShell PrepareUpdate failed")
        self.assertTrue((destination / "update.json").is_file())
        result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            str(ROOT / "service.ps1"), "-Action", "Update", "-KeyStore", str(self.work / "missing"),
            "-PackageDirectory", str(destination), "-Port", "COM999"], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Owner keys are missing", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__": unittest.main()
