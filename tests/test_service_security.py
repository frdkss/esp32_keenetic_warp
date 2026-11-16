"""Real signing/NVS/DPAPI, virtual Espressif eFuses, and fake USB. No hardware."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_stage4_security import IDF, ROOT, SERVICE_PYTHON, PASSWORD, evidence, security
from test_stage5_network import compile_native
from test_stage9_probe import FAKES
from test_stage9_update import FakeRom

sys.path.insert(0, str(ROOT / "scripts"))
import secure_provision as provision
import secure_update as update
import service_nvs as nvs


def configuration():
    return {
        "WifiSsid": "SYNTHETIC-SSID-\u0436", "WifiPassword": 'synthetic "wifi" \\ password',
        "RouterLogin": "SYNTHETIC-account", "RouterPassword": 'synthetic router \\ "password"',
        "RouterAddress": "192.0.2.1", "RouterHttpsName": "router.example.invalid", "RouterPort": 443,
        "WarpInterface": "Wireguard7", "TargetUrls": ["https://target.example.invalid/one", "https://target.example.invalid/two"],
        "ControlUrls": ["https://control.example.invalid/"], "CheckIntervalSeconds": 60,
        "ConnectTimeoutSeconds": 5, "ReadTimeoutSeconds": 5, "DisablePauseSeconds": 2,
        "WarmupSeconds": 30, "CooldownSeconds": 600, "FailureThreshold": 7, "TargetFailurePolicy": 0,
        "ScheduleDay": 4, "ScheduleTime": "05:00", "Timezone": "MSK-3",
        "EnableAutoRecovery": 1, "EnableWeeklyRestart": 1, "OledEnabled": 0,
    }


def virtual_commands():
    import espefuse
    return espefuse.init_commands(chip="esp32c3", virt=True, do_not_confirm=True)


@unittest.skipUnless(os.name == "nt", "Windows native/DPAPI harness")
class ContractTests(unittest.TestCase):
    def test_python_and_actual_firmware_configuration_hmac_match(self):
        c = configuration()
        def literal(text):
            return '"' + "".join("\\%03o" % b for b in text.encode("utf-8")) + '"'
        with tempfile.TemporaryDirectory(prefix="warp-tag-") as temporary:
            work = Path(temporary)
            fake = work / "fake/mbedtls"
            fake.mkdir(parents=True)
            (fake / "md.h").write_text('#include "../probe_fakes.h"\n')
            (fake.parent / "probe_fakes.h").write_text(FAKES)
            source = ['#include "warp/config_tag.h"', '#include <cstring>', '#include <iostream>',
                      'int main() { warp::RuntimeConfiguration c;']
            arrays = {"WifiSsid": "wifiSsid", "WifiPassword": "wifiPassword", "RouterLogin": "routerLogin",
                "RouterPassword": "routerPassword", "RouterAddress": "router.address", "RouterHttpsName": "router.tlsName",
                "WarpInterface": "router.interfaceName", "Timezone": "network.timezone"}
            for field, target in arrays.items():
                source.append(f"std::strcpy(c.{target}.data(), {literal(c[field])});")
            source += ["c.router.port=443; c.scheduler.weekday=4; c.scheduler.hour=5; c.scheduler.minute=0;",
                "c.monitor.failureThreshold=7; c.monitor.targetFailurePolicy=warp::TargetFailurePolicy::Any;",
                "c.monitor.cooldownMs=600000;"]
            for field, target in (("TargetUrls", "targets"), ("ControlUrls", "controls")):
                source.append(f"c.network.{'targetCount' if field == 'TargetUrls' else 'controlCount'}={len(c[field])};")
                for index, url in enumerate(c[field]):
                    source.append(f"std::strcpy(c.network.{target}[{index}].data(), {literal(url)});")
            source += ["unsigned char key[64], tag[32]; for(unsigned i=0;i<64;++i) key[i]=static_cast<unsigned char>(i);",
                "if(!warp::configurationTag(c,key,tag)) return 1;",
                'for(unsigned char b:tag) std::cout << "0123456789abcdef"[b>>4] << "0123456789abcdef"[b&15];',
                "}"]
            (work / "tag.cpp").write_text("\n".join(source))
            binary = compile_native(work, "tag", [work / "tag.cpp", ROOT / "src/config_tag.cpp"], includes=[fake.parent])
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, nvs.configuration_tag(c, bytes(range(64))))

    def test_official_virtual_c3_burn_order_and_usb_preservation(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            commands = virtual_commands()
            phases = []
            bundle = {"keys": {"flash": base64.b64encode(bytes(range(32))).decode()}}
            provision.burn_security(commands, bundle, bytes(range(32)).hex(), phases.append)
            self.assertEqual(phases, ["flash-key", "signing-digest", "security-flags", "write-protection", "secure-download"])
            self.assertEqual(int(commands.efuses["ENABLE_SECURITY_DOWNLOAD"].get_raw()), 1)
            for name in provision.KEEP_ZERO:
                self.assertEqual(int(commands.efuses[name].get_raw()), 0)
            with self.assertRaises(Exception):
                provision.burn_security(commands, bundle, "24" * 32, lambda _: None)


@unittest.skipUnless(os.name == "nt" and SERVICE_PYTHON.is_file(), "Windows pinned security tools")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-service-security-")
        cls.work = Path(cls.temporary.name)
        cls.vault = cls.work / "owner"
        security.new_vault(cls.vault, evidence())
        cls.bundle = security.load_vault(cls.vault)
        cls.backup = cls.work / "copy.warpbackup"
        security.backup_vault(cls.vault, cls.backup, PASSWORD)
        cls.config = configuration()
        cls.nvs = cls.work / "configuration.bin"
        with security.transaction(cls.work) as work:
            key = work / "key.bin"
            key.write_bytes(security.raw(cls.bundle, "nvs"))
            csv = work / "input.csv"
            nvs.write_csv(cls.config, csv)
            nvs.run_official(("encrypt", csv, cls.nvs, "0x6000", "--inputkey", key, "--version", "2"))
        cls.package = cls.work / "update"
        cls.plan = update.prepare(ROOT, cls.vault, cls.package, "c3-production-no-oled", IDF, cls.nvs)
        with security.transaction(cls.work) as work:
            _, cls.cipher = update.load_package(cls.package, cls.bundle, work)
        cls.initial = cls.work / "initial"
        security.prepare(ROOT, cls.vault, cls.backup, PASSWORD, evidence(), cls.initial,
                         "c3-production-no-oled", IDF, cls.nvs)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def proof(self, **changes):
        source = (ROOT / ".pio/build/c3-production-no-oled/firmware.bin").read_bytes()
        return {"schema": 1, "nonce": "12" * 32, "mac": self.bundle["identity"]["mac"],
            "revision": 4, "flash_bytes": 4194304, "secure": 1,
            **{k: self.plan[k] for k in ("app_sha", "image_sha", "version_hex", "boot_digest", "table_sha")},
            "cipher": self.cipher[:128].hex(), "plain_sha": security.sha(source[:128]),
            "cycle": 1, "controls": 1, "targets": 2, "ready": 1, "internet": 1, "time": 1,
            "service": 1, "challenge": "34" * 32, "locked": 0, "weekly_date": 20261112,
            "config_tag": self.plan["configuration"]["tag"], **changes}

    def device(self, locked=1, **changes):
        rom = FakeRom()
        device = Mock()
        device.probe.side_effect = [self.proof(), self.proof(**changes)]
        device.lock.return_value = self.proof(locked=locked)
        @contextlib.contextmanager
        def connection(_):
            yield rom
        device.rom.side_effect = connection
        return device, rom

    def test_configuration_update_retains_schedule_and_never_targets_keys_or_bootloader(self):
        device, rom = self.device()
        result = update.execute(self.package, self.vault, IDF, device, timeout=1)
        self.assertTrue(result["nvs_targeted"])
        begins = [call[2] for call in rom.calls if call[0] == "begin"]
        self.assertEqual(begins, [0x20000, 0x10000])
        self.assertEqual(rom.memory[:0x10000], b"\xA5" * 0x10000)
        self.assertEqual(rom.memory[0x16000:0x20000], b"\xA5" * 0xA000)
        with security.transaction(self.work) as work:
            key = work / "key.bin"; key.write_bytes(security.raw(self.bundle, "nvs"))
            applied = work / "applied.bin"; applied.write_bytes(rom.memory[0x10000:0x16000])
            values = nvs.read_configuration(applied, key, work, IDF)
            self.assertEqual(values, self.config)
            plain = (work / "configuration.plain.bin").read_bytes()
            self.assertIn(b"WSD\x01" + (20261112).to_bytes(4, "little"), plain)

    def test_busy_or_wrong_applied_fingerprint_cannot_report_success(self):
        device, rom = self.device(locked=0)
        with self.assertRaisesRegex(update.UpdateError, "recovery"):
            update.execute(self.package, self.vault, IDF, device, timeout=1)
        device.rom.assert_not_called()
        self.assertEqual(rom.calls, [])
        device, _ = self.device(config_tag="00" * 32)
        with self.assertRaisesRegex(update.UpdateError, "different configuration"):
            update.execute(self.package, self.vault, IDF, device, timeout=1)

    def test_tampered_configuration_is_rejected_before_device_access(self):
        package = self.work / "tampered"
        shutil.copytree(self.package, package)
        data = bytearray((package / "configuration.encrypted.bin").read_bytes()); data[120] ^= 1
        (package / "configuration.encrypted.bin").write_bytes(data)
        device = Mock()
        with self.assertRaisesRegex(update.UpdateError, "hash mismatch"):
            update.execute(package, self.vault, IDF, device)
        device.probe.assert_not_called()

    def test_initial_package_roundtrip_and_bad_confirmation_before_hardware(self):
        with security.transaction(self.work) as work:
            _, segments, proof = provision.load_package(self.initial, self.bundle, self.backup, PASSWORD, work, IDF)
            self.assertEqual(set(segments), set(provision.LAYOUT))
            self.assertEqual(proof["config_tag"], nvs.configuration_tag(self.config, security.raw(self.bundle, "nvs")))
        factory = Mock()
        with self.assertRaisesRegex(update.UpdateError, "confirmation"):
            provision.execute(self.initial, self.vault, self.backup, PASSWORD, IDF, "COM999", "wrong", device_factory=factory)
        factory.assert_not_called()

    def test_pristine_rom_writer_erases_explicit_region_and_verifies_ciphertext_before_keys(self):
        with security.transaction(self.work) as work:
            _, segments, _ = provision.load_package(self.initial, self.bundle, self.backup, PASSWORD, work, IDF)
        mac = self.bundle["identity"]["mac"]
        class Rom(FakeRom):
            secure_download_mode = False
            corrupt = False
            def get_chip_revision(self): return 4
            def flash_id(self): return 0x164046
            def read_mac(self): return tuple(bytes.fromhex(mac))
            def read_flash(self, address, size):
                raise AssertionError("Use the ROM digest command for full segment verification")
            def flash_md5sum(self, address, size):
                data = bytes(self.memory[address:address + size])
                return hashlib.md5(bytes([data[0] ^ 1]) + data[1:] if self.corrupt else data).hexdigest()
        device = provision.ProvisionDevice("COM999", mac)
        device.esp = Rom()
        with contextlib.redirect_stdout(io.StringIO()):
            device.commands = virtual_commands()
        with patch.object(update, "usb_serial", return_value=mac):
            device.write(segments)
        begins = [call for call in device.esp.calls if call[0] == "begin"]
        self.assertEqual(begins[0], ("begin", 4194304, 0, False))
        for name, data in segments.items():
            address = provision.LAYOUT[name][0]
            self.assertEqual(device.esp.memory[address:address + len(data)], data)
        self.assertEqual(device.esp.memory[0x17000:0x20000], b"\xff" * 0x9000)
        device.esp.corrupt = True
        with patch.object(update, "usb_serial", return_value=mac):
            with self.assertRaisesRegex(update.UpdateError, "readback mismatch"):
                device.write(segments)
        self.assertEqual(device.commands.efuses["KEY_PURPOSE_0"].get(), "USER")
        self.assertEqual(int(device.commands.efuses["SECURE_BOOT_EN"].get_raw()), 0)

    def test_interrupted_initial_write_retains_receipt_and_cannot_be_retried(self):
        vault = self.work / "interrupted-attempt"
        security.save_vault(vault, self.bundle)
        class Interrupted:
            def __init__(self, *_): pass
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def write(self, _, checkpoint=None, progress=None): raise OSError("synthetic interrupted transport")
            def protect(self, *_): raise AssertionError("Protection must not begin")
        with self.assertRaises(OSError):
            provision.execute(self.initial, vault, self.backup, PASSWORD, IDF,
                "COM999", self.bundle["identity"]["mac"], device_factory=Interrupted)
        receipt = security.read_json(vault / "provision-receipt.json")
        self.assertEqual((receipt["phase"], receipt["result"]), ("flash", "incomplete"))
        self.assertEqual(receipt["error_type"], "OSError")
        self.assertNotIn("synthetic interrupted transport", json.dumps(receipt))
        with self.assertRaisesRegex(update.UpdateError, "already recorded"):
            provision.execute(self.initial, vault, self.backup, PASSWORD, IDF,
                "COM999", self.bundle["identity"]["mac"], device_factory=Interrupted)

    def test_initial_executor_records_verified_attempt_and_blocks_repetition(self):
        vault = self.work / "attempt"
        security.save_vault(vault, self.bundle)
        calls = []
        class Device:
            def __init__(self, port, mac): calls.append(("open", port, mac))
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def write(self, segments, checkpoint=None, progress=None): calls.append(("write", set(segments)))
            def protect(self, bundle, proof, checkpoint):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    provision.burn_security(virtual_commands(), bundle, proof["boot_digest"], checkpoint)
        with security.transaction(self.work) as work:
            _, _, expected = provision.load_package(self.initial, self.bundle, self.backup, PASSWORD, work, IDF)
        probe = {**expected, "ready": 1, "cycle": 1, "time": 1, "internet": 1}
        with patch.object(update, "UsbDevice") as usb:
            usb.return_value.probe.return_value = probe
            result = provision.execute(self.initial, vault, self.backup, PASSWORD, IDF,
                "COM999", self.bundle["identity"]["mac"], timeout=1, device_factory=Device)
        self.assertEqual(result["result"], "verified")
        self.assertEqual(security.read_json(vault / "provision-receipt.json")["result"], "verified")
        with self.assertRaisesRegex(update.UpdateError, "already recorded"):
            provision.execute(self.initial, vault, self.backup, PASSWORD, IDF,
                "COM999", self.bundle["identity"]["mac"], timeout=1, device_factory=Device)
        self.assertEqual(sum(call[0] == "open" for call in calls), 1)

    def test_official_secure_download_success_exit_is_caught_only_at_last_burn(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            commands = virtual_commands()
            original = commands.burn_efuse
            def burn(values):
                original(values)
                if values == {"ENABLE_SECURITY_DOWNLOAD": "1"}:
                    raise SystemExit(0)
            checkpoints = []
            with patch.object(commands, "burn_efuse", side_effect=burn):
                provision.burn_security(commands, self.bundle, self.plan["boot_digest"], checkpoints.append)
        self.assertEqual(checkpoints[-1], "secure-download")
        self.assertEqual(int(commands.efuses["ENABLE_SECURITY_DOWNLOAD"].get_raw()), 1)

    def verification_receipt(self, phase="secure-download"):
        vault = self.work / self._testMethodName
        security.save_vault(vault, self.bundle)
        plan = security.read_json(self.initial / "plan.json")
        receipt = vault / "provision-receipt.json"
        receipt.write_bytes(security.encoded({"schema": 1, "identity": self.bundle["identity"],
            "phase": phase, "result": "started", "package_sha256": security.sha(security.encoded(plan))}))
        security.seal_private_files([receipt])
        return vault, receipt

    def test_secure_download_does_not_hide_nonzero_or_earlier_tool_exit(self):
        for early in (False, True):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                commands = virtual_commands()
                original = commands.burn_efuse
                def burn(values):
                    if early and set(values) == set(provision.SECURITY_BITS):
                        raise SystemExit(0)
                    original(values)
                    if values == {"ENABLE_SECURITY_DOWNLOAD": "1"}:
                        raise SystemExit(1)
                with patch.object(commands, "burn_efuse", side_effect=burn):
                    with self.assertRaises(SystemExit if early else update.UpdateError):
                        provision.burn_security(commands, self.bundle, self.plan["boot_digest"], lambda _: None)

    def verification_device(self, rom):
        device = Mock()
        @contextlib.contextmanager
        def connection(mac):
            self.assertEqual(mac, self.bundle["identity"]["mac"])
            yield rom
        device.rom.side_effect = connection
        device.probe.return_value = self.proof()
        return device

    def test_resume_only_verifies_existing_rom_and_boot_without_flash_or_efuse_calls(self):
        vault, receipt = self.verification_receipt()
        original_keys = (vault / "owner.warpkeys").read_bytes()
        rom = FakeRom()
        rom.info["key_purposes"][6] = 12  # observed C3 reserved byte
        device = self.verification_device(rom)
        with patch.object(update, "UsbDevice", return_value=device), \
                patch.object(provision, "ProvisionDevice", side_effect=AssertionError("No provisioning")), \
                patch.object(security, "open_backup", side_effect=AssertionError("No backup password needed for proof")):
            result = provision.verify_existing(vault, IDF, "COM999", self.initial, timeout=1)
        self.assertEqual(result["result"], "verified")
        self.assertEqual(rom.calls, [("reset", True)])
        self.assertEqual(rom.memory, bytearray(b"\xA5" * 4194304))
        self.assertEqual((vault / "owner.warpkeys").read_bytes(), original_keys)
        record = security.read_json(receipt)
        self.assertEqual((record["result"], record["interrupted_phase"]), ("verified", "secure-download"))

    def test_resume_rejects_changed_rom_profile_before_reset_or_marking_success(self):
        vault, receipt = self.verification_receipt()
        rom = FakeRom(); rom.info["flags"] ^= 1 << 8
        with patch.object(update, "UsbDevice", return_value=self.verification_device(rom)):
            with self.assertRaises(update.UpdateError):
                provision.verify_existing(vault, IDF, "COM999", self.initial, timeout=1)
        self.assertEqual(rom.calls, [])
        self.assertNotEqual(security.read_json(receipt)["result"], "verified")

    def test_resume_rejects_a_different_package_before_opening_usb(self):
        vault, receipt = self.verification_receipt()
        record = security.read_json(receipt); record["package_sha256"] = "00" * 32
        receipt.write_bytes(security.encoded(record))
        with patch.object(update, "UsbDevice") as usb:
            with self.assertRaisesRegex(update.UpdateError, "differs"):
                provision.verify_existing(vault, IDF, "COM999", self.initial, timeout=1)
        usb.assert_not_called()

    def test_resume_rejects_an_interrupted_flash_before_opening_usb(self):
        vault, _ = self.verification_receipt("flash")
        with patch.object(update, "UsbDevice") as usb:
            with self.assertRaisesRegex(update.UpdateError, "cannot resume"):
                provision.verify_existing(vault, IDF, "COM999", self.initial, timeout=1)
        usb.assert_not_called()


if __name__ == "__main__":
    unittest.main()
