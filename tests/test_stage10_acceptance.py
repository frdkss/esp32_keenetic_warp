"""Stage 10 acceptance: real application code/crypto, synthetic I/O and secrets.

TLS sockets bind only to loopback. No physical board or router is accessed.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from test_stage5_network import ROOT, compile_native, vcvars
from test_stage4_security import IDF, PASSWORD, SERVICE_PYTHON, evidence, security


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class RecoveryAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-stage10-monitor-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake/mbedtls"
        fake.mkdir(parents=True)
        for name, declaration in (("md5", "int mbedtls_md5(const unsigned char*, std::size_t, unsigned char*);"),
                                  ("sha256", "int mbedtls_sha256(const unsigned char*, std::size_t, unsigned char*, int);")):
            (fake / (name + ".h")).write_text("#pragma once\n#include <cstddef>\n" + declaration + "\n")
        cls.binary = compile_native(cls.work, "stage10_monitor",
            [ROOT / "tests/stage10_monitor_native.cpp"] + [ROOT / "src" / name for name in
                ("monitor.cpp", "scheduler.cpp", "network.cpp", "network_protocol.cpp", "keenetic.cpp",
                 "keenetic_settings.cpp", "keenetic_protocol.cpp")],
            includes=[fake.parent, ROOT / ".pio/libdeps/c3-test-no-oled/ArduinoJson/src"],
            flags=["/MDd", "/D_DEBUG"])

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def scenario(self, *args):
        result = subprocess.run([str(self.binary), *args], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_wifi_loss_at_every_recovery_phase(self):
        for phase in range(9):
            with self.subTest(phase=phase): self.scenario("wifi", str(phase))

    def test_time_loss_at_every_recovery_phase(self):
        for phase in range(9):
            with self.subTest(phase=phase): self.scenario("time", str(phase))

    def test_router_unreachable_at_every_recovery_phase(self):
        for phase in range(9):
            with self.subTest(phase=phase): self.scenario("lan", str(phase))

    def test_reboot_from_actual_journal_and_router_state_at_every_phase(self): self.scenario("reboot")

    def test_ninety_virtual_days_heap_reconnects_restart_and_flash_counters(self):
        output = self.scenario("soak")
        self.assertIn("virtual_minutes=131040", output)
        self.assertIn("live_heap_delta=0", output)
        # Only aggregate metrics are saved, without synthetic auth requests.
        folder = ROOT / ".local/stage10"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "simulation.log").write_text(output)


@unittest.skipUnless(os.name == "nt" and security and IDF.is_dir() and shutil.which("cmake"),
                     "Pinned SDK, security tools, MSVC and CMake required")
class CertificateAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-stage10-tls-")
        cls.work = Path(cls.temporary.name)
        build = ROOT / ".local/stage10/tls-build"
        build.mkdir(parents=True, exist_ok=True)
        cmake = shutil.which("cmake")
        commands = [[cmake, "-S", str(ROOT / "tests/stage10_tls"), "-B", str(build),
                     "-G", "NMake Makefiles", "-DCMAKE_BUILD_TYPE=Release",
                     "-DWARP_MBEDTLS=" + str(IDF / "components/mbedtls/mbedtls")],
                    [cmake, "--build", str(build), "--target", "stage10_tls"]]
        command = cls.work / "build.cmd"
        command.write_text('@echo off\ncall "' + str(vcvars()) + '" >nul\n' +
            "\n".join(subprocess.list2cmdline(c) + "\nif errorlevel 1 exit /b 1" for c in commands) + "\n")
        result = subprocess.run(["cmd.exe", "/d", "/c", str(command)], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=240)
        (build.parent / "tls-build.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode: raise AssertionError((result.stdout + result.stderr)[-8000:])
        cls.binary = build / "stage10_tls.exe"
        cls.certificates()

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    @classmethod
    def certificates(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        now = datetime.now(timezone.utc)
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Stage10 synthetic CA")])
        cls.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(cls.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(cls.ca_key, hashes.SHA256()))
        cls.ca_path = cls.work / "ca.pem"
        cls.ca_path.write_bytes(cls.ca.public_bytes(serialization.Encoding.PEM))
        for variant in ("valid", "name", "untrusted", "expired", "future", "tampered"):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            host = "substituted.stage10.invalid" if variant == "name" else "router.stage10.invalid"
            signer = rsa.generate_private_key(public_exponent=65537, key_size=2048) if variant == "untrusted" else cls.ca_key
            start = now + timedelta(days=2) if variant == "future" else now - timedelta(days=2)
            end = now - timedelta(days=1) if variant == "expired" else now + timedelta(days=3)
            cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(cls.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(signer, hashes.SHA256()))
            if variant == "tampered":
                data = bytearray(cert.public_bytes(serialization.Encoding.DER))
                data[-1] ^= 1  # Keep the leaf key valid, break the CA signature.
                cert = x509.load_der_x509_certificate(bytes(data))
            (cls.work / (variant + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (cls.work / (variant + ".key")).write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def certificate(self, variant, flags):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.num_tickets = 0
        context.load_cert_chain(self.work / (variant + ".pem"), self.work / (variant + ".key"))
        received, failures = [], []
        names = []
        context.set_servername_callback(lambda sock, name, ctx: names.append(name))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(10)
            port = listener.getsockname()[1]
            def serve():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(10)
                        with context.wrap_socket(raw, server_side=True) as secured:
                            received.append(secured.recv(512))
                            secured.sendall(b"!")
                except (ssl.SSLError, ConnectionError):
                    if not flags: failures.append("Unexpected server TLS error")
                except Exception as error: failures.append(type(error).__name__)
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            result = subprocess.run([str(self.binary), str(self.ca_path), str(port), str(flags)],
                                    capture_output=True, text=True, timeout=15)
            worker.join(12)
            self.assertFalse(worker.is_alive(), "Loopback TLS server did not finish")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(failures, [])
            self.assertEqual(received, [] if flags else [b"STAGE10-APPLICATION-DATA"])
            self.assertEqual(names, ["router.stage10.invalid"])
            self.assertIn("mbedtls=3.6.6", result.stdout)

    def test_valid_chain_name_and_dates_allow_application_data(self): self.certificate("valid", 0)
    def test_substituted_hostname_rejected_before_application_data(self): self.certificate("name", 4)
    def test_untrusted_signer_rejected_before_application_data(self): self.certificate("untrusted", 8)
    def test_expired_certificate_rejected_before_application_data(self): self.certificate("expired", 1)
    def test_future_certificate_rejected_before_application_data(self): self.certificate("future", 512)
    def test_corrupted_signature_rejected_before_application_data(self): self.certificate("tampered", 8)


@unittest.skipUnless(security and os.name == "nt" and SERVICE_PYTHON.is_file() and IDF.is_dir(),
                     "Windows with pinned security tools required")
class BackupAcceptanceTests(unittest.TestCase):
    def test_backup_only_restore_in_separate_workspace_and_process_prepares_valid_update(self):
        import secure_update as update
        with tempfile.TemporaryDirectory(prefix="warp-stage10-recovery-") as folder:
            work = Path(folder)
            vault = work / "source-vault"
            security.new_vault(vault, evidence())
            bundle = security.load_vault(vault)
            backup = work / "portable.warpbackup"
            security.backup_vault(vault, backup, PASSWORD)
            # Original DPAPI files are unavailable to the restored workspace.
            self.assertEqual(vault.resolve().parent, work.resolve())
            self.assertEqual(vault.name, "source-vault")
            shutil.rmtree(vault)
            project = work / "second-workspace"
            (project / "scripts").mkdir(parents=True)
            for name in ("security_store.py", "secure_update.py", "service_nvs.py", "service_events.py"):
                shutil.copyfile(ROOT / "scripts" / name, project / "scripts" / name)
            env = "c3-production-no-oled"
            shutil.copyfile(ROOT / ("sdkconfig." + env), project / ("sdkconfig." + env))
            build = project / ".pio/build" / env
            (build / "config").mkdir(parents=True)
            for name in ("firmware.bin", "partitions.bin", "config/sdkconfig.json"):
                shutil.copyfile(ROOT / ".pio/build" / env / name, build / name)
            restored = work / "restored-vault"
            with security.transaction(work) as private:
                request = private / "passphrase.json"
                request.write_bytes(security.encoded({"passphrase": PASSWORD}))
                result = subprocess.run([str(SERVICE_PYTHON), str(project / "scripts/security_store.py"),
                    "restore", "--idf-path", str(IDF), "--vault", str(restored),
                    "--backup", str(backup), "--request", str(request)], cwd=project,
                    capture_output=True, timeout=60)
                self.assertNotIn(PASSWORD.encode(), result.stdout + result.stderr)
                self.assertEqual(result.returncode, 0, "Isolated backup restore failed")
            package = work / "restored-update"
            result = subprocess.run([str(SERVICE_PYTHON), str(project / "scripts/secure_update.py"),
                "prepare", "--idf-path", str(IDF), "--vault", str(restored), "--package", str(package)],
                cwd=project, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, "Update with backup-only restored keys failed")
            self.assertEqual(security.load_vault(restored), bundle)
            with security.transaction(work) as private:
                plan, cipher = update.load_package(package, bundle, private)
                self.assertEqual(plan["unsigned_sha256"], security.sha((build / "firmware.bin").read_bytes()))
                self.assertEqual(len(cipher), plan["size"])
            for artifact in package.iterdir():
                data = artifact.read_bytes()
                for kind in ("flash", "nvs", "signing"):
                    self.assertNotIn(security.raw(bundle, kind), data)
                    self.assertNotIn(bundle["keys"][kind].encode(), data)
                self.assertNotIn(security.raw(bundle, "nvs")[:64], data)
                self.assertNotIn(PASSWORD.encode(), data)
                self.assertNotIn(b"PRIVATE KEY", data)


class ArtifactScannerTests(unittest.TestCase):
    def test_scanner_detects_ascii_and_utf16_without_disclosing_value(self):
        from verify_stage10_artifacts import scan
        secret = b"SYNTHETIC-stage10-secret-detector-test"
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "artifact.bin"
            for data in (secret, secret.decode().encode("utf-16le")):
                artifact.write_bytes(b"prefix" + data + b"suffix")
                with self.assertRaises(ValueError) as result: scan(artifact, [secret])
                self.assertNotIn(secret.decode(), str(result.exception))


if __name__ == "__main__": unittest.main()
