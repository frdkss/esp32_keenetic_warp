"""Run production C++ Keenetic protocol/client with scripted HTTPS, synthetic secrets,
and native Windows CNG MD5/SHA-256. No router or board is accessed.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_stage5_network import ROOT, compile_native


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class KeeneticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-keenetic-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake/mbedtls"
        fake.mkdir(parents=True)
        (fake / "md5.h").write_text('#pragma once\n#include <cstddef>\nint mbedtls_md5(const unsigned char*, std::size_t, unsigned char*);\n')
        (fake / "sha256.h").write_text('#pragma once\n#include <cstddef>\nint mbedtls_sha256(const unsigned char*, std::size_t, unsigned char*, int);\n')
        cls.binary = compile_native(cls.work, "keenetic",
            [ROOT / "tests/keenetic_native.cpp", ROOT / "src/keenetic.cpp", ROOT / "src/keenetic_protocol.cpp",
             ROOT / "src/keenetic_settings.cpp", ROOT / "src/network.cpp", ROOT / "src/network_protocol.cpp"],
            includes=[fake.parent, ROOT / ".pio/libdeps/c3-test-no-oled/ArduinoJson/src"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name, *args):
        result = subprocess.run([str(self.binary), name, *args], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_md5_sha256_challenge_vectors_and_json_escaping(self):
        login, password, realm, challenge = 'test"\\login', 'synthetic:password', 'test:realm', 'SYNTHETIC_CHALLENGE'
        digest = hashlib.md5(f'{login}:{realm}:{password}'.encode()).hexdigest()
        proof = hashlib.sha256((challenge + digest).encode()).hexdigest()
        self.scenario("proof", proof)

    def test_only_configured_https_ip_name_and_wireguard_interface(self): self.scenario("settings")
    def test_bounded_http_framing_headers_chunked_and_cookies(self): self.scenario("http")
    def test_bad_http_truncation_oversize_and_ambiguous_headers(self): self.scenario("http_bad")
    def test_long_www_authenticate_parameters_do_not_break_login(self): self.scenario("long_authenticate")
    def test_rci_schema_identity_errors_and_full_json_consumption(self): self.scenario("schema")
    def test_login_state_read_and_ram_cookie_reuse(self): self.scenario("read")
    def test_disable_enable_preflight_ack_and_state_verification(self): self.scenario("change")
    def test_expired_session_reauthorizes_once(self): self.scenario("expiry")
    def test_invalid_password_and_certificate_latch_commands(self): self.scenario("auth_tls")
    def test_permissions_wrong_interface_unknown_profile_and_rci_error(self): self.scenario("blocked")
    def test_post_state_mismatch_blocks_further_commands(self): self.scenario("mismatch")
    def test_wifi_and_time_loss_cancel_requests_and_forget_session(self): self.scenario("loss")
    def test_request_timeout_across_millis_wrap_and_busy(self): self.scenario("timeout")
    def test_no_mutation_retry_after_uncertain_transport_failure(self): self.scenario("uncertain")


if __name__ == "__main__":
    unittest.main()
