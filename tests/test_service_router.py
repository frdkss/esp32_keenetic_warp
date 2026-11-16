"""Read-only router discovery, verified TLS and the actual menu picker."""

import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_router
import service_events
import service_router


class RouterDiscoveryTests(unittest.TestCase):
    def tearDown(self):
        service_events.enable(False)

    def test_discovery_uses_public_redirect_without_credentials(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 302
        connection.getresponse.return_value.getheader.return_value = "https://unit.keenetic.pro:8443/"
        with patch.object(inspect_router.http.client, "HTTPConnection", return_value=connection) as factory:
            self.assertEqual(inspect_router.discover_name("192.0.2.1", 8443), "unit.keenetic.pro")
        factory.assert_called_once_with("192.0.2.1", timeout=5)
        connection.request.assert_called_once_with("GET", "/", headers={"Host": "my.keenetic.net"})
        connection.close.assert_called_once()

    def test_discovery_rejects_untrusted_redirect_shapes(self):
        for location in ("http://unit.keenetic.pro/", "https://login:secret@unit.keenetic.pro/",
                         "//unit.keenetic.pro/", "https://unit.keenetic.pro:999/", "/auth"):
            with self.subTest(location=location):
                connection = MagicMock()
                connection.getresponse.return_value.status = 302
                connection.getresponse.return_value.getheader.return_value = location
                with patch.object(inspect_router.http.client, "HTTPConnection", return_value=connection):
                    with self.assertRaises(ValueError):
                        inspect_router.discover_name("192.0.2.1")

    def test_tls_still_targets_saved_ip_and_port_with_hostname_validation(self):
        router = inspect_router.Router("192.0.2.1", "unit.keenetic.pro", port=8443)
        with patch.object(inspect_router.socket, "create_connection") as tcp, \
                patch.object(router.context, "wrap_socket") as wrap:
            connection = inspect_router.LanHTTPSConnection(router.name, router.address, router.context, router.port)
            connection.connect()
        tcp.assert_called_once_with(("192.0.2.1", 8443), 8)
        wrap.assert_called_once_with(tcp.return_value, server_hostname="unit.keenetic.pro")
        self.assertTrue(router.context.check_hostname)
        self.assertEqual(router.context.verify_mode, ssl.CERT_REQUIRED)

    def test_only_real_wireguard_ids_are_listed_in_numeric_order(self):
        response = {
            "Wireguard10": {"type": "Wireguard", "description": "VPN\x1b[2J\n\u202e", "state": "down"},
            "Wireguard2": {"id": "Wireguard2", "type": "Wireguard", "description": "WARP", "state": "up", "connected": "yes"},
            "Wireguard0": {"id": "Wireguard0", "type": "Wireguard"},
            "Wireguard1": {"id": "Wireguard5", "type": "Wireguard"},
            "Wireguard3": {"type": "Ethernet"},
            "Bridge0": {"type": "Wireguard"},
            "Wireguard4": "SECRET", "Wireguard5\n": {"type": "Wireguard"},
        }
        result = service_router.wireguard_interfaces(response)
        self.assertEqual([item["id"] for item in result], ["Wireguard0", "Wireguard2", "Wireguard10"])
        self.assertTrue(result[1]["enabled"] and result[1]["connected"])
        self.assertFalse(result[2]["enabled"])
        self.assertEqual(result[2]["description"], "VPN [2J")
        self.assertEqual(service_router.wireguard_interfaces({"Bridge0": {"type": "Ethernet"}}), [])

    def test_interface_listing_authenticates_and_reads_only_interfaces(self):
        request = {"address": "192.0.2.1", "port": 8443, "login": "SYNTHETIC", "password": "SECRET"}
        with patch.object(service_router, "discover_name", return_value="unit.keenetic.pro") as discover, \
                patch.object(service_router, "Router") as factory:
            router = factory.return_value
            router.read_json.return_value = {"Wireguard1": {"type": "Wireguard", "description": "WARP"}}
            result = service_router.discover(request, True)
        discover.assert_called_once_with("192.0.2.1", 8443)
        factory.assert_called_once_with("192.0.2.1", "unit.keenetic.pro", port=8443)
        router.login.assert_called_once_with("SYNTHETIC", "SECRET")
        router.read_json.assert_called_once_with("/rci/show/interface")
        self.assertEqual(result["https_name"], "unit.keenetic.pro")
        self.assertTrue(result["tls_verified"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_name_only_verifies_https_challenge_without_login(self):
        with patch.object(service_router, "discover_name", return_value="unit.keenetic.pro"), \
                patch.object(service_router, "Router") as factory:
            router = factory.return_value
            router.request.return_value = (401, {"X-NDM-Realm": "secret", "X-NDM-Challenge": "secret"}, b"")
            result = service_router.discover({"address": "192.0.2.1", "port": 443})
        router.login.assert_not_called()
        router.request.assert_called_once_with("GET", "/auth")
        self.assertEqual(result, {"https_name": "unit.keenetic.pro", "tls_verified": True})

    def test_tls_and_auth_errors_are_safe_and_never_return_success(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "request.json"
            path.write_text(json.dumps({"address": "192.0.2.1", "port": 443, "login": "SYNTHETIC", "password": "SECRET"}))
            for failure in (ssl.SSLCertVerificationError("SECRET certificate"), ValueError("SECRET password"),
                            OSError("SECRET socket"), http.client.HTTPException("SECRET body")):
                with self.subTest(failure=type(failure).__name__), \
                        patch.object(service_router, "discover_name", return_value="unit.keenetic.pro"), \
                        patch.object(service_router, "Router") as factory:
                    factory.return_value.login.side_effect = failure
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                        code = service_router.main(["--request", str(path), "--interfaces", "--events"])
                    self.assertEqual(code, 1)
                    self.assertNotIn("SECRET", output.getvalue())
                    events = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(events[-1]["event"], "error")
                    self.assertFalse(any(event["event"] == "result" for event in events))
                    factory.return_value.read_json.assert_not_called()

    def test_missing_credentials_or_invalid_endpoint_never_access_network(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "request.json"
            for request in ({"address": "192.0.2.1", "port": 443},
                            {"address": "https://router/", "port": 443},
                            {"address": "192.0.2.1", "port": True}):
                path.write_text(json.dumps(request))
                with patch.object(service_router, "discover_name") as discover, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(service_router.main(["--request", str(path), "--interfaces"]), 1)
                discover.assert_not_called()


@unittest.skipUnless(os.name == "nt" and (ROOT / ".local/service-tools/Scripts/python.exe").is_file(),
                     "Windows service tools required")
class RouterMenuTests(unittest.TestCase):
    def test_automatic_config_arrow_selection_cancellation_and_private_staging(self):
        with tempfile.TemporaryDirectory(prefix="warp-router-menu-") as work:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(ROOT / "tests/verify_router_menu.ps1"), "-WorkRoot", work],
                capture_output=True, timeout=30)
            output = result.stdout + result.stderr
            self.assertNotIn(b"SYNTHETIC", output)
            self.assertEqual(result.returncode, 0, output.decode(errors="replace"))
            self.assertIn(b"PASS router discovery/menu", output)


if __name__ == "__main__":
    unittest.main()
