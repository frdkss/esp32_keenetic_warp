"""Offline checks for diagnostic operations that protect secrets and hardware."""

import contextlib
import io
import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import inspect_board
import inspect_router


class DiagnosticsTests(unittest.TestCase):
    def test_rcI_error_inside_successful_http_is_rejected(self):
        for value in ({"status": [{"status": "error", "message": "SECRET"}]},
                      [{"interface": {"status": "error"}}]):
            with self.assertRaisesRegex(ValueError, "inside HTTP 200") as error:
                inspect_router.parse_rci(200, json.dumps(value))
            self.assertNotIn("SECRET", str(error.exception))

    def test_rcI_requires_success_and_json(self):
        with self.assertRaises(ValueError):
            inspect_router.parse_rci(401, b"SECRET")
        with self.assertRaises(ValueError):
            inspect_router.parse_rci(200, b"not json")
        self.assertEqual(inspect_router.parse_rci(200, b'{"title":"5.1.8"}'), {"title": "5.1.8"})

    def test_credentials_preserve_separate_line_values_without_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret.txt"
            path.write_text('Login:\nexample\n\nPassword:\n  p\\a"ss:$\u0436  \n', encoding="utf-8-sig")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                login, password = inspect_router.read_credentials(path)
            self.assertEqual(login, "example")
            self.assertEqual(password, '  p\\a"ss:$\u0436  ')
            self.assertEqual(output.getvalue(), "")

    def test_tls_failure_sends_no_request_and_has_no_http_retry(self):
        router = inspect_router.Router("192.168.1.1", "example.invalid")
        with patch.object(inspect_router.LanHTTPSConnection, "connect", side_effect=ssl.SSLError("failed")), \
                patch.object(inspect_router.LanHTTPSConnection, "request") as request, \
                patch.object(inspect_router.http.client.HTTPConnection, "connect") as http_connect:
            with self.assertRaises(ssl.SSLError):
                router.request("POST", "/auth", {"password": "SECRET"})
            request.assert_not_called()
            http_connect.assert_not_called()
        self.assertTrue(router.context.check_hostname)
        self.assertEqual(router.context.verify_mode, ssl.CERT_REQUIRED)

    def test_board_commands_are_reads_and_exclude_key_contents(self):
        self.assertTrue(all(not field.startswith("BLOCK_KEY") for field in inspect_board.SECURITY_FIELDS))
        with patch.object(inspect_board.subprocess, "run") as run:
            run.return_value.returncode = 0
            inspect_board.run_read("esptool", "COM4", "get-security-info")
            command = run.call_args.args[0]
            self.assertIn("--no-stub", command)
            self.assertEqual(command[-1], "get-security-info")


if __name__ == "__main__":
    unittest.main()
