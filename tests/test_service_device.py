"""Synthetic serial failures; never opens a real port or writes a device."""
import contextlib
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import serial
import secure_update as update
import service_device as device_service
import secure_provision as provision


class SerialProbeTests(unittest.TestCase):
    def test_write_timeout_is_no_application_response_and_closes_port(self):
        port = MagicMock()
        port.__enter__.return_value = port
        port.write.side_effect = serial.SerialTimeoutException("SYNTHETIC-private-diagnostic")
        with patch("serial.Serial", return_value=port), patch.object(update, "usb_serial"):
            with self.assertRaises(update.ProbeUnavailableError) as result:
                update.UsbDevice("COM999").probe({"identity": {"mac": "020000000001"}}, {}, Path("."), 1)
        self.assertNotIn("SYNTHETIC", str(result.exception))
        port.__exit__.assert_called_once()

    def test_busy_or_disconnected_port_is_actionable_and_not_an_initial_candidate(self):
        port = MagicMock()
        port.__enter__.side_effect = serial.SerialException("SYNTHETIC-private-diagnostic")
        with patch("serial.Serial", return_value=port), patch.object(update, "usb_serial"):
            with self.assertRaises(update.UpdateError) as result:
                update.UsbDevice("COM999").probe({"identity": {"mac": "020000000001"}}, {}, Path("."), 1)
        self.assertNotIsInstance(result.exception, update.ProbeUnavailableError)
        self.assertIn("COM port", str(result.exception))
        self.assertNotIn("SYNTHETIC", str(result.exception))


class ClassificationTests(unittest.TestCase):
    def test_initial_failure_reports_stage_and_type_without_exception_values(self):
        with patch.object(provision, "main", side_effect=OSError("SYNTHETIC-private-value")), \
                patch.object(provision, "_stage", "flash-write-bootloader"), \
                patch.object(provision.events, "error") as output:
            self.assertEqual(provision.cli(), 1)
        message = output.call_args.args[0]
        self.assertIn(provision.phase_label("flash-write-bootloader"), message)
        self.assertIn("OSError", message)
        self.assertNotIn("SYNTHETIC", message)

    def probe(self, failure=None):
        @contextlib.contextmanager
        def transaction(_):
            yield Path(".")
        with patch.object(update, "load_owner", return_value={}), \
                patch.object(device_service.store, "check_security_tools"), \
                patch.object(device_service.store, "transaction", side_effect=transaction), \
                patch.object(update, "load_package", return_value=({}, b"")), \
                patch.object(update, "UsbDevice") as device:
            if failure is not None:
                device.return_value.probe.side_effect = failure
            else:
                device.return_value.probe.return_value = {"service": 1}
            return device_service.probe_application("unused-package", "unused-vault", "COM999", "unused-idf")

    def test_no_reply_allows_read_only_initial_classification(self):
        self.assertEqual(self.probe(update.ProbeUnavailableError("no reply")),
            {"running": False, "reason": "no-application-response"})

    def test_invalid_authentication_cannot_be_downgraded_to_initial_preparation(self):
        with self.assertRaisesRegex(update.UpdateError, "authentication"):
            self.probe(update.UpdateError("authentication mismatch"))

    def test_running_application_is_detected(self):
        self.assertEqual(self.probe(), {"running": True, "service": 1})

    def test_unexpected_failure_reports_stage_without_sensitive_exception_text(self):
        with patch.object(device_service, "main", side_effect=ValueError("SYNTHETIC-private-value")), \
                patch.object(device_service, "_stage", "signed firmware package validation"), \
                patch.object(device_service.events, "error") as output:
            self.assertEqual(device_service.cli(), 1)
        message = output.call_args.args[0]
        self.assertIn("signed firmware package validation", message)
        self.assertIn("ValueError", message)
        self.assertNotIn("SYNTHETIC", message)


if __name__ == "__main__":
    unittest.main()
