"""Read-only pre-provision inspection. Never prints key blocks or writes a device."""
import argparse
import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys

from security_store import FIELDS, PROFILE, encoded, plain_path, preflight


def inspect(port):
    import esptool
    import espefuse
    import importlib.metadata
    from serial.tools import list_ports

    if (importlib.metadata.version("esptool") != "5.1.0"
            or importlib.metadata.version("bitstring") != "4.3.1"):
        raise ValueError("Pinned diagnostics tools required")
    ports = [entry for entry in list_ports.comports() if entry.device.lower() == port.lower()]
    if len(ports) != 1 or (ports[0].vid, ports[0].pid) != (0x303A, 0x1001):
        raise ValueError("Native ESP32-C3 USB serial port required")
    esp = None
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            esp = esptool.cmds.detect_chip(port, baud=115200, connect_attempts=3)
            if esp.CHIP_NAME != "ESP32-C3" or esp.secure_download_mode:
                raise ValueError("Pristine ESP32-C3 required; secure mode cannot supply full evidence")
            esptool.cmds.attach_flash(esp)
            flash_id = esp.flash_id()
            fields = espefuse.init_commands(esp=esp).efuses
            values = {name: fields[name].get() if name.startswith("KEY_PURPOSE_")
                      else int(fields[name].get_raw()) for name in FIELDS}
            empty = {}
            for index in (0, 1):
                block = fields.blocks[4 + index]
                # Only retain an empty/nonempty result, never the key-block bytes.
                empty[block.name] = block.is_readable() and block.get_raw() == bytes(32)
            evidence = {"schema": 1, "profile": PROFILE,
                        "observed_utc": datetime.now(timezone.utc).isoformat(),
                        "identity": {"chip": "esp32c3", "revision": esp.get_chip_revision(),
                                     "flash_bytes": 1 << ((flash_id >> 16) & 0xFF),
                                     "mac": bytes(esp.read_mac()).hex(),
                                     "usb_vid": ports[0].vid, "usb_pid": ports[0].pid},
                        "efuses": values, "key_blocks_empty": empty}
            # Still save unsupported/dirty states for diagnosis; preflight will reject.
            try:
                preflight(evidence)
                evidence["preflight"] = "passed"
            except ValueError:
                evidence["preflight"] = "blocked"
            return evidence
    finally:
        if esp is not None:
            # No reset into a possibly protective bootloader after inspection.
            esp._port.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = plain_path(args.output)
    if output.exists():
        raise ValueError("Evidence will not be overwritten")
    evidence = inspect(args.port)
    with output.open("xb") as stream:
        stream.write(encoded(evidence))
    print(json.dumps({"identity": evidence["identity"], "preflight": evidence["preflight"]}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Read-only security inspection failed. Check pinned tools, port and supported board.", file=sys.stderr)
        sys.exit(1)
