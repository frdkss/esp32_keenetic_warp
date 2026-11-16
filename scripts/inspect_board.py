"""Read ESP32-C3 identity and selected security flags; never write flash/eFuses.

Install diagnostics-requirements.txt into the Python environment first.
Opening the ROM connection resets the board. Evidence stays in ignored .local/.
"""

import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SECURITY_FIELDS = (
    "WR_DIS", "RD_DIS", "SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT",
    "DIS_DOWNLOAD_MANUAL_ENCRYPT", "DIS_DOWNLOAD_ICACHE",
    "DIS_USB_JTAG", "DIS_PAD_JTAG", "SOFT_DIS_JTAG",
    "DIS_USB_SERIAL_JTAG", "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
    "DIS_DOWNLOAD_MODE", "ENABLE_SECURITY_DOWNLOAD",
    "SECURE_BOOT_KEY_REVOKE0", "SECURE_BOOT_KEY_REVOKE1",
    "SECURE_BOOT_KEY_REVOKE2", "SECURE_BOOT_AGGRESSIVE_REVOKE",
    *(f"KEY_PURPOSE_{i}" for i in range(6)),
)


def run_read(module, port, *arguments):
    # Arguments are fixed at the call sites; no caller-supplied tool commands.
    command = [sys.executable, "-m", module, "--chip", "esp32c3",
               "--port", port]
    if module == "esptool":
        command.append("--no-stub")
    result = subprocess.run(command + list(arguments), capture_output=True,
                            text=True, encoding="utf-8", errors="replace",
                            timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(f"{module} read failed: {result.stdout}{result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    args = parser.parse_args()
    if importlib.metadata.version("esptool") != "5.1.0":
        parser.error("Use the pinned diagnostics-requirements.txt environment")
    folder = ROOT / ".local" / "stage1" / datetime.now(timezone.utc).strftime("board-%Y%m%dT%H%M%S%fZ")
    folder.mkdir(parents=True)
    # Do not request BLOCK_KEY* contents, even if the chip allows reading them.
    # espefuse 5.1's chained parser requires variadic fields before options.
    run_read("espefuse", args.port, "summary", *SECURITY_FIELDS,
             "--format", "json", "--file", str(folder / "security-efuses.json"))
    for name, command in (("security-info", "get-security-info"),
                          ("flash-id", "flash-id")):
        (folder / f"{name}.txt").write_text(
            run_read("esptool", args.port, command), encoding="utf-8")
    efuses = json.loads((folder / "security-efuses.json").read_text(encoding="utf-8"))
    # Assert that the pinned tool saved exactly the requested flags.
    if set(efuses) != set(SECURITY_FIELDS):
        raise ValueError("Unexpected fields in eFuse evidence")
    filtered = {key: efuses[key] for key in SECURITY_FIELDS}
    (folder / "security-efuses.json").write_text(
        json.dumps(filtered, indent=2) + "\n", encoding="utf-8")
    print(f"Read-only board evidence: {folder}")
    print(json.dumps({key: filtered[key]["value"] for key in SECURITY_FIELDS}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired, KeyError, ValueError) as error:
        print(f"Inspection failed: {error}", file=sys.stderr)
        sys.exit(1)
