"""Build with synthetic provisioning canaries present, scan explicit release files.

Does not read owner credentials/keys, open serial ports, upload or write eFuses.
Refuses to replace any existing provisioning header. Logs never contain canaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from verify_stage2_builds import ENVIRONMENTS, ROOT, verify


def scan(path, sentinels):
    data = Path(path).read_bytes()
    for sentinel in sentinels:
        if sentinel in data or sentinel.decode().encode("utf-16le") in data:
            # Do not include even the matched value or a data excerpt in errors.
            raise ValueError("Synthetic provisioning secret found in a release artifact")
    return {"file": Path(path).relative_to(ROOT).as_posix(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def run(platformio):
    folder = ROOT / ".local/stage10"
    folder.mkdir(parents=True, exist_ok=True)
    # Random per-run values cannot accidentally match pre-existing dummy strings.
    sentinels = [("WARP10_" + kind + "_" + secrets.token_hex(16)).encode()
                 for kind in ("SSID", "WIFI", "LOGIN", "PASSWORD")]
    header = ROOT / "include/service_secrets.h"
    if header.exists() or header.is_symlink():
        raise ValueError("Existing provisioning header must be preserved; canary build refused")
    source = ROOT / "src/runtime_config.cpp"
    original_stat = source.stat()
    created = False
    try:
        # Any accidental include must fail, even when unused literals get optimized out.
        with header.open("xb") as stream:
            created = True
            stream.write(b'#error Stage10 provisioning input must not be compiled\n' +
                         b"\n".join(b'constexpr char canary_' + str(i).encode() + b'[] = "' + value + b'";'
                                    for i, value in enumerate(sentinels)) + b"\n")
        os.utime(source, None)  # Force the credential-loading unit through the compiler.
        command = [str(platformio), "run"]
        for environment in ENVIRONMENTS: command += ["-e", environment]
        with (folder / "all-builds.log").open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise ValueError("Canary builds failed; see local stage10 build log")
        builds = [verify(env) for env in ENVIRONMENTS]
        artifacts = []
        for environment in ENVIRONMENTS:
            for name in ("firmware.bin", "firmware.elf", "esp32_keenetic_warp.map", "bootloader.bin", "partitions.bin"):
                artifacts.append(scan(ROOT / ".pio/build" / environment / name, sentinels))
        report = {"schema": 1, "synthetic_canaries": 4, "secret_matches": 0,
                  "builds": builds, "artifacts": artifacts,
                  "scope": "Explicit binary/ELF/map artifacts; local provisioning inputs are excluded from distribution"}
        (folder / "artifacts.json").write_text(json.dumps(report, indent=2) + "\n")
        return {"environments": len(builds), "artifacts": len(artifacts), "secret_matches": 0}
    finally:
        if created: header.unlink()
        os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platformio", type=Path, default=Path.home() / ".platformio/penv/Scripts/platformio.exe")
    args = parser.parse_args()
    print(json.dumps(run(args.platformio)))


if __name__ == "__main__":
    try: main()
    except Exception:
        print("Stage10 artifact verification failed. No secret values are printed.", file=sys.stderr)
        sys.exit(1)
