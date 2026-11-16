"""Local dependency probe: no installs, network or device access."""
import argparse
import importlib
import importlib.metadata
import json
import configparser
from pathlib import Path
import sys


def check(kind, root, pio_root):
    if not (3, 10) <= sys.version_info[:2] < (3, 14):
        return False
    versions = ({"platformio": "6.1.19"} if kind == "build" else {
        "esp-idf-nvs-partition-gen": "0.1.9", "cryptography": "44.0.3",
        "esptool": "5.1.0", "bitstring": "4.3.1", "pyserial": "3.5"})
    for name, version in versions.items():
        if importlib.metadata.version(name) != version:
            return False
    for module in (("platformio",) if kind == "build" else
                   ("esp_idf_nvs_partition_gen.nvs_partition_gen", "cryptography", "esptool", "espefuse", "serial")):
        importlib.import_module(module)
    if kind == "service":
        from service_nvs import check_tools
        check_tools(pio_root / "packages/framework-espidf")
        return True
    for name in ("framework-espidf", "framework-arduinoespressif32", "toolchain-riscv32-esp", "tool-cmake", "tool-ninja"):
        if not (pio_root / "packages" / name / "package.json").is_file():
            return False
    for filename in ("toolchain-riscv32-esp/bin/riscv32-esp-elf-g++.exe", "tool-cmake/bin/cmake.exe", "tool-ninja/ninja.exe"):
        if not (pio_root / "packages" / filename).is_file():
            return False
    ini = configparser.ConfigParser(interpolation=None)
    ini.read(root / "platformio.ini", encoding="utf-8")
    for package in ini["env"]["platform_packages"].split():
        name, version = package.split("@", 1)
        manifest = pio_root / "packages" / name.split("/")[-1] / "package.json"
        if json.loads(manifest.read_text()).get("version") != version:
            return False
    manifests = list((pio_root / "platforms").glob("*/platform.json"))
    if not any(json.loads(p.read_text()).get("version") == "8.0.0" and
               json.loads(p.read_text()).get("name") == "espressif32" for p in manifests):
        return False
    for environment in ("c3-test-no-oled", "c3-test-oled", "c3-production-no-oled", "c3-production-oled"):
        libraries = root / ".pio/libdeps" / environment
        if not (libraries / "ArduinoJson/library.json").is_file():
            return False
        if json.loads((libraries / "ArduinoJson/library.json").read_text())["version"] != "7.4.2":
            return False
        if not (libraries / "ArduinoJson/src/ArduinoJson.h").is_file():
            return False
        if not environment.endswith("no-oled"):
            properties = (libraries / "U8g2/library.properties").read_text()
            if "version=2.36.17" not in properties.splitlines():
                return False
            if not (libraries / "U8g2/src/U8g2lib.h").is_file():
                return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("build", "service"), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--pio-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        sys.exit(0 if check(args.kind, args.root, args.pio_root) else 1)
    except Exception:
        sys.exit(1)
