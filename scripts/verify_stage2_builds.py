"""Inspect the four completed builds without connecting to hardware."""
import json
import configparser
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = (
    "c3-test-no-oled", "c3-test-oled",
    "c3-production-no-oled", "c3-production-oled",
)


def verify(environment):
    protected = "production" in environment
    oled = not environment.endswith("no-oled")
    build = ROOT / ".pio/build" / environment
    sdk = (ROOT / f"sdkconfig.{environment}").read_text(encoding="utf-8")
    for name in ("SECURE_BOOT", "SECURE_BOOT_V2_ENABLED", "SECURE_FLASH_ENC_ENABLED",
                 "SECURE_FLASH_ENCRYPTION_MODE_RELEASE", "NVS_ENCRYPTION"):
        assert (f"CONFIG_{name}=y" in sdk) == protected, f"{environment}: wrong {name}"
    assert "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y" not in sdk
    assert "CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT=y" not in sdk
    if protected:
        assert "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y" in sdk
    assert "config_partition_table_offset=0xf000" in sdk.lower()
    assert "CONFIG_MBEDTLS_PSK_MODES=y" in sdk
    assert "CONFIG_MBEDTLS_KEY_EXCHANGE_PSK=y" in sdk

    commands = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
    project_commands = [item for item in commands
                        if Path(item["file"]).resolve().parent == ROOT / "src"
                        and item["file"].endswith(".cpp")]
    assert len(project_commands) == len(list((ROOT / "src").glob("*.cpp"))), f"{environment}: missing project translation units"
    assert "CONFIG_MBEDTLS_HAVE_TIME_DATE=y" in sdk
    assert "CONFIG_AUTOSTART_ARDUINO=y" not in sdk
    assert "CONFIG_ESP_TLS_INSECURE=y" not in sdk
    assert "CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y" not in sdk
    project = configparser.ConfigParser()
    project.read(ROOT / "platformio.ini", encoding="utf-8")
    removed_flags = set(project["env"]["build_unflags"].split())
    for item in project_commands:
        standards = re.findall(r"-std=([^\s\"]+)", item["command"])
        # CMake's database precedes PlatformIO's build_unflags filtering.
        # build_contract.cpp additionally asserts the actual __cplusplus value.
        standards = [standard for standard in standards if f"-std={standard}" not in removed_flags]
        assert standards and standards[-1] == "gnu++17", f"C++17 missing: {item['file']}"

    library_dir = ROOT / ".pio/libdeps" / environment
    u8g2 = list(library_dir.glob("U8g2*/library.properties"))
    assert bool(u8g2) == oled, f"{environment}: incorrect U8g2 dependency"
    for manifest in u8g2:
        assert "version=2.36.17" in manifest.read_text().splitlines()

    # A nominally successful skeleton link must not hide an omitted TLS client.
    tls_objects = list(build.rglob("ssl_client.cpp.o"))
    assert len(tls_objects) == 1, f"{environment}: TLS client object missing"
    assert b"start_ssl_client" in tls_objects[0].read_bytes(), "TLS implementation was compiled out"

    firmware = (build / "firmware.bin").read_bytes()
    # The protected updater needs this read-only app protocol before ROM reset;
    # test firmware must not expose an owner-key authentication endpoint.
    assert (b"WARP9 " in firmware) == protected, f"{environment}: incorrect USB probe boundary"
    bootloader = (build / "bootloader.bin").read_bytes()
    partition_data = (build / "partitions.bin").read_bytes()
    partitions = {}
    for offset in range(0, len(partition_data), 32):
        magic, _, _, address, size, name, flags = struct.unpack_from("<HBBII16sI", partition_data, offset)
        if magic != 0x50AA:  # End marker or MD5 record.
            break
        partitions[name.split(b"\0", 1)[0].decode("ascii")] = (address, size, flags)
    assert partitions["nvs"] == (0x10000, 0x6000, 0)
    assert partitions["nvs_keys"] == (0x16000, 0x1000, 1)
    assert partitions["otadata"] == (0x18000, 0x2000, 0)
    assert partitions["ota_0"] == (0x20000, 0x1E0000, 0)
    assert partitions["ota_1"] == (0x200000, 0x1E0000, 0)
    assert partitions["wifi_tls"] == (0x3E0000, 0x1000, 0)
    assert len(firmware) <= 0x1E0000
    assert len(bootloader) <= 0xF000
    if protected:
        assert ((len(bootloader) + 4095) // 4096 + 1) * 4096 <= 0xF000, "No room for boot signature"
        assert ((len(firmware) + 4095) // 4096 + 1) * 4096 <= 0x1E0000, "No room for app signature"
        for marker in (b"TEST_ONLY_NO_WIFI", b"TEST_ONLY_WIFI_PASSWORD",
                       b"TEST_ONLY_ROUTER_LOGIN", b"TEST_ONLY_ROUTER_PASSWORD"):
            assert marker not in firmware, "Test credentials found in protected image"
    return {"environment": environment, "firmware_bytes": len(firmware),
            "bootloader_bytes": len(bootloader), "cpp17_units": len(project_commands),
            "u8g2": oled, "protected": protected, "tls_client_compiled": True,
            "usb_probe_compiled": protected}


if __name__ == "__main__":
    print(json.dumps([verify(environment) for environment in ENVIRONMENTS], indent=2))
