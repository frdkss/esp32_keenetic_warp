"""Offline adapter for ESP-IDF 5.5.5 NVS tools. No serial/network/device operations.

Secrets enter through a private request file, never command-line arguments.
The request/CSV live in PowerShell's private transaction directory and are removed
in its finally block. The official tool owns the NVS format and XTS encryption.
"""
import argparse
import contextlib
import csv
import importlib.metadata
import hmac
import io
import json
from pathlib import Path
import secrets
import struct
import sys
import zlib


# NVS schema 2 adds the target failure policy. Readers also accept schema 1.
STRINGS = {
    "WifiSsid": "wifi_ssid", "WifiPassword": "wifi_pass",
    "RouterLogin": "router_login", "RouterPassword": "router_pass",
    "RouterAddress": "router_addr", "RouterHttpsName": "router_tls",
    "WarpInterface": "warp_iface", "Timezone": "timezone", "ScheduleTime": "schedule_time",
}
INTEGERS = {
    "RouterPort": "router_port", "ScheduleDay": "schedule_day",
    "FailureThreshold": "fail_threshold", "CheckIntervalSeconds": "check_secs",
    "ConnectTimeoutSeconds": "connect_secs", "ReadTimeoutSeconds": "read_secs",
    "DisablePauseSeconds": "disable_secs", "WarmupSeconds": "warmup_secs",
    "CooldownSeconds": "cooldown_secs", "EnableAutoRecovery": "autorecovery",
    "EnableWeeklyRestart": "weekly_restart", "OledEnabled": "oled_enabled",
    "TargetFailurePolicy": "target_policy",
}
LISTS = {"TargetUrls": "target_urls", "ControlUrls": "control_urls"}

def configuration_tag(configuration, key):
    """Length-prefixed UTF-8, LE u32, URL counts/items; shared with config_tag.cpp."""
    configuration = dict(configuration)
    configuration.setdefault("TargetFailurePolicy", 2)
    tag = hmac.new(key[:64], b"WARP-CFG-2\0", "sha256")
    def text(value):
        data = value.encode("utf-8")
        tag.update(struct.pack("<I", len(data)))
        tag.update(data)
    for field in STRINGS:
        text(configuration[field])
    for field in INTEGERS:
        tag.update(struct.pack("<I", configuration[field]))
    for field in LISTS:
        tag.update(struct.pack("<I", len(configuration[field])))
        for value in configuration[field]:
            text(value)
    return tag.hexdigest()


def read_configuration(path, key, work, idf):
    """Decrypt and parse only the explicit configuration fields, never tool stdout."""
    import importlib.util
    plain = Path(work) / "configuration.plain.bin"
    run_official(("decrypt", path, key, plain))
    spec = importlib.util.spec_from_file_location("service_nvs_parser", Path(idf) /
        "components/nvs_flash/nvs_partition_tool/nvs_parser.py")
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    partition = parser.NVS_Partition("configuration", bytearray(plain.read_bytes()))
    values = {}
    for page in partition.pages:
        for entry in page.entries:
            if entry.state == "Written" and entry.metadata["namespace"] == 1:
                if entry.metadata["type"] == "string":
                    raw = b"".join(bytes(child.raw) for child in entry.children)[:entry.data["size"]]
                    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                        raise ValueError("Invalid configuration string")
                    values[entry.key] = raw[:-1].decode("utf-8")
                elif entry.metadata["type"] == "uint32_t":
                    values[entry.key] = entry.data["value"]
    if values.get("schema") not in (1, 2):
        raise ValueError("Invalid configuration schema")
    if values["schema"] == 1 and values.get("fail_threshold") != 5:
        raise ValueError("Invalid legacy failure threshold")
    configuration = {field: values[name] for field, name in STRINGS.items()}
    configuration.update({field: values.get(name, 2) if field == "TargetFailurePolicy" and values["schema"] == 1
                          else values[name] for field, name in INTEGERS.items()})
    configuration.update({field: json.loads(values[name]) for field, name in LISTS.items()})
    validate_configuration(configuration)
    return configuration


def validate_configuration(c):
    """Host-side bounds also apply to signed packages before any ROM write."""
    import ipaddress
    from urllib.parse import urlsplit
    for field, maximum in (("WifiSsid", 32), ("WifiPassword", 64), ("RouterLogin", 128),
            ("RouterPassword", 256), ("RouterAddress", 253), ("RouterHttpsName", 253),
            ("WarpInterface", 32), ("Timezone", 128), ("ScheduleTime", 5)):
        value = c[field]
        if (not isinstance(value, str) or (not value and field != "WifiPassword")
                or len(value.encode("utf-8")) > maximum or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ValueError("Invalid configuration text")
    # The current Keenetic transport supports IPv4 addresses only.
    ipaddress.IPv4Address(c["RouterAddress"])
    import re
    if not re.fullmatch(r"Wireguard[0-9]+", c["WarpInterface"]):
        raise ValueError("Unsupported WARP interface")
    for field in INTEGERS:
        maximum = {"RouterPort": 65535, "ScheduleDay": 6, "FailureThreshold": 1000,
            "ConnectTimeoutSeconds": 60, "ReadTimeoutSeconds": 60, "DisablePauseSeconds": 3600,
            "WarmupSeconds": 3600, "TargetFailurePolicy": 3,
            "EnableAutoRecovery": 1, "EnableWeeklyRestart": 1, "OledEnabled": 1}.get(field, 86400)
        minimum = 0 if field in ("ScheduleDay", "TargetFailurePolicy", "EnableAutoRecovery", "EnableWeeklyRestart", "OledEnabled") else 1
        if type(c[field]) is not int or not minimum <= c[field] <= maximum:
            raise ValueError("Invalid configuration integer")
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", c["ScheduleTime"]):
        raise ValueError("Invalid schedule time")
    for field in LISTS:
        urls = c[field]
        if not isinstance(urls, list) or not 1 <= len(urls) <= 8 or len(set(urls)) != len(urls):
            raise ValueError("Invalid configuration URL list")
        for url in urls:
            parsed = urlsplit(url)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
                    or parsed.password or parsed.fragment or len(url.encode("utf-8")) > 512
                    or any(ch.isspace() or ord(ch) < 32 or ch == "\\" for ch in url)):
                raise ValueError("Invalid configuration URL")
    if set(c["TargetUrls"]) & set(c["ControlUrls"]):
        raise ValueError("Overlapping configuration URL lists")


def check_tools(idf_path):
    root = Path(idf_path)
    if (root / "version.txt").read_text(encoding="utf-8").strip() != "5.5.5":
        raise ValueError("Wrong ESP-IDF version")
    if not (root / "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py").is_file():
        raise ValueError("Missing SDK NVS launcher")
    for name, version in (("esp-idf-nvs-partition-gen", "0.1.9"), ("cryptography", "44.0.3")):
        if importlib.metadata.version(name) != version:
            raise ValueError("Wrong service dependencies")


def validate_key(path):
    """Reject random/corrupt/wrong-format key partitions before encrypting anything."""
    data = Path(path).read_bytes()
    if (len(data) != 4096 or data[68:] != b"\xff" * (4096 - 68)
            or struct.unpack_from("<I", data, 64)[0] != zlib.crc32(data[:64], 0xFFFFFFFF)
            or data[:32] == data[32:64] or data[:64] in (b"\0" * 64, b"\xff" * 64)):
        raise ValueError("Invalid NVS key partition")


def nvs_size(path):
    with Path(path).open(encoding="utf-8", newline="") as source:
        rows = {row[0].strip(): [value.strip() for value in row]
                for row in csv.reader(line for line in source
                                      if line.strip() and not line.lstrip().startswith("#"))}
    if rows["nvs"] != ["nvs", "data", "nvs", "0x10000", "0x6000", ""]:
        raise ValueError("Unsupported NVS layout")
    if rows["nvs_keys"] != ["nvs_keys", "data", "nvs_keys", "0x16000", "0x1000", "encrypted"]:
        raise ValueError("Unsupported NVS key layout")
    return 0x6000


def write_csv(configuration, path, weekly_date=0):
    configuration = dict(configuration)
    configuration.setdefault("TargetFailurePolicy", 2)
    if set(configuration) != set(STRINGS) | set(INTEGERS) | set(LISTS):
        raise ValueError("Wrong configuration schema")
    with Path(path).open("w", encoding="utf-8", newline="") as destination:
        writer = csv.writer(destination, lineterminator="\n")
        writer.writerow(("key", "type", "encoding", "value"))
        writer.writerow(("warp", "namespace", "", ""))
        writer.writerow(("schema", "data", "u32", 2))
        if weekly_date:
            from datetime import date
            if type(weekly_date) is not int or not 20240101 <= weekly_date <= 21001231:
                raise ValueError("Invalid retained schedule date")
            date(weekly_date // 10000, weekly_date // 100 % 100, weekly_date % 100)
            writer.writerow(("weekly_date", "data", "hex2bin", (b"WSD\x01" + struct.pack("<I", weekly_date)).hex()))
        for field, key in STRINGS.items():
            value = configuration[field]
            if not isinstance(value, str) or "\0" in value:
                raise ValueError("Invalid NVS string")
            # csv.writer preserves quotes, commas, backslashes and leading/trailing spaces.
            writer.writerow((key, "data", "string", value))
        for field, key in INTEGERS.items():
            value = configuration[field]
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Invalid NVS integer")
            writer.writerow((key, "data", "u32", value))
        for field, key in LISTS.items():
            value = configuration[field]
            if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
                raise ValueError("Invalid NVS URL list")
            writer.writerow((key, "data", "string", json.dumps(value, ensure_ascii=False, separators=(",", ":"))))


def run_official(arguments):
    # This is the same entry point used by the ESP-IDF SDK's -m launcher.
    from esp_idf_nvs_partition_gen import nvs_partition_gen as official

    # 0.1.9 uses random.choice for generate-key. Supply the OS cryptographic RNG;
    # leave Espressif's key layout, CRC and XTS encryption implementation intact.
    official.random = secrets.SystemRandom()
    previous = sys.argv
    sys.argv = ["nvs_partition_gen.py", *map(str, arguments)]
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            official.main()
    finally:
        sys.argv = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "key", "encrypt"))
    parser.add_argument("--idf-path", required=True)
    parser.add_argument("--request")
    parser.add_argument("--partitions")
    parser.add_argument("--key")
    parser.add_argument("--output")
    args = parser.parse_args()
    check_tools(args.idf_path)
    if args.action == "check":
        return
    key = Path(args.key).absolute()
    if key.suffix.lower() != ".bin":
        raise ValueError("NVS key requires .bin extension")
    if args.action == "key":
        if key.exists():
            raise ValueError("Key already exists")
        run_official(("generate-key", "--keyfile", key, "--outdir", key.parent))
        validate_key(key)
        return
    validate_key(key)
    size = nvs_size(args.partitions)
    request = Path(args.request).absolute()
    csv_path = request.with_suffix(".csv")
    output = Path(args.output).absolute()
    if output.exists() or output.parent != request.parent:
        raise ValueError("NVS output must be a new private staging file")
    try:
        configuration = json.loads(request.read_text(encoding="utf-8"))
        write_csv(configuration, csv_path)
        run_official(("encrypt", csv_path, output, hex(size), "--inputkey", key, "--version", "2"))
        if output.stat().st_size != size:
            raise ValueError("Wrong NVS image size")
    finally:
        csv_path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        # Never include exception values, JSON, tool output or stack frames here.
        print("NVS service tool failed; check dependencies, key, schema and partition layout.", file=sys.stderr)
        sys.exit(1)
