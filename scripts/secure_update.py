"""Device-bound USB update; optional encrypted configuration. No eFuse writes.

The ROM cannot identify a secured C3 by MAC. A fresh NVS-key-authenticated app
probe binds the connected USB device, signing digest and flash key BEFORE reset.
Only an exact native USB serial-number match may bridge that reset boundary.
"""
import argparse
import contextlib
import hmac
import io
import json
from pathlib import Path
import re
import secrets
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import security_store as store
import service_nvs as nvs
import service_events as events

ADDRESS, LIMIT = 0x20000, 0x1E0000  # Package canonical slot (ota_0); other slots are re-encrypted per device.
SLOTS = (0x20000, 0x200000)
TABLE_ADDRESS, OTADATA_ADDRESS, TLS_ADDRESS, NVS_ADDRESS = 0xF000, 0x18000, 0x3E0000, 0x10000
FIXED_SEGMENTS = {NVS_ADDRESS: 0x6000, OTADATA_ADDRESS: 0x2000, TABLE_ADDRESS: 0x1000, TLS_ADDRESS: 0x1000}
LEGACY_TABLE = Path(__file__).resolve().parent / "legacy" / "partitions-factory.csv"
DOMAIN = b"WARP-USB-PROBE-1\0"
RUNTIME_ERRORS = ("NONE", "NO_CONFIG", "NOT_IMPLEMENTED", "NO_WIFI", "NO_TIME", "DNS", "CONNECT",
    "TIMEOUT", "TLS", "HTTP", "AUTH", "DENIED", "JSON", "RCI", "NO_INTERFACE", "NO_INTERNET",
    "OLED_UNKNOWN", "NO_OLED", "CONNECTION_FAILURE", "DNS_TIMEOUT", "URL", "HTTP_FORMAT", "HTTP_LIMIT",
    "RESOURCES", "NVS", "CANCELLED", "PENDING", "BUSY", "ROUTER_PROFILE", "STATE_MISMATCH", "WARP_FAIL", "INTERFACE_DISABLED")


def monitoring_summary(proof):
    fields = [name + "=" + str(proof[name]) for name in ("ready", "cycle", "time", "internet")]
    if "runtime_error" in proof:
        fields.append("runtime=" + RUNTIME_ERRORS[proof["runtime_error"]])
        fields.append("router_http=" + str(proof["router_http"]))
    return ", ".join(fields)


class UpdateError(ValueError):
    """Only fixed, non-sensitive messages may cross the service boundary."""


class ProbeUnavailableError(UpdateError):
    """The application did not accept/answer a read-only probe."""


def fail(message):
    raise UpdateError(message)


def load_owner(vault):
    try:
        return store.load_vault(vault)
    except Exception:
        fail("Owner keys are missing, inaccessible or invalid. Select the matching external KeyStore.")


def descriptor(data):
    # esp_image_header_t + first esp_image_segment_header_t + esp_app_desc_t.
    if len(data) < 288 or struct.unpack_from("<I", data, 32)[0] != 0xABCD5432:
        fail("Firmware has no valid application descriptor.")
    desc = data[32:288]
    if desc[48:80].split(b"\0", 1)[0] != b"esp32_keenetic_warp":
        fail("Firmware belongs to a different application.")
    return {"app_sha": desc[144:176].hex(), "version_hex": desc[16:48].hex()}


def key_files(bundle, work):
    key = serialization.load_pem_private_key(store.raw(bundle, "signing"), password=None)
    (work / "signing.pem").write_bytes(store.raw(bundle, "signing"))
    (work / "public.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (work / "flash.key").write_bytes(store.raw(bundle, "flash"))
    store.official(("digest-sbv2-public-key", "--keyfile", work / "public.pem",
                    "--output", work / "digest.bin"))
    return key, (work / "digest.bin").read_bytes().hex()


def decrypt(data, work, address=ADDRESS):
    (work / "cipher.bin").write_bytes(data)
    store.official(("decrypt-flash-data", "--aes-xts", "--keyfile", work / "flash.key",
                    "--address", hex(address), "--output", work / "plain.bin", work / "cipher.bin"))
    return (work / "plain.bin").read_bytes()


def prepare(root, vault, output, environment, idf, configuration=None, migrate=False):
    store.check_security_tools(idf)
    bundle = load_owner(vault)
    root, output = Path(root), store.plain_path(output)
    if output.exists():
        fail("Update package directory must be new.")
    if migrate and configuration is not None:
        fail("Layout migration cannot be combined with configuration. Run the migration first.")
    sdk = store.sdk_configuration(root, environment)
    build = root / ".pio/build" / environment
    store.verify_build_configuration(build, sdk)
    store.verify_partition_table(build / "partitions.bin", idf)
    source = build / "firmware.bin"
    store.verify_image(source, LIMIT)
    data = source.read_bytes()
    if b"WARP9 " not in data:
        fail("Firmware lacks the stage 9 USB verification protocol. Rebuild first.")
    app = descriptor(data)
    from esptool.bin_image import ESP32C3FirmwareImage
    image = ESP32C3FirmwareImage(io.BytesIO(data))
    with store.transaction(output.parent) as work:
        key, digest = key_files(bundle, work)
        # Freeze validated inputs before signing (do not reopen a mutable build).
        (work / "firmware.bin").write_bytes(data)
        signed = work / "signed.bin"
        store.official(("sign-data", "--version", "2", "--keyfile", work / "signing.pem",
                        "--output", signed, work / "firmware.bin"))
        store.official(("verify-signature", "--version", "2", "--keyfile", work / "public.pem", signed))
        if not 0 < signed.stat().st_size <= LIMIT or signed.stat().st_size % 4096:
            fail("Signed application does not fit the factory partition.")
        package = store.private_directory(work / "package")
        encrypted = package / "firmware.encrypted.bin"
        store.official(("encrypt-flash-data", "--aes-xts", "--keyfile", work / "flash.key",
                        "--address", hex(ADDRESS), "--output", encrypted, signed))
        if decrypt(encrypted.read_bytes(), work) != signed.read_bytes():
            fail("Application encryption roundtrip failed.")
        plan = {"schema": 1, "kind": "application-update", "profile": store.PROFILE,
                "identity": bundle["identity"], "keys": store.summary(bundle)["fingerprints"],
                "environment": environment, "address": ADDRESS, "size": encrypted.stat().st_size,
                "file": encrypted.name, "cipher_sha256": store.sha(encrypted.read_bytes()),
                "signed_sha256": store.sha(signed.read_bytes()), "unsigned_sha256": store.sha(data),
                "table_sha": store.sha((build / "partitions.bin").read_bytes()),
                "boot_digest": digest, "image_sha": image.stored_digest.hex(), **app}
        if migrate:
            plan["migration"] = migration_package(bundle, package, work, build, idf, plan)
        if configuration is not None:
            (work / "nvs-key.bin").write_bytes(store.raw(bundle, "nvs"))
            config_data = Path(configuration).read_bytes()
            frozen = package / "configuration.encrypted.bin"
            frozen.write_bytes(config_data)
            store.verify_nvs(frozen, work / "nvs-key.bin", work, idf)
            values = nvs.read_configuration(frozen, work / "nvs-key.bin", work, idf)
            plan["configuration"] = {"file": frozen.name, "size": len(config_data),
                "sha256": store.sha(config_data), "tag": nvs.configuration_tag(values, store.raw(bundle, "nvs"))}
        (package / "update.json").write_bytes(store.encoded(plan))
        signature = key.sign(store.encoded(plan), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
        (package / "update.sig").write_bytes(signature)
        store.seal_private_files(list(package.iterdir()))
        package.rename(output)
    return plan


def encrypt(plain, address, work, name):
    source = work / (name + ".plain")
    source.write_bytes(plain)
    output = work / (name + ".encrypted")
    store.official(("encrypt-flash-data", "--aes-xts", "--keyfile", work / "flash.key",
                    "--address", hex(address), "--output", output, source))
    data = output.read_bytes()
    if decrypt(data, work, address) != plain:
        fail("Flash encryption roundtrip failed.")
    return data


def reencrypt(data, address, work):
    # The XTS tweak depends on the flash address: each OTA slot needs its own ciphertext of the same signed image.
    return encrypt(decrypt(data, work), address, work, "slot-" + hex(address))


def legacy_table_sha(idf):
    # Binary of the pre-OTA single-factory table, generated by the same pinned SDK tool.
    module_path = str(Path(idf) / "components/partition_table")
    sys.path.insert(0, module_path)
    try:
        import gen_esp32part
        with contextlib.redirect_stdout(io.StringIO()):
            table = gen_esp32part.PartitionTable.from_csv(LEGACY_TABLE.read_text(encoding="utf-8"))
            table.verify()
            binary = table.to_binary()
    finally:
        sys.path.remove(module_path)
    return store.sha(binary)


def migration_package(bundle, package, work, build, idf, plan):
    # One-time USB migration from the single-factory layout: table, selector and Wi-Fi TLS identity.
    import wifi_update
    table = (build / "partitions.bin").read_bytes()
    if len(table) != 0xC00:
        fail("Unexpected partition table size.")
    record, fingerprint = wifi_update.tls_identity(bundle["identity"]["mac"])
    contents = {"table": (TABLE_ADDRESS, table + b"\xff" * (0x1000 - len(table))),
                "otadata": (OTADATA_ADDRESS, b"\xff" * 0x2000),
                "tls": (TLS_ADDRESS, record)}
    segments = []
    for name in ("table", "otadata", "tls"):
        address, content = contents[name]
        data = encrypt(content, address, work, "migration-" + name)
        file = "migration-" + name + ".encrypted.bin"
        (package / file).write_bytes(data)
        segments.append({"name": name, "file": file, "address": address, "size": len(data), "sha256": store.sha(data)})
    return {"previous_table_sha": legacy_table_sha(idf), "tls_fingerprint": fingerprint, "segments": segments}


def load_package(package, bundle, work):
    package = store.plain_path(package)
    plan = store.read_json(package / "update.json")
    expected_files = {"update.json", "update.sig", "firmware.encrypted.bin"}
    if "configuration" in plan:
        expected_files.add("configuration.encrypted.bin")
    migration = plan.get("migration")
    if migration is not None:
        expected_files.update(segment["file"] for segment in migration.get("segments", []) if "file" in segment)
    if {p.name for p in package.iterdir()} != expected_files:
        fail("Unexpected update package contents.")
    for name in expected_files:
        store.plain_path(package / name)
    key, digest = key_files(bundle, work)
    signature = package / "update.sig"
    if signature.stat().st_size != 384:
        fail("Invalid update manifest signature.")
    try:
        key.public_key().verify(signature.read_bytes(), store.encoded(plan),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
    except Exception:
        fail("Update manifest signature does not match the owner signing key.")
    if (plan.get("schema") != 1 or plan.get("kind") != "application-update"
            or plan.get("profile") != store.PROFILE or plan.get("identity") != bundle["identity"]
            or plan.get("keys") != store.summary(bundle)["fingerprints"] or plan.get("boot_digest") != digest
            or plan.get("environment") not in ("c3-production-no-oled", "c3-production-oled")
            or plan.get("address") != ADDRESS or plan.get("file") != "firmware.encrypted.bin"
            or type(plan.get("size")) is not int or not 0 < plan["size"] <= LIMIT or plan["size"] % 4096):
        fail("Update package profile, device, keys or partition address mismatch.")
    path = package / "firmware.encrypted.bin"
    if path.stat().st_size != plan["size"]:
        fail("Encrypted application size mismatch.")
    data = path.read_bytes()
    if store.sha(data) != plan["cipher_sha256"]:
        fail("Encrypted application hash mismatch.")
    signed = decrypt(data, work)
    if store.sha(signed) != plan["signed_sha256"] or descriptor(signed) != {
            name: plan[name] for name in ("app_sha", "version_hex")}:
        fail("Decrypted application identity mismatch.")
    store.verify_image(work / "plain.bin", LIMIT)
    from esptool.bin_image import ESP32C3FirmwareImage
    if ESP32C3FirmwareImage(io.BytesIO(signed)).stored_digest.hex() != plan["image_sha"]:
        fail("Application content digest mismatch.")
    store.official(("verify-signature", "--version", "2", "--keyfile", work / "public.pem", work / "plain.bin"))
    if migration is not None:
        verify_migration(package, migration, plan, work)
    return plan, data


def verify_migration(package, migration, plan, work):
    # Signed plan binds every raw segment to a fixed address; the roundtrip proves the address-tweaked ciphertext.
    if (set(migration) != {"previous_table_sha", "tls_fingerprint", "segments"}
            or not re.fullmatch("[0-9a-f]{64}", str(migration["previous_table_sha"]))
            or not re.fullmatch("[0-9a-f]{64}", str(migration["tls_fingerprint"]))
            or "configuration" in plan):
        fail("Invalid migration description.")
    expected = {"table": (TABLE_ADDRESS, 0x1000), "otadata": (OTADATA_ADDRESS, 0x2000),
                "tls": (TLS_ADDRESS, 0x1000)}
    segments = migration["segments"]
    if [segment.get("name") for segment in segments] != ["table", "otadata", "tls"]:
        fail("Invalid migration segment order.")
    for segment in segments:
        name = segment["name"]
        address, size = expected[name]
        if (set(segment) != {"name", "file", "address", "size", "sha256"} or segment["address"] != address
                or segment["size"] != size or segment["file"] != "migration-" + name + ".encrypted.bin"):
            fail("Invalid migration segment.")
        data = (package / segment["file"]).read_bytes()
        if len(data) != size or store.sha(data) != segment["sha256"]:
            fail("Migration segment hash mismatch.")


def load_configuration(package, bundle, plan, work, idf):
    spec = plan["configuration"]
    if (set(spec) != {"file", "size", "sha256", "tag"} or spec["file"] != "configuration.encrypted.bin"
            or type(spec["size"]) is not int or spec["size"] != 0x6000):
        fail("Invalid configuration segment.")
    path = store.plain_path(Path(package) / spec["file"])
    data = path.read_bytes()
    if len(data) != spec["size"] or store.sha(data) != spec["sha256"]:
        fail("Configuration ciphertext hash mismatch.")
    frozen = work / "configuration.frozen.bin"
    frozen.write_bytes(data)
    key = work / "nvs-key.bin"
    key.write_bytes(store.raw(bundle, "nvs"))
    store.verify_nvs(frozen, key, work, idf)
    configuration = nvs.read_configuration(frozen, key, work, idf)
    if not hmac.compare_digest(nvs.configuration_tag(configuration, store.raw(bundle, "nvs")), spec["tag"]):
        fail("Configuration fingerprint mismatch.")
    return configuration


def usb_serial(port, expected=None):
    from serial.tools import list_ports
    ports = [p for p in list_ports.comports() if p.device.casefold() == port.casefold()]
    if len(ports) != 1 or (ports[0].vid, ports[0].pid) != (0x303A, 0x1001):
        fail("Expected one native ESP32-C3 USB Serial/JTAG port.")
    serial = re.sub("[:-]", "", ports[0].serial_number or "").lower()
    if not re.fullmatch("[0-9a-f]{12}", serial) or (expected is not None and serial != expected):
        fail("USB serial number is unavailable or differs from the authenticated device. No write allowed.")
    return serial


def validate_probe(line, nonce, bundle, plan, work):
    if len(line) > 4096 or not line.startswith(b"WARP9 "):
        fail("Invalid USB probe response.")
    try:
        payload, tag = line[6:].strip().rsplit(b" ", 1)
        expected = hmac.digest(store.raw(bundle, "nvs")[:64], DOMAIN + payload, "sha256").hex().encode()
        if not hmac.compare_digest(tag, expected):
            fail("USB application proof does not match the NVS key.")
        proof = json.loads(payload)
        if "slot" in proof:
            if type(proof["slot"]) is not int or proof["slot"] not in SLOTS:
                fail("USB device reported an unknown application slot.")
            expected_table = plan["table_sha"]
        else:
            # Pre-OTA firmware: only the signed one-time migration package may address it.
            migration = plan.get("migration")
            if migration is None:
                fail("Firmware predates OTA slots. Use the one-time layout migration package.")
            expected_table = migration["previous_table_sha"]
        slot = proof.get("slot", ADDRESS)
        if (proof["schema"] != 1 or proof["nonce"] != nonce or proof["mac"] != bundle["identity"]["mac"]
                or proof["revision"] != 4 or proof["flash_bytes"] != 4194304 or proof["secure"] != 1
                or proof["boot_digest"] != plan["boot_digest"] or proof["table_sha"] != expected_table):
            fail("USB device identity, protection or partition table mismatch.")
        sample = bytes.fromhex(proof["cipher"])
        if len(sample) != 128 or store.sha(decrypt(sample, work, slot)) != proof["plain_sha"]:
            fail("Saved flash encryption key does not match the running device.")
        for field in ("cycle", "controls", "targets", "ready", "internet", "time"):
            if type(proof[field]) is not int or not 0 <= proof[field] <= 0xFFFFFFFF:
                fail("Malformed USB monitoring proof.")
        if "runtime_error" in proof or "router_http" in proof:
            error, http = proof.get("runtime_error"), proof.get("router_http")
            if (type(error) is not int or not 0 <= error < len(RUNTIME_ERRORS) or type(http) is not int
                    or (http != 0 and not 100 <= http <= 599)):
                fail("Malformed authenticated runtime diagnostics.")
        for field in ("app_sha", "image_sha", "version_hex"):
            if not re.fullmatch("[0-9a-f]{64}", proof[field]):
                fail("Malformed application descriptor in USB proof.")
        if proof.get("service") == 1:
            for field in ("challenge", "config_tag"):
                if not re.fullmatch(r"[0-9a-f]{64}", proof.get(field, "")):
                    fail("Malformed authenticated service proof.")
            if proof.get("locked") not in (0, 1) or type(proof.get("weekly_date")) is not int:
                fail("Malformed authenticated service state.")
        return proof
    except UpdateError:
        raise
    except Exception:
        fail("Malformed authenticated USB application response.")


class UsbDevice:
    def __init__(self, port):
        if not re.fullmatch(r"COM[1-9][0-9]*", port):
            fail("A Windows COM port is required.")
        self.port = port

    def probe(self, bundle, plan, work, timeout):
        nonce = secrets.token_hex(32)
        return self.exchange(b"WARP9 " + nonce.encode() + b"\n", nonce, bundle, plan, work, timeout)

    def lock(self, before, bundle, plan, work, timeout):
        challenge = before["challenge"].encode()
        tag = hmac.digest(store.raw(bundle, "nvs")[:64], b"WARP-USB-LOCK-1\0" + challenge, "sha256").hex().encode()
        return self.exchange(b"WARPLOCK " + challenge + b" " + tag + b"\n",
                             before["nonce"], bundle, plan, work, timeout)

    def exchange(self, request, nonce, bundle, plan, work, timeout):
        import serial
        usb_serial(self.port, bundle["identity"]["mac"])
        # Never toggle DTR/RTS on application inspection.
        device = serial.Serial(port=None, baudrate=115200, timeout=0.2, write_timeout=1)
        device.dtr = False
        device.rts = False
        device.port = self.port
        deadline, next_request = time.monotonic() + timeout, 0
        received = bytearray()
        try:
            with device:
                while time.monotonic() < deadline:
                    if time.monotonic() >= next_request:
                        device.write(request)
                        next_request = time.monotonic() + 2
                    for char in device.read(512):
                        if char == 10:
                            line, received = bytes(received), bytearray()
                            if line.startswith(b"WARP9 "):
                                return validate_probe(line, nonce, bundle, plan, work)
                        elif len(received) < 4096:
                            received.append(char)
                        else:
                            fail("USB response exceeds the protocol limit.")
        except serial.SerialTimeoutException:
            raise ProbeUnavailableError("USB application request timed out while sending. Release BOOT, press RESET and retry.") from None
        except serial.SerialException:
            fail("Cannot communicate with the selected COM port. Close Serial Monitor/other port users and check the USB connection.")
        raise ProbeUnavailableError("Running protected application did not answer. Release BOOT, press RESET and retry.")

    @contextlib.contextmanager
    def rom(self, mac):
        import esptool
        usb_serial(self.port, mac)
        esp = None
        try:
            # Suppress tool output: publish fixed errors and a safe receipt only.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                esp = esptool.cmds.detect_chip(self.port, baud=115200, connect_attempts=3)
            usb_serial(self.port, mac)
            yield esp
        finally:
            if esp is not None:
                esp._port.close()


def validate_rom(esp):
    if esp.CHIP_NAME != "ESP32-C3" or esp.IS_STUB or not esp.secure_download_mode:
        fail("Only ESP32-C3 ROM Secure Download Mode is supported. Initial protection is a separate procedure.")
    info = esp.get_security_info(cache=False)
    # Flags from pinned esptool 5.1.0 GET_SECURITY_INFO, not arbitrary eFuse reads.
    required = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10)
    purposes = list(info["key_purposes"])
    # The pinned parser exposes seven bytes; C3 has six key blocks (0..5).
    # esptool itself ignores bytes beyond EFUSE_MAX_KEY. The last byte is not
    # a C3 key purpose and is nonzero on real C3 ROMs.
    if (info["chip_id"] != 5 or info["flash_crypt_cnt"] != 7 or info["flags"] != required
            or len(purposes) != 7 or any(type(value) is not int or not 0 <= value <= 255 for value in purposes)
            or purposes[:6] != [4, 9, 0, 0, 0, 0]):
        fail("Unsupported ROM protection state or key purposes. Protection will not be changed.")


def segment_allowed(address, data):
    # Exact geometry for each fixed partition; app slots accept any size within the slot.
    if address in SLOTS:
        return 0 < len(data) <= LIMIT
    return FIXED_SEGMENTS.get(address) == len(data)


def write_ciphertext(esp, data, address=ADDRESS, reset=True, progress=None):
    """Narrow ROM writer: validated ciphertext at fixed partition addresses only.

    esptool.write_flash treats every input as plaintext and requires --force in
    secure release mode. Use its basic ROM methods after our crypto/profile
    checks instead. No force, RAM stub, memory/register reads, or whole-chip erase.
    """
    validate_rom(esp)
    if (not segment_allowed(address, data) or len(data) % 4096 or esp.FLASH_WRITE_SIZE != 1024):
        fail("Invalid encrypted segment size or ROM write geometry.")
    esp.flash_spi_attach(0)
    esp.flash_set_parameters(4194304)
    esp.flash_begin(len(data), address, begin_rom_encrypted=False)
    for sequence, offset in enumerate(range(0, len(data), esp.FLASH_WRITE_SIZE)):
        esp.flash_block(data[offset:offset + esp.FLASH_WRITE_SIZE], sequence)
        if progress and (sequence % 64 == 0 or offset + esp.FLASH_WRITE_SIZE >= len(data)):
            progress(min(offset + esp.FLASH_WRITE_SIZE, len(data)))
    # FLASH_END exits ROM; reset only after every requested segment is written.
    if reset:
        esp.hard_reset(uses_usb=True)


def execute(package, vault, idf, device, timeout=180, apply_configuration=True, report_progress=True):
    labels = {"tools": "Проверка инструментов и ключей", "package": "Проверка пакета",
        "proof": "Проверка устройства", "maintenance": "Подготовка обновления",
        "rom": "Проверка ROM", "write": "Запись прошивки и CFG",
        "reset": "Запуск прошивки", "verify": "Проверка запуска и мониторинга"}
    progress = events.StageProgress(tuple(labels), labels.__getitem__, enabled=report_progress)
    progress.start("tools")
    store.check_security_tools(idf)
    bundle = load_owner(vault)
    package = store.plain_path(package)
    with store.transaction(package.parent) as work:
        progress.start("package")
        plan, data = load_package(package, bundle, work)
        configuration = load_configuration(package, bundle, plan, work, idf) if apply_configuration and "configuration" in plan else None
        progress.start("proof")
        before = device.probe(bundle, plan, work, min(timeout, 15))
        if before["ready"] != 1 and configuration is None:
            fail("Current application configuration is not ready. No flash write attempted.")
        app_written = False
        progress.start("maintenance")
        if configuration is not None:
            if before.get("service") != 1:
                progress.start("maintenance", "Обновление протокола обслуживания")
                execute(package, vault, idf, device, timeout, apply_configuration=False, report_progress=False)
                app_written = True
                before = device.probe(bundle, plan, work, min(timeout, 15))
            if before.get("service") != 1:
                fail("Firmware does not support authenticated configuration maintenance.")
            before = device.lock(before, bundle, plan, work, min(timeout, 10))
            if before.get("locked") != 1:
                fail("WARP recovery or router operation is active. Configuration was not written; wait and retry.")
            key = work / "nvs-key.bin"
            csv = work / "applied.csv"
            nvs.write_csv(configuration, csv, before["weekly_date"])
            applied = work / "applied.nvs.bin"
            nvs.run_official(("encrypt", csv, applied, "0x6000", "--inputkey", key, "--version", "2"))
            store.verify_nvs(applied, key, work, idf)
            nvs_data = applied.read_bytes()  # Freeze the exact retained-state image before reset.
        slot = before.get("slot", ADDRESS)
        migration = plan.get("migration")
        if migration is not None and "slot" in before:
            fail("Device already uses the OTA layout. Use a regular update package instead of the migration.")
        image = data if slot == ADDRESS else reencrypt(data, slot, work)
        writes = []
        if not app_written:
            writes.append((slot, image))
        if migration is not None:
            # Table last: the new layout becomes visible only after every other segment is in place.
            order = {"otadata": 0, "tls": 1, "table": 2}
            for segment in sorted(migration["segments"], key=lambda item: order[item["name"]]):
                writes.append((segment["address"], (package / segment["file"]).read_bytes()))
        if configuration is not None:
            writes.append((NVS_ADDRESS, nvs_data))  # Freeze the exact retained-state image before reset.
        total = sum(len(segment) for _, segment in writes)
        progress.start("rom")
        try:
            with device.rom(bundle["identity"]["mac"]) as esp:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    validate_rom(esp)
                    done = 0
                    progress.start("write")
                    for address, segment in writes:
                        write_ciphertext(esp, segment, address=address, reset=False,
                            progress=lambda count, base=done: progress.update(base + count, total))
                        done += len(segment)
                    progress.start("reset")
                    esp.hard_reset(uses_usb=True)
        except UpdateError:
            raise
        except Exception:
            fail("ROM connection/write failed. Firmware or requested configuration may be incomplete. Release BOOT and press RESET. No automatic retry.")
        progress.start("verify")
        deadline = time.monotonic() + timeout
        last_proof = None
        last_summary = None
        while time.monotonic() < deadline:
            try:
                after = device.probe(bundle, plan, work, min(5, max(0.1, deadline - time.monotonic())))
            except (OSError, UpdateError):
                # Re-enumeration and boot can temporarily make USB unavailable.
                time.sleep(0.2)
                continue
            if any(after[field] != plan[field] for field in ("app_sha", "image_sha", "version_hex")):
                fail("Expected firmware did not start after writing. Update is not verified.")
            if after.get("slot", ADDRESS) != slot:
                fail("Expected application slot did not start after writing. Update is not verified.")
            if configuration is not None and after.get("config_tag") != plan["configuration"]["tag"]:
                fail("Firmware started with a different configuration. Update is not verified.")
            last_proof = after
            if (after["ready"] == 1 and after["cycle"] > 0 and after["controls"] > 0
                    and after["targets"] > 0 and after["time"] == 1 and after["internet"] == 1):
                progress.complete("Запуск подтверждён")
                return {"schema": 1, "result": "verified", "identity": bundle["identity"],
                        "app_sha": after["app_sha"], "version_hex": after["version_hex"],
                        "monitor_cycle": after["cycle"], "address": slot, "bytes": len(image),
                        "nvs_targeted": configuration is not None, "migrated": migration is not None}
            summary = monitoring_summary(after)
            if summary != last_summary:
                last_summary = summary
                progress.start("verify", "Ожидание мониторинга: " + summary)
            time.sleep(0.5)
        if last_proof is not None:
            subject = "Firmware and CFG are authenticated" if configuration is not None else "Firmware is authenticated"
            fail(subject + ". Monitoring was not verified before timeout: " + monitoring_summary(last_proof) +
                 ". Inspect the runtime error; do not repeat initial protection.")
        fail("Bytes written, but expected firmware and monitoring were not verified before timeout. Release BOOT, press RESET; inspect Wi-Fi/time/control connectivity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "update"))
    parser.add_argument("--vault", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--idf-path", required=True)
    parser.add_argument("--environment", default="c3-production-no-oled")
    parser.add_argument("--port")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--nvs")
    parser.add_argument("--events", action="store_true")
    parser.add_argument("--migrate", action="store_true", help="prepare: one-time USB layout migration package")
    args = parser.parse_args()
    events.enable(args.events)
    if not 15 <= args.timeout <= 900:
        fail("Verification timeout must be 15..900 seconds.")
    if args.action == "prepare":
        result = prepare(store.ROOT, args.vault, args.package, args.environment, args.idf_path, args.nvs,
                         migrate=args.migrate)
        events.result({"result": "prepared", "identity": result["identity"], "app_sha": result["app_sha"],
                       "migration": "migration" in result})
    else:
        result = execute(args.package, args.vault, args.idf_path, UsbDevice(args.port or ""), args.timeout)
        events.result(result)


if __name__ == "__main__":
    try:
        main()
    except UpdateError as error:
        events.error(str(error))
        sys.exit(1)
    except Exception:
        events.error("Secure update failed before verification. Check pinned tools, keys and package. No protection settings were changed.")
        sys.exit(1)
