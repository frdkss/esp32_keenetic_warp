"""Explicit initial provisioning for pristine, measured C3 v0.4/4MB/native USB.

No generic burn commands, force option, retry, or editable approval flag.
Hardware acceptance must be recorded separately from virtual/software tests.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import security_store as store
import secure_update as update
import service_nvs as nvs
import service_events as events

LAYOUT = {"bootloader": (0, 0xF000), "partitions": (0xF000, 0x1000),
          "nvs": (0x10000, 0x6000), "nvs_keys": (0x16000, 0x1000),
          "firmware": (0x20000, 0x1E0000), "tls": (0x3E0000, 0x1000)}
SECURITY_BITS = {
    "SPI_BOOT_CRYPT_CNT": 7, "SECURE_BOOT_EN": 1, "DIS_PAD_JTAG": 1,
    "DIS_USB_JTAG": 1, "SOFT_DIS_JTAG": 7, "DIS_DOWNLOAD_MANUAL_ENCRYPT": 1,
    "DIS_DOWNLOAD_ICACHE": 1, "DIS_DIRECT_BOOT": 1,
    "SECURE_BOOT_KEY_REVOKE1": 1, "SECURE_BOOT_KEY_REVOKE2": 1,
}
KEEP_ZERO = ("DIS_ICACHE", "DIS_USB_SERIAL_JTAG", "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
             "DIS_DOWNLOAD_MODE", "SECURE_BOOT_KEY_REVOKE0", "SECURE_BOOT_AGGRESSIVE_REVOKE")
_stage = "arguments"
PHASE_LABELS = {
    "flash": "Подготовка записи", "flash-pristine": "Проверка чистого состояния платы",
    "flash-attach": "Подключение flash", "flash-parameters": "Настройка параметров flash",
    "flash-erase": "Очистка flash перед первичной записью",
    "flash-key": "Запись ключа шифрования", "signing-digest": "Запись отпечатка Secure Boot",
    "security-flags": "Включение защиты", "write-protection": "Защита eFuse от записи",
    "secure-download": "Включение Secure Download", "verified": "Запуск подтверждён",
    "security-tools": "Проверка инструментов", "owner-keys": "Проверка ключей",
    "signed-package-and-backup": "Проверка пакета и копии ключей",
    "signed-package": "Проверка записанного пакета", "ROM-pristine-check": "Проверка платы через ROM",
    "flash-final-pristine": "Проверка платы перед защитой",
    "secure-ROM-validation": "Проверка включённой защиты", "boot-reset": "Запуск прошивки",
    "boot-verification": "Проверка запуска и мониторинга",
}
SEGMENT_LABELS = {"bootloader": "загрузчика", "partitions": "таблицы разделов",
                  "nvs": "конфигурации", "nvs_keys": "ключа NVS", "firmware": "прошивки"}
PROVISION_STAGES = (
    "security-tools", "owner-keys", "signed-package-and-backup", "ROM-pristine-check",
    "flash-pristine", "flash-attach", "flash-parameters", "flash-erase",
    *(phase + name for name in LAYOUT for phase in ("flash-write-", "flash-verify-")),
    "flash-final-pristine", "flash-key", "signing-digest", "security-flags", "write-protection",
    "secure-download", "secure-ROM-validation", "boot-reset", "boot-verification",
)
VERIFY_STAGES = ("owner-keys", "signed-package", "secure-ROM-validation", "boot-reset", "boot-verification")


def phase_label(phase):
    for prefix, label in (("flash-write-", "Запись "), ("flash-verify-", "Проверка ")):
        if phase.startswith(prefix):
            return label + SEGMENT_LABELS.get(phase[len(prefix):], "flash")
    return PHASE_LABELS.get(phase, phase)


def load_package(package, bundle, backup, password, work, idf):
    recovered = store.open_backup(backup, password)
    if not hmac.compare_digest(store.encoded(recovered), store.encoded(bundle)):
        update.fail("Portable backup does not match the selected device keys.")
    return inspect_package(package, recovered, work, idf, store.sha(Path(backup).read_bytes()))


def inspect_package(package, bundle, work, idf, backup_sha=None):
    """Verify signed/encrypted inputs; this function cannot write a device."""
    package = store.plain_path(package)
    plan = store.read_json(package / "plan.json")
    key, digest = update.key_files(bundle, work)
    key.public_key().verify((package / "plan.sig").read_bytes(), store.encoded(plan),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
    if (plan.get("schema") != 1 or plan.get("profile") != store.PROFILE
            or plan.get("identity") != bundle["identity"] or plan.get("keys") != store.summary(bundle)["fingerprints"]
            or (backup_sha is not None and plan.get("backup_sha256") != backup_sha)
            or plan.get("secure_boot_digest_hex") != digest or plan.get("backup_recovery") != "passed"
            or plan.get("sign_verify_encrypt_roundtrip") != "passed"
            or plan.get("environment") not in ("c3-production-no-oled", "c3-production-oled")):
        update.fail("Initial package, recovered backup, keys or device do not match.")
    segments = {}
    for spec in plan["segments"]:
        name = spec["name"]
        if name not in LAYOUT or name in segments:
            update.fail("Unexpected provisioning segment.")
        address, limit = LAYOUT[name]
        filename = name + ".encrypted.bin"
        if (spec["address"] != address or spec["file"] != filename or type(spec["size"]) is not int
                or not 0 < spec["size"] <= limit
                or (name == "partitions" and spec["size"] != 0xC00)
                or (name != "partitions" and spec["size"] % 4096)):
            update.fail("Invalid provisioning segment geometry.")
        path = store.plain_path(package / filename)
        data = path.read_bytes()
        if len(data) != spec["size"] or store.sha(data) != spec["sha256"]:
            update.fail("Provisioning segment hash mismatch.")
        segments[name] = data
    if set(segments) != set(LAYOUT) or {p.name for p in package.iterdir()} != {
            "plan.json", "plan.sig", *(name + ".encrypted.bin" for name in LAYOUT)}:
        update.fail("Incomplete provisioning package.")
    for name in ("bootloader", "firmware"):
        plain = update.decrypt(segments[name], work, LAYOUT[name][0])
        frozen = work / (name + ".signed.bin")
        frozen.write_bytes(plain)
        store.verify_image(frozen, LAYOUT[name][1])
        store.official(("verify-signature", "--version", "2", "--keyfile", work / "public.pem", frozen))
    app_data = update.decrypt(segments["firmware"], work)
    from esptool.bin_image import ESP32C3FirmwareImage
    app = ESP32C3FirmwareImage(io.BytesIO(app_data))
    (work / "table.bin").write_bytes(update.decrypt(segments["partitions"], work, 0xF000))
    store.verify_partition_table(work / "table.bin", idf)
    if update.decrypt(segments["nvs_keys"], work, 0x16000) != store.raw(bundle, "nvs"):
        update.fail("NVS key segment differs from recovered keys.")
    tls_record = update.decrypt(segments["tls"], work, LAYOUT["tls"][0])
    if (tls_record[:8] != b"WARPTLS1" or tls_record[16:80].decode("ascii", "replace") != plan.get("tls_fingerprint")):
        update.fail("Wi-Fi TLS identity does not match the signed plan.")
    (work / "nvs-key.bin").write_bytes(store.raw(bundle, "nvs"))
    frozen_nvs = work / "configuration.bin"
    frozen_nvs.write_bytes(segments["nvs"])
    store.verify_nvs(frozen_nvs, work / "nvs-key.bin", work, idf)
    config = nvs.read_configuration(frozen_nvs, work / "nvs-key.bin", work, idf)
    verification = {**update.descriptor(app_data), "image_sha": app.stored_digest.hex(),
        "boot_digest": digest, "table_sha": store.sha((work / "table.bin").read_bytes()),
        "config_tag": nvs.configuration_tag(config, store.raw(bundle, "nvs"))}
    return plan, segments, verification


def check_key(fields, block, purpose, readable):
    if (fields["KEY_PURPOSE_" + str(block)].get() != purpose
            or fields["KEY_PURPOSE_" + str(block)].is_writeable()
            or fields["BLOCK_KEY" + str(block)].is_writeable()
            or fields["BLOCK_KEY" + str(block)].is_readable() != readable):
        update.fail("Burned key protection or purpose did not verify. Stop; no automatic retry.")


def burn_security(commands, bundle, digest, checkpoint):
    """Pinned official espefuse API; also exercised with its virtual C3 controller."""
    checkpoint("flash-key")
    commands.burn_key(["BLOCK_KEY0"], [io.BytesIO(store.raw(bundle, "flash"))], ["XTS_AES_128_KEY"])
    check_key(commands.efuses, 0, "XTS_AES_128_KEY", False)
    checkpoint("signing-digest")
    commands.burn_key(["BLOCK_KEY1"], [io.BytesIO(bytes.fromhex(digest))], ["SECURE_BOOT_DIGEST0"])
    check_key(commands.efuses, 1, "SECURE_BOOT_DIGEST0", True)
    # espefuse's bitstring bytes are most-significant-first; ESP-IDF block reads
    # and the digest file use the reverse byte order (see EfuseFieldBase.get).
    if bytes(commands.efuses["BLOCK_KEY1"].get_raw())[::-1] != bytes.fromhex(digest):
        update.fail("Signing digest readback mismatch.")
    checkpoint("security-flags")
    commands.burn_efuse({name: str(value) for name, value in SECURITY_BITS.items()})
    checkpoint("write-protection")
    commands.write_protect_efuse(["SPI_BOOT_CRYPT_CNT", "RD_DIS", "DIS_ICACHE"])
    fields = commands.efuses
    for name, expected in SECURITY_BITS.items():
        if int(fields[name].get_raw()) != expected:
            update.fail("Protection flags did not verify.")
    for name in KEEP_ZERO + ("ENABLE_SECURITY_DOWNLOAD",):
        if int(fields[name].get_raw()) != 0:
            update.fail("USB download or protection state changed unexpectedly.")
    for name in ("SPI_BOOT_CRYPT_CNT", "RD_DIS", "DIS_ICACHE"):
        if fields[name].is_writeable():
            update.fail("Security write protection did not verify.")
    check_key(fields, 0, "XTS_AES_128_KEY", False)
    check_key(fields, 1, "SECURE_BOOT_DIGEST0", True)
    # Last register/eFuse operation: secure ROM can no longer run espefuse.
    checkpoint("secure-download")
    try:
        commands.burn_efuse({"ENABLE_SECURITY_DOWNLOAD": "1"})
    except SystemExit as exit_status:
        # Pinned espefuse exits successfully after its secure-mode reconnect.
        # Success still requires an independent ROM/profile and boot check.
        if exit_status.code not in (None, 0):
            update.fail("espefuse exited unsuccessfully while enabling Secure Download. Inspect receipt; do not repeat protection.")


class ProvisionDevice:
    def __init__(self, port, mac):
        self.port, self.mac = port, mac
        self.esp = self.commands = None

    def __enter__(self):
        import esptool
        import espefuse
        update.usb_serial(self.port, self.mac)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.esp = esptool.cmds.detect_chip(self.port, baud=115200, connect_attempts=3)
            try:
                if self.esp.CHIP_NAME != "ESP32-C3" or self.esp.IS_STUB or self.esp.secure_download_mode:
                    update.fail("A pristine ESP32-C3 ROM connection is required.")
                esptool.cmds.attach_flash(self.esp)
                self.commands = espefuse.init_commands(esp=self.esp, do_not_confirm=True)
                self.assert_pristine()
            except Exception:
                self.esp._port.close()
                raise
        return self

    def assert_pristine(self):
        fields = self.commands.efuses
        evidence = {"schema": 1, "profile": store.PROFILE,
            "identity": {"chip": "esp32c3", "revision": self.esp.get_chip_revision(),
                "flash_bytes": 1 << ((self.esp.flash_id() >> 16) & 0xFF),
                "mac": bytes(self.esp.read_mac()).hex(), "usb_vid": 0x303A, "usb_pid": 0x1001},
            "efuses": {name: fields[name].get() if name.startswith("KEY_PURPOSE_")
                else int(fields[name].get_raw()) for name in store.FIELDS},
            "key_blocks_empty": {fields.blocks[4 + index].name:
                fields.blocks[4 + index].is_readable() and fields.blocks[4 + index].get_raw() == bytes(32)
                for index in (0, 1)}}
        store.preflight(evidence)
        if evidence["identity"]["mac"] != self.mac:
            update.fail("Fresh ROM identity differs from the confirmed device.")
        update.usb_serial(self.port, self.mac)

    def write(self, segments, checkpoint=None, progress=None):
        mark = checkpoint or (lambda _: None)
        mark("flash-pristine")
        self.assert_pristine()
        # ERASE_FLASH is stub-only. The official no-stub erase-region command
        # uses FLASH_BEGIN, which erases the explicit region without a RAM stub.
        mark("flash-attach")
        self.esp.flash_spi_attach(0)
        mark("flash-parameters")
        self.esp.flash_set_parameters(4194304)
        mark("flash-erase")
        self.esp.flash_begin(4194304, 0, begin_rom_encrypted=False)
        total = sum(map(len, segments.values()))
        done = 0
        for name in sorted(segments, key=lambda item: LAYOUT[item][0]):
            data = segments[name]
            address = LAYOUT[name][0]
            mark("flash-write-" + name)
            self.esp.flash_begin(len(data), address, begin_rom_encrypted=False)
            for sequence, offset in enumerate(range(0, len(data), self.esp.FLASH_WRITE_SIZE)):
                block = data[offset:offset + self.esp.FLASH_WRITE_SIZE]
                self.esp.flash_block(block, sequence)
                if sequence % 64 == 0 or offset + len(block) == len(data):
                    if progress is not None:
                        progress.update(offset + len(block), len(data))
                    else:
                        events.emit("progress", phase="Первичная запись", current=done + offset + len(block), total=total)
            # ROM FLASH_END leaves the loader even with reboot=False. Keep the
            # session open for remaining segments, verification and eFuse work.
            mark("flash-verify-" + name)
            # The official ROM digest command avoids thousands of 64-byte USB
            # reads. Package signatures and SHA-256 were checked before writing.
            actual = self.esp.flash_md5sum(address, len(data))
            if not hmac.compare_digest(actual.lower(), hashlib.md5(data).hexdigest()):
                update.fail("Initial ciphertext readback mismatch. eFuses were not changed.")
            done += len(data)
        mark("flash-final-pristine")
        self.assert_pristine()

    def protect(self, bundle, verification, checkpoint):
        burn_security(self.commands, bundle, verification["boot_digest"], checkpoint)
        # Do not attempt register/eFuse reads after secure download is enabled.
        checkpoint("secure-ROM-validation")
        self.close_ports()
        import esptool
        self.esp = esptool.cmds.detect_chip(self.port, baud=115200, connect_attempts=3)
        update.usb_serial(self.port, self.mac)
        update.validate_rom(self.esp)
        checkpoint("boot-reset")
        self.esp.hard_reset(uses_usb=True)

    def close_ports(self):
        # espefuse can reconnect using a different loader object before exiting.
        current = getattr(getattr(self.commands, "efuses", None), "_esp", None)
        ports = {id(port): port for port in (getattr(self.esp, "_port", None), getattr(current, "_port", None)) if port is not None}
        for port in ports.values():
            port.close()

    def __exit__(self, *_):
        self.close_ports()


def save_receipt(record, receipt, work):
    temporary = work / "receipt.json"
    temporary.write_bytes(store.encoded(record))
    store.seal_private_files([temporary])
    temporary.replace(receipt)


def verify_boot(bundle, verification, work, port, timeout, record, checkpoint, progress):
    record["result"] = "unverified"
    checkpoint("boot-verification")
    probe_device = update.UsbDevice(port)
    deadline = time.monotonic() + timeout
    previous_monitoring = None
    while time.monotonic() < deadline:
        try:
            proof = probe_device.probe(bundle, verification, work, min(5, deadline - time.monotonic()))
        except (OSError, update.UpdateError):
            time.sleep(0.2)
            continue
        if any(proof.get(name) != verification[name] for name in ("app_sha", "image_sha", "version_hex", "config_tag")):
            record["verification_error"] = "image-or-configuration-mismatch"
            checkpoint("boot-verification")
            update.fail("Initial image or configuration did not verify. Protection was not repeated.")
        record["monitoring"] = {name: proof[name] for name in ("ready", "cycle", "time", "internet")}
        for name in ("runtime_error", "router_http"):
            if name in proof: record["monitoring"][name] = proof[name]
        record["authenticated_image_and_configuration"] = True
        if proof["ready"] == 1 and proof["cycle"] > 0 and proof["time"] == 1 and proof["internet"] == 1:
            record["result"] = "verified"
            checkpoint("verified")
            return {"result": "verified", "identity": bundle["identity"], "nvs_targeted": True}
        if record["monitoring"] != previous_monitoring:
            previous_monitoring = dict(record["monitoring"])
            progress.start("boot-verification", "Ожидание мониторинга: " + update.monitoring_summary(proof))
        time.sleep(0.2)
    checkpoint("boot-verification")
    if record.get("authenticated_image_and_configuration"):
        state = record["monitoring"]
        update.fail("Firmware and configuration are authenticated, but monitoring is not ready: " + update.monitoring_summary(state) +
                    ". Inspect runtime diagnostics; do not repeat initial protection.")
    update.fail("Initial writes completed, but boot/monitoring was not verified. Do not repeat protection; use verification of the existing attempt.")


def execute(package, vault, backup, password, idf, port, confirmation, timeout=180, device_factory=ProvisionDevice):
    global _stage
    progress = events.StageProgress(PROVISION_STAGES, phase_label)
    _stage = "security-tools"
    progress.start(_stage)
    store.check_security_tools(idf)
    _stage = "owner-keys"
    progress.start(_stage)
    bundle = update.load_owner(vault)
    mac = bundle["identity"]["mac"]
    if confirmation != mac:
        update.fail("Device confirmation does not match the selected key store.")
    receipt = store.plain_path(Path(vault) / "provision-receipt.json")
    if receipt.exists():
        update.fail("A provisioning attempt is already recorded for these keys. Inspect its receipt; no automatic retry.")
    store.assert_private(Path(vault))
    with store.transaction(Path(vault).parent) as work:
        _stage = "signed-package-and-backup"
        progress.start(_stage)
        plan, segments, verification = load_package(package, bundle, backup, password, work, idf)
        record = {"schema": 1, "identity": bundle["identity"], "package_sha256": store.sha(store.encoded(plan)),
                  "started_utc": datetime.now(timezone.utc).isoformat(), "phase": "preflight", "result": "started"}
        def checkpoint(phase):
            global _stage
            _stage = phase
            record["phase"] = phase
            save_receipt(record, receipt, work)
            if phase == "verified": progress.complete(phase_label(phase))
            else: progress.start("flash-pristine" if phase == "flash" else phase, phase_label(phase))
        _stage = "ROM-pristine-check"
        progress.start(_stage)
        with device_factory(port, mac) as device:
            # Create exclusively before the first write; an existing attempt is never resumed.
            with receipt.open("xb") as stream:
                stream.write(store.encoded(record))
            store.seal_private_files([receipt])
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    checkpoint("flash")
                    device.write(segments, checkpoint=checkpoint, progress=progress)
                    device.protect(bundle, verification, checkpoint)
            except (Exception, SystemExit) as error:
                record["result"] = "incomplete"
                record["error_type"] = type(error).__name__
                checkpoint(record["phase"])
                if isinstance(error, SystemExit):
                    update.fail("Protection tool exited unexpectedly at " + phase_label(_stage) + ". Inspect receipt; do not repeat protection.")
                raise
        return verify_boot(bundle, verification, work, port, timeout, record, checkpoint, progress)


def verify_existing(vault, idf, port, package=None, timeout=180):
    """Resume proof only. Never calls ProvisionDevice, flash writes or eFuse tools."""
    global _stage
    progress = events.StageProgress(VERIFY_STAGES, phase_label)
    _stage = "owner-keys"
    progress.start(_stage)
    store.check_security_tools(idf)
    bundle = update.load_owner(vault)
    receipt = store.plain_path(Path(vault) / "provision-receipt.json")
    store.assert_private(receipt)
    record = store.read_json(receipt)
    if (record.get("schema") != 1 or record.get("identity") != bundle["identity"]
            or record.get("phase") not in ("secure-download", "secure-ROM-validation", "boot-reset", "boot-verification", "verified")):
        update.fail("This receipt cannot resume verification. No flash/eFuse operation was attempted.")
    if package is None:
        base = store.ROOT / ".local/service"
        for candidate in sorted(base.glob("initial-*")):
            if candidate.is_dir() and (candidate / "plan.json").is_file():
                if store.sha(store.encoded(store.read_json(candidate / "plan.json"))) == record["package_sha256"]:
                    package = candidate
                    break
    if package is None:
        update.fail("The signed initial package recorded in the receipt was not found. Keep existing keys and receipt.")
    _stage = "signed-package"
    progress.start(_stage)
    if store.sha(store.encoded(store.read_json(Path(package) / "plan.json"))) != record["package_sha256"]:
        update.fail("Verification package differs from the recorded initial attempt.")
    with store.transaction(Path(vault).parent) as work:
        _, _, verification = inspect_package(package, bundle, work, idf)
        record.setdefault("interrupted_phase", record["phase"])
        record["verification_resumed_utc"] = datetime.now(timezone.utc).isoformat()
        def checkpoint(phase):
            global _stage
            _stage = phase
            record["phase"] = phase
            save_receipt(record, receipt, work)
            if phase == "verified": progress.complete(phase_label(phase))
            else: progress.start(phase)
        checkpoint("secure-ROM-validation")
        with update.UsbDevice(port).rom(bundle["identity"]["mac"]) as esp:
            update.validate_rom(esp)
            checkpoint("boot-reset")
            esp.hard_reset(uses_usb=True)
        return verify_boot(bundle, verification, work, port, timeout, record, checkpoint, progress)


def main():
    global _stage
    parser = argparse.ArgumentParser(description=__doc__)
    _stage = "arguments"
    parser.add_argument("--package")
    parser.add_argument("--vault", required=True)
    parser.add_argument("--backup")
    parser.add_argument("--request")
    parser.add_argument("--idf-path", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--confirm-device")
    parser.add_argument("--verify-existing", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--events", action="store_true")
    args = parser.parse_args()
    events.enable(args.events)
    if not 15 <= args.timeout <= 900:
        update.fail("Verification timeout must be 15..900 seconds.")
    if args.verify_existing:
        events.result(verify_existing(args.vault, args.idf_path, args.port, args.package, args.timeout))
        return
    if not all((args.package, args.backup, args.request, args.confirm_device)):
        update.fail("Initial protection requires package, recovered backup and matching device identity.")
    _stage = "backup-request"
    password = store.read_json(args.request)["passphrase"]
    events.result(execute(args.package, args.vault, args.backup, password, args.idf_path,
                          args.port, args.confirm_device, args.timeout))


def cli():
    try:
        main()
        return 0
    except update.UpdateError as error:
        events.error(str(error))
    except SystemExit:
        if _stage == "arguments": raise
        events.error("Initial protection tool exited without a result at " + phase_label(_stage) + ". Inspect receipt; no automatic retry.")
    except Exception as error:
        events.error("Initial protection failed at " + phase_label(_stage) + " (" + type(error).__name__ +
                     "). Inspect provision-receipt.json. No automatic retry; keys and receipts were retained.")
    return 1


if __name__ == "__main__":
    sys.exit(cli())
