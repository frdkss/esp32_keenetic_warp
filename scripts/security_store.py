"""Offline owner key vault and provisioning rehearsal. Never writes a device.

CurrentUser DPAPI protects the local vault. Portable backups use scrypt + AES-GCM.
All raw material used by Espressif tools lives in a private transaction directory.
The only supported profile is the measured ESP32-C3 v0.4 / 4 MB / native USB board.
"""
import argparse
import base64
import contextlib
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from service_nvs import check_tools, nvs_size, run_official, validate_key

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "warp-c3-supermini-v0.4-4mb-usb"
BACKUP_MAGIC = b"WARPKEYS\x01"
ENTROPY = b"KeeneticWarp owner vault v1"
FIELDS = (
    "WR_DIS", "RD_DIS", "SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT",
    "DIS_DOWNLOAD_MANUAL_ENCRYPT", "DIS_DOWNLOAD_ICACHE", "DIS_ICACHE",
    "DIS_USB_JTAG", "DIS_PAD_JTAG", "SOFT_DIS_JTAG", "DIS_DIRECT_BOOT",
    "DIS_USB_SERIAL_JTAG", "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
    "DIS_DOWNLOAD_MODE", "ENABLE_SECURITY_DOWNLOAD",
    "SECURE_BOOT_KEY_REVOKE0", "SECURE_BOOT_KEY_REVOKE1", "SECURE_BOOT_KEY_REVOKE2",
    "SECURE_BOOT_AGGRESSIVE_REVOKE", *(f"KEY_PURPOSE_{i}" for i in range(6)),
)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    if Path(path).stat().st_size > 1024 * 1024:
        raise ValueError("Input too large")
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def plain_path(path, external=False):
    if external and not Path(path).is_absolute():
        raise ValueError("Absolute owner-material path required")
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.exists() and (part.is_symlink() or getattr(part.lstat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("Reparse point")
    if external and (path == ROOT or ROOT in path.parents):
        raise ValueError("Owner material must be outside the repository")
    return path


def private_directory(path):
    """Create with owner-only DACL before any sensitive byte is written."""
    path = plain_path(path)
    if os.name != "nt" or path.exists() or not path.parent.is_dir():
        raise ValueError("New Windows private directory and existing parent required")
    script = r"""
    $ErrorActionPreference='Stop'; $p=$env:WARP_PRIVATE_PATH
    $id=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($id); $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $id,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    if ([IO.Directory]::Exists($p)) { throw 'Already exists' }
    [void][IO.Directory]::CreateDirectory($p,$acl)
    """
    env = dict(os.environ, WARP_PRIVATE_PATH=str(path))
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=30)
    return path


def assert_private(path):
    path = plain_path(path)
    script = r"""
    $ErrorActionPreference='Stop'
    $id=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=Get-Acl -LiteralPath $env:WARP_PRIVATE_PATH
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $id.Value) { exit 1 }
    $rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    if ($rules.Count -eq 0) { exit 1 }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -ne $id.Value -or $rule.AccessControlType -ne 'Allow') { exit 1 }
    }
    """
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                   env=dict(os.environ, WARP_PRIVATE_PATH=str(path)), check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class VaultOwnershipError(ValueError):
    """A fixed diagnostic; never include paths, key contents or subprocess text."""


def seal_private_files(paths):
    """Fix UAC's default Administrators owner without broadening any file DACL.

    Windows does not inherit a directory's owner when an elevated Python process
    creates files. Only direct, single-link files in current-user-only private
    directories are accepted. Validate the entire batch before changing owners.
    """
    targets = [plain_path(path) for path in paths]
    if not targets:
        return
    for path in targets:
        if not path.is_file() or path.stat().st_nlink != 1:
            raise VaultOwnershipError("Private owner files must be regular single-link files.")
    script = r"""
    $ErrorActionPreference='Stop'
    $id=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $admins='S-1-5-32-544'
    $targets=ConvertFrom-Json $env:WARP_PRIVATE_FILES
    foreach ($p in $targets) {
        $item=Get-Item -LiteralPath $p -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid file' }
        foreach ($entry in @($item.Directory.FullName,$item.FullName)) {
            $acl=Get-Acl -LiteralPath $entry
            $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($entry -eq $item.Directory.FullName) {
                if ($owner -ne $id.Value) { throw 'Foreign parent owner' }
            } elseif ($owner -ne $id.Value -and $owner -ne $admins) {
                throw 'Foreign file owner'
            }
            $rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
            if ($rules.Count -eq 0) { throw 'Empty permissions' }
            foreach ($rule in $rules) {
                if ($rule.IdentityReference.Value -ne $id.Value -or $rule.AccessControlType -ne 'Allow') { throw 'Non-private permissions' }
            }
        }
    }
    foreach ($p in $targets) {
        $acl=[IO.File]::GetAccessControl($p)
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $id.Value) {
            $acl.SetOwner($id)
            [IO.File]::SetAccessControl($p,$acl)
        }
    }
    """
    try:
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=dict(os.environ, WARP_PRIVATE_FILES=json.dumps(list(map(str, targets)))),
            check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise VaultOwnershipError("Private file ownership could not be verified or repaired.") from None


@contextlib.contextmanager
def transaction(parent):
    parent = plain_path(parent)
    path = private_directory(parent / (".warp-private-" + secrets.token_hex(16)))
    try:
        yield path
    finally:
        # Exact directory created above; no computed shell deletion or traversal.
        plain_path(path)
        if path.parent != parent or not path.name.startswith(".warp-private-"):
            raise ValueError("Private transaction cleanup escaped its parent")
        if path.exists():
            shutil.rmtree(path)


def dpapi(data, decrypt=False):
    if os.name != "nt":
        raise ValueError("Windows DPAPI required")

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    def blob(value):
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        return Blob(len(value), buffer), buffer

    incoming, incoming_buffer = blob(data)
    entropy, entropy_buffer = blob(ENTROPY)
    outgoing = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        function = crypt.CryptUnprotectData
        second = None
    else:
        function = crypt.CryptProtectData
        second = "KeeneticWarp owner keys"
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p if decrypt else wintypes.LPCWSTR,
                        ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                        wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(incoming), second, ctypes.byref(entropy), None, None,
                    1, ctypes.byref(outgoing)):  # CRYPTPROTECT_UI_FORBIDDEN; CurrentUser.
        raise ValueError("DPAPI failed")
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        ctypes.memset(outgoing.data, 0, outgoing.size)
        kernel.LocalFree(outgoing.data)


def identity(value):
    if (set(value) != {"chip", "revision", "flash_bytes", "mac", "usb_vid", "usb_pid"}
            or value["chip"] != "esp32c3" or type(value["revision"]) is not int
            or value["revision"] != 4 or value["flash_bytes"] != 4194304
            or value["usb_vid"] != 0x303A or value["usb_pid"] != 0x1001
            or not re.fullmatch(r"[0-9a-f]{12}", value["mac"])
            or value["mac"] in ("000000000000", "ffffffffffff")):
        raise ValueError("Unsupported measured device profile")
    return value


def preflight(evidence):
    identity(evidence["identity"])
    if evidence["schema"] != 1 or evidence["profile"] != PROFILE:
        raise ValueError("Unsupported evidence")
    if set(evidence["efuses"]) != set(FIELDS):
        raise ValueError("Incomplete eFuse evidence")
    for name, value in evidence["efuses"].items():
        expected = "USER" if name.startswith("KEY_PURPOSE_") else 0
        if type(value) is not type(expected) or value != expected:
            raise ValueError("Only pristine readable/unlocked eFuses supported")
    # Purpose USER alone does not establish that a key block is unused.
    if (set(evidence["key_blocks_empty"]) != {"BLOCK_KEY0", "BLOCK_KEY1"}
            or any(value is not True for value in evidence["key_blocks_empty"].values())):
        raise ValueError("Selected key blocks are not proven empty")


def raw(bundle, name):
    return base64.b64decode(bundle["keys"][name], validate=True)


def validate_bundle(bundle):
    if set(bundle) != {"schema", "profile", "identity", "created_utc", "keys"}:
        raise ValueError("Wrong vault schema")
    if bundle["schema"] != 1 or bundle["profile"] != PROFILE:
        raise ValueError("Wrong vault version/profile")
    identity(bundle["identity"])
    if set(bundle["keys"]) != {"flash", "nvs", "signing"}:
        raise ValueError("Incomplete key set")
    flash, nvs, signing = (raw(bundle, name) for name in ("flash", "nvs", "signing"))
    if len(flash) != 32 or flash[:16] == flash[16:]:
        raise ValueError("Invalid flash XTS-AES-128 key")
    if (len(nvs) != 4096 or nvs[:32] == nvs[32:64]
            or struct.unpack_from("<I", nvs, 64)[0] != zlib.crc32(nvs[:64], 0xFFFFFFFF)
            or nvs[68:] != b"\xff" * 4028):
        raise ValueError("Invalid NVS XTS key partition")
    key = serialization.load_pem_private_key(signing, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072 or key.public_key().public_numbers().e != 65537:
        raise ValueError("Secure Boot v2 requires RSA-3072")
    return bundle


def summary(bundle):
    key = serialization.load_pem_private_key(raw(bundle, "signing"), password=None)
    public = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"schema": 1, "profile": PROFILE, "identity": bundle["identity"],
            "created_utc": bundle["created_utc"],
            "fingerprints": {"flash_sha256": sha(raw(bundle, "flash")),
                             "nvs_sha256": sha(raw(bundle, "nvs")),
                             "signing_public_der_sha256": sha(public)}}


def save_vault(path, bundle):
    path = plain_path(path, external=True)
    validate_bundle(bundle)
    if path.exists():
        raise ValueError("Vault will not be overwritten")
    with transaction(path.parent) as work:
        (work / "owner.warpkeys").write_bytes(dpapi(encoded(bundle)))
        (work / "manifest.json").write_bytes(encoded(summary(bundle)))
        seal_private_files([work / "owner.warpkeys", work / "manifest.json"])
        # Move completed directory; same-volume rename preserves private ACL.
        work.rename(path)
    return summary(bundle)


def load_vault(path):
    path = plain_path(path, external=True)
    private = path / "owner.warpkeys"
    assert_private(path)
    try:
        for part in (private, path / "manifest.json"):
            assert_private(part)
    except subprocess.CalledProcessError:
        # Recover only the known elevated-owner case. Shared/foreign material
        # still fails the unchanged strict assertions; key bytes are untouched.
        seal_private_files([private, path / "manifest.json"])
        for part in (private, path / "manifest.json"):
            assert_private(part)
    if private.stat().st_size > 65536:
        raise ValueError("Vault too large")
    bundle = validate_bundle(json.loads(dpapi(private.read_bytes(), decrypt=True)))
    if read_json(path / "manifest.json") != summary(bundle):
        raise ValueError("Vault manifest does not match protected keys")
    return bundle


def new_vault(path, evidence):
    preflight(evidence)
    with transaction(plain_path(path, external=True).parent) as work:
        run_official(("generate-key", "--keyfile", work / "nvs.bin", "--outdir", work))
        validate_key(work / "nvs.bin")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        keys = {"flash": secrets.token_bytes(32), "nvs": (work / "nvs.bin").read_bytes(),
                "signing": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption())}
        bundle = {"schema": 1, "profile": PROFILE, "identity": evidence["identity"],
                  "created_utc": datetime.now(timezone.utc).isoformat(),
                  "keys": {name: base64.b64encode(data).decode("ascii") for name, data in keys.items()}}
        return save_vault(path, bundle)


def backup_key(password, salt):
    if not isinstance(password, str) or not 16 <= len(password.encode("utf-8")) <= 1024:
        raise ValueError("Backup passphrase must contain 16..1024 UTF-8 bytes")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def open_backup(path, password):
    path = plain_path(path, external=True)
    if path.stat().st_size > 65536:
        raise ValueError("Backup too large")
    data = path.read_bytes()
    if not data.startswith(BACKUP_MAGIC) or len(data) < len(BACKUP_MAGIC) + 44:
        raise ValueError("Wrong backup format")
    offset = len(BACKUP_MAGIC)
    salt, nonce = data[offset:offset + 16], data[offset + 16:offset + 28]
    header = data[:offset + 28]
    plain = AESGCM(backup_key(password, salt)).decrypt(nonce, data[offset + 28:], header)
    return validate_bundle(json.loads(plain))


def backup_vault(vault, destination, password):
    path = plain_path(destination, external=True)
    vault = plain_path(vault, external=True)
    if vault == path or vault in path.parents or path.exists():
        raise ValueError("New backup outside vault required")
    bundle = load_vault(vault)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = BACKUP_MAGIC + salt + nonce
    data = header + AESGCM(backup_key(password, salt)).encrypt(nonce, encoded(bundle), header)
    with transaction(path.parent) as work:
        temporary = work / "backup.warpbackup"
        temporary.write_bytes(data)
        recovered = open_backup(temporary, password)
        if not hmac.compare_digest(encoded(bundle), encoded(recovered)):
            raise ValueError("Backup verification failed")
        seal_private_files([temporary])
        temporary.rename(path)
    return {"backup_sha256": sha(data), "device": bundle["identity"]}


def official(arguments):
    import espsecure
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            espsecure.main(list(map(str, arguments)))
    except SystemExit as error:
        if error.code not in (None, 0):
            raise ValueError("Official security tool failed") from None


def check_security_tools(idf):
    check_tools(idf)
    if importlib.metadata.version("esptool") != "5.1.0" or importlib.metadata.version("bitstring") != "4.3.1":
        raise ValueError("Wrong security tool versions")


def sdk_configuration(root, environment):
    if environment not in ("c3-production-no-oled", "c3-production-oled"):
        raise ValueError("Protected environment required")
    text = (root / f"sdkconfig.{environment}").read_text(encoding="utf-8")
    required = ("SECURE_BOOT", "SECURE_BOOT_V2_ENABLED", "SECURE_FLASH_ENC_ENABLED",
                "SECURE_FLASH_ENCRYPTION_MODE_RELEASE", "NVS_ENCRYPTION", "SECURE_ENABLE_SECURE_ROM_DL_MODE",
                "MBEDTLS_CERTIFICATE_BUNDLE", "MBEDTLS_HAVE_TIME_DATE")
    forbidden = ("SECURE_BOOT_ALLOW_JTAG", "SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS",
                 "SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC", "SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE",
                 "SECURE_FLASH_SKIP_WRITE_PROTECTION_CACHE", "SECURE_DISABLE_ROM_DL_MODE",
                 "SECURE_INSECURE_ALLOW_DL_MODE", "SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE",
                 "SECURE_BOOT_ALLOW_UNUSED_DIGEST_SLOTS", "SECURE_BOOT_INSECURE",
                 "SECURE_BOOT_BUILD_SIGNED_BINARIES", "SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT",
                 "AUTOSTART_ARDUINO", "ESP_TLS_INSECURE", "ESP_TLS_SKIP_SERVER_CERT_VERIFY")
    settings = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", text, re.M))
    if (any(settings.get("CONFIG_" + name) != "y" for name in required)
            or any(settings.get("CONFIG_" + name) == "y" for name in forbidden)
            or settings.get("CONFIG_PARTITION_TABLE_OFFSET", "").lower() != "0xf000"
            or settings.get("CONFIG_ESP32C3_REV_MIN_FULL") != "3"
            or settings.get("CONFIG_ESPTOOLPY_FLASHSIZE") != '"4MB"'):
        raise ValueError("Unsafe or unsupported SDK configuration")
    return text


def verify_build_configuration(build, sdk):
    compiled = read_json(build / "config/sdkconfig.json")
    settings = dict(re.findall(r"^CONFIG_(\w+)=(.*)$", sdk, re.M))
    for name in ("SECURE_BOOT", "SECURE_BOOT_V2_ENABLED", "SECURE_FLASH_ENC_ENABLED",
                 "SECURE_FLASH_ENCRYPTION_MODE_RELEASE", "NVS_ENCRYPTION", "SECURE_ENABLE_SECURE_ROM_DL_MODE",
                 "SECURE_BOOT_ALLOW_JTAG", "SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS",
                 "SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC", "SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE",
                 "SECURE_FLASH_SKIP_WRITE_PROTECTION_CACHE", "SECURE_DISABLE_ROM_DL_MODE",
                 "SECURE_INSECURE_ALLOW_DL_MODE", "SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE",
                 "SECURE_BOOT_ALLOW_UNUSED_DIGEST_SLOTS", "SECURE_BOOT_INSECURE",
                 "SECURE_BOOT_BUILD_SIGNED_BINARIES", "SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT",
                 "MBEDTLS_CERTIFICATE_BUNDLE", "MBEDTLS_HAVE_TIME_DATE", "AUTOSTART_ARDUINO",
                 "ESP_TLS_INSECURE", "ESP_TLS_SKIP_SERVER_CERT_VERIFY"):
        if bool(compiled.get(name, False)) != (settings.get(name) == "y"):
            raise ValueError("Build configuration is stale or does not match SDK settings")
    if compiled["PARTITION_TABLE_OFFSET"] != 0xF000 or compiled["ESP32C3_REV_MIN_FULL"] != 3:
        raise ValueError("Unexpected compiled profile")


def verify_partition_table(path, idf):
    # Parse the binary with the pinned SDK, then compare every partition/flag.
    module_path = str(Path(idf) / "components/partition_table")
    sys.path.insert(0, module_path)
    try:
        import gen_esp32part
        with contextlib.redirect_stdout(io.StringIO()):
            table = gen_esp32part.PartitionTable.from_binary(Path(path).read_bytes())
            table.verify()
        expected = [("nvs", 1, 2, 0x10000, 0x6000, False),
                    ("nvs_keys", 1, 4, 0x16000, 0x1000, True),
                    ("phy_init", 1, 1, 0x17000, 0x1000, False),
                    ("factory", 0, 0, 0x20000, 0x3E0000, False)]
        if [(p.name, p.type, p.subtype, p.offset, p.size, p.encrypted) for p in table] != expected:
            raise ValueError("Unexpected binary partition table")
    finally:
        sys.path.remove(module_path)


def verify_image(path, maximum):
    from esptool.bin_image import ESP32C3FirmwareImage
    data = Path(path).read_bytes()
    if not data or len(data) > maximum:
        raise ValueError("Image does not fit")
    with Path(path).open("rb") as source:
        image = ESP32C3FirmwareImage(source)
        image.verify()
    if (image.chip_id != 5 or image.flash_mode != 2 or image.flash_size_freq != 0x20
            # PlatformIO's elf2image leaves min_rev_full=0; the SDK minimum
            # and measured silicon revision are checked independently above.
            or image.min_rev_full > 4 or image.max_rev_full < 4
            or not image.append_digest or image.stored_digest != image.calc_digest):
        raise ValueError("Unexpected firmware header/digest")


def verify_nvs(path, key, work, idf):
    if Path(path).stat().st_size != 0x6000:
        raise ValueError("Wrong NVS size")
    plain = work / "nvs.decrypted.bin"
    try:
        try:
            run_official(("decrypt", path, key, plain))
        except SystemExit:
            raise ValueError("Official NVS decryption failed") from None
        # A wrong XTS key produces garbage without an authentication failure.
        # Espressif's NVS parser must therefore validate pages, entries and schema.
        import importlib.util
        spec = importlib.util.spec_from_file_location("warp_nvs_parser", Path(idf) /
            "components/nvs_flash/nvs_partition_tool/nvs_parser.py")
        parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parser)
        partition = parser.NVS_Partition("verified", bytearray(plain.read_bytes()))
        values = {}
        namespace_ok = False
        for page in partition.pages:
            if page.is_empty:
                continue
            if page.header["status"] not in ("Active", "Full"):
                raise ValueError("Invalid NVS page")
            if page.header["crc"]["original"] != page.header["crc"]["computed"]:
                raise ValueError("Invalid NVS page CRC")
            for entry in page.entries:
                if entry.state != "Written":
                    continue
                crc = entry.metadata["crc"]
                if crc["original"] != crc["computed"]:
                    raise ValueError("Invalid NVS entry CRC")
                if entry.children and crc["data_original"] != crc["data_computed"]:
                    raise ValueError("Invalid NVS data CRC")
                if entry.metadata["namespace"] == 0 and entry.key == "warp" and entry.data["value"] == 1:
                    namespace_ok = True
                elif entry.metadata["namespace"] == 1:
                    values[entry.key] = entry
        required = {"wifi_ssid", "wifi_pass", "router_login", "router_pass"}
        if not namespace_ok or values["schema"].data["value"] not in (1, 2) or not required <= set(values):
            raise ValueError("NVS schema/credentials missing")
        if values["schema"].metadata["type"] != "uint32_t":
            raise ValueError("Wrong NVS schema type")
        for name in required:
            entry = values[name]
            if entry.metadata["type"] != "string":
                raise ValueError("Wrong NVS credential type")
            data = b"".join(bytes(child.raw) for child in entry.children)[:entry.data["size"]]
            if not data.endswith(b"\0") or b"\0" in data[:-1]:
                raise ValueError("Invalid NVS string")
            value = data[:-1].decode("utf-8", errors="strict")
            if name != "wifi_pass" and not value:
                raise ValueError("Empty required credential")
        return {"nvs_sha256": sha(Path(path).read_bytes()), "credential_keys": sorted(required)}
    finally:
        plain.unlink(missing_ok=True)


def prepare(root, vault, backup, password, evidence, output, environment, idf, nvs):
    """Recover backup, sign actual build images, encrypt at actual flash addresses.

    This rehearsal deliberately cannot authorize irreversible device writes.
    No caller-controlled 'USB verified' flag or generic command execution exists.
    """
    preflight(evidence)
    bundle = load_vault(vault)
    recovered = open_backup(backup, password)
    if (bundle["identity"] != evidence["identity"]
            or not hmac.compare_digest(encoded(bundle), encoded(recovered))):
        raise ValueError("Device/vault/backup mismatch")
    root = Path(root)
    sdk = sdk_configuration(root, environment)
    nvs_size(root / "partitions.csv")
    build = root / ".pio/build" / environment
    verify_build_configuration(build, sdk)
    verify_partition_table(build / "partitions.bin", idf)
    output = plain_path(output)
    if output.exists():
        raise ValueError("Package output must be new")
    with transaction(output.parent) as work:
        # Use restored keys rather than originals to prove portable recovery.
        for name, filename in (("flash", "flash.key"), ("nvs", "nvs-key.bin"), ("signing", "signing.pem")):
            (work / filename).write_bytes(raw(recovered, name))
        key = serialization.load_pem_private_key(raw(recovered, "signing"), password=None)
        (work / "public.pem").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        official(("digest-sbv2-public-key", "--keyfile", work / "public.pem", "--output", work / "digest.bin"))
        nvs_check = verify_nvs(nvs, work / "nvs-key.bin", work, idf)
        package = private_directory(work / "package")
        segments = []
        sources = (("bootloader", build / "bootloader.bin", 0, 0xF000, True),
                   ("partitions", build / "partitions.bin", 0xF000, 0x1000, False),
                   ("nvs_keys", work / "nvs-key.bin", 0x16000, 0x1000, False),
                   ("firmware", build / "firmware.bin", 0x20000, 0x3E0000, True))
        for name, source, address, limit, sign in sources:
            plain = work / (name + ".plain.bin")
            if sign:
                verify_image(source, limit)
                official(("sign-data", "--version", "2", "--keyfile", work / "signing.pem",
                          "--output", plain, source))
                official(("verify-signature", "--version", "2", "--keyfile", work / "public.pem", plain))
            else:
                shutil.copyfile(source, plain)
            if plain.stat().st_size > limit:
                raise ValueError("Signed image overlaps next partition")
            encrypted = package / (name + ".encrypted.bin")
            official(("encrypt-flash-data", "--aes-xts", "--keyfile", work / "flash.key",
                      "--address", hex(address), "--output", encrypted, plain))
            roundtrip = work / (name + ".roundtrip.bin")
            official(("decrypt-flash-data", "--aes-xts", "--keyfile", work / "flash.key",
                      "--address", hex(address), "--output", roundtrip, encrypted))
            if roundtrip.read_bytes() != plain.read_bytes() or encrypted.stat().st_size > limit:
                raise ValueError("Encryption roundtrip failed")
            segments.append({"name": name, "address": address, "size": encrypted.stat().st_size,
                             "file": encrypted.name, "sha256": sha(encrypted.read_bytes())})
        shutil.copyfile(nvs, package / "nvs.encrypted.bin")
        segments.append({"name": "nvs", "address": 0x10000, "size": 0x6000,
                         "file": "nvs.encrypted.bin", "sha256": nvs_check["nvs_sha256"]})
        plan = {"schema": 1, "profile": PROFILE, "identity": evidence["identity"],
                "environment": environment, "sdkconfig_sha256": sha(sdk.encode()),
                "evidence_sha256": sha(encoded(evidence)), "keys": summary(bundle)["fingerprints"],
                "secure_boot_digest_hex": (work / "digest.bin").read_bytes().hex(),
                "backup_sha256": sha(Path(backup).read_bytes()), "backup_recovery": "passed",
                "sign_verify_encrypt_roundtrip": "passed", "segments": sorted(segments, key=lambda s: s["address"]),
                "efuse_plan": {"BLOCK_KEY0": "XTS_AES_128_KEY; read/write protected",
                               "BLOCK_KEY1": "SECURE_BOOT_DIGEST0; write protected; MUST remain readable",
                               "SPI_BOOT_CRYPT_CNT": "0b111; write protected (Release)",
                               "SECURE_BOOT_EN": 1, "DIS_PAD_JTAG": 1, "DIS_USB_JTAG": 1,
                               "SOFT_DIS_JTAG": "0b111", "DIS_DOWNLOAD_MANUAL_ENCRYPT": 1,
                               "DIS_DOWNLOAD_ICACHE": 1, "DIS_DIRECT_BOOT": 1,
                               "SECURE_BOOT_KEY_REVOKE0": "keep 0 (only trusted signing key)",
                               "SECURE_BOOT_KEY_REVOKE1": 1, "SECURE_BOOT_KEY_REVOKE2": 1,
                               "SECURE_BOOT_AGGRESSIVE_REVOKE": "keep 0",
                               "WR_DIS_RD_DIS": "set after flash key read protection",
                               "WR_DIS_DIS_ICACHE": "set shared write protection; preserve USB serial",
                               "ENABLE_SECURITY_DOWNLOAD": 1,
                               "DIS_USB_SERIAL_JTAG": "keep 0", "DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE": "keep 0",
                               "DIS_DOWNLOAD_MODE": "keep 0"},
                "provision_allowed": False,
                "blockers": ["Offline preparation does not authorize device writes.",
                             "Provision requires fresh matching hardware, recovered backup and typed device confirmation.",
                             "Physical protected USB/BOOT/RESET acceptance is still required."]}
        (package / "plan.json").write_bytes(encoded(plan))
        (package / "plan.sig").write_bytes(key.sign(encoded(plan),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256()))
        seal_private_files(list(package.iterdir()))
        package.rename(output)
        return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("new", "backup", "restore", "nvs-key", "prepare"))
    parser.add_argument("--idf-path", required=True)
    parser.add_argument("--vault")
    parser.add_argument("--backup")
    parser.add_argument("--request")
    parser.add_argument("--evidence")
    parser.add_argument("--output")
    parser.add_argument("--environment", default="c3-production-no-oled")
    parser.add_argument("--nvs", default=str(ROOT / ".local/service/nvs.encrypted.bin"))
    args = parser.parse_args()
    check_security_tools(args.idf_path)
    password = read_json(args.request)["passphrase"] if args.request else None
    if args.action == "new":
        result = new_vault(args.vault, read_json(args.evidence))
    elif args.action == "backup":
        result = backup_vault(args.vault, args.backup, password)
    elif args.action == "restore":
        result = save_vault(args.vault, open_backup(args.backup, password))
    elif args.action == "nvs-key":
        destination = plain_path(args.output)
        # Refuse raw-key output into a directory with permissive permissions.
        assert_private(destination.parent)
        with destination.open("xb") as stream:
            stream.write(raw(load_vault(args.vault), "nvs"))
        seal_private_files([destination])
        return
    else:
        result = prepare(ROOT, args.vault, args.backup, password, read_json(args.evidence),
                         args.output, args.environment, args.idf_path, args.nvs)
    if args.action != "prepare" and args.output:
        with plain_path(args.output).open("xb") as stream:
            stream.write(encoded(result))
    print("Offline security operation passed. No device writes were attempted.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as error:
        if isinstance(error.code, int) or error.code is None:
            raise
        print("Security operation failed. No sensitive diagnostics are printed.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Security operation failed: check profile, dependencies, paths, vault, backup and build inputs.", file=sys.stderr)
        sys.exit(1)
