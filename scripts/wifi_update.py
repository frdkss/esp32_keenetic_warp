"""Wi-Fi application update: LAN discovery, pinned HTTPS staging, and verified boot.

Wire protocol (device side: src/wifi_update.cpp). Tag domains include a terminating NUL.
- Discovery: PC broadcasts b"WARP-DISCOVER-1 " + 64 hex nonce on UDP 47831.
  Device replies unicast b"WARP-HERE-1 " + json + b" " + tag + b"\\n", where
  tag = HMAC-SHA256(NVS key[:64], b"WARP-WIFI-DISCOVER-1\\0" + json).
  The authenticated json carries tls_sha256 (SHA-256 of the device certificate DER).
- Pin: the PC accepts the TLS certificate only if its DER hash equals tls_sha256.
- GET /api/v1/hello -> {"challenge", "target", "target_size"}; the challenge is single-use for 60 s.
- POST /api/v1/firmware with X-WARP-Challenge/Target/Length/Sha256/Tag. The body is ciphertext encrypted
  for the target slot. tag = HMAC-SHA256(NVS key[:64], b"WARP-WIFI-UPLOAD-1\\0" +
  f"{challenge}\\n{target}\\n{length}\\n{sha256}\\n"). The device checks the tag before erasing anything.
- Success is reported only after discovery shows the staged app_sha running in the target slot.

Tls identity is generated once on the PC during the USB migration and stored in partition wifi_tls.
"""
import argparse
import datetime
import hashlib
import hmac
import http.client
import json
import secrets
import socket
import ssl
import struct
import time
from pathlib import Path

import security_store as store
import secure_update as update
import service_events as events

PORT = 47831
DISCOVER_DOMAIN = b"WARP-WIFI-DISCOVER-1\0"
UPLOAD_DOMAIN = b"WARP-WIFI-UPLOAD-1\0"
RECORD_MAGIC = b"WARPTLS1"
RECORD_SIZE = 0x1000
RECORD_HEADER = 80
PAGE = 4096


def tls_identity(mac):
    """Self-signed P-256 certificate and key, returned as the wifi_tls partition record and its fingerprint."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WARP-" + mac)])
    start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=365 * 20))
                   .sign(key, hashes.SHA256()))
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    fingerprint = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    if RECORD_HEADER + len(certificate_pem) + len(key_pem) > RECORD_SIZE or len(certificate_pem) >= 1024 \
            or len(key_pem) >= 1024:
        raise update.UpdateError("TLS identity does not fit the device record.")
    record = bytearray(b"\xff" * RECORD_SIZE)
    record[0:8] = RECORD_MAGIC
    struct.pack_into("<II", record, 8, len(certificate_pem), len(key_pem))
    record[16:80] = fingerprint.encode()
    record[RECORD_HEADER:RECORD_HEADER + len(certificate_pem)] = certificate_pem
    key_start = RECORD_HEADER + len(certificate_pem)
    record[key_start:key_start + len(key_pem)] = key_pem
    return bytes(record), fingerprint


def device_key(bundle):
    return store.raw(bundle, "nvs")[:64]


def parse_reply(packet, nonce, bundle):
    prefix = b"WARP-HERE-1 "
    if not packet.startswith(prefix):
        return None
    body = packet[len(prefix):].rstrip(b"\r\n")
    if b" " not in body:
        return None
    payload, tag = body.rsplit(b" ", 1)
    expected = hmac.digest(device_key(bundle), DISCOVER_DOMAIN + payload, "sha256").hex().encode()
    if not hmac.compare_digest(tag, expected):
        return None
    try:
        reply = json.loads(payload)
    except ValueError:
        return None
    if (reply.get("schema") != 1 or reply.get("nonce") != nonce or reply.get("model") != "esp32c3"
            or reply.get("tls_port") != 8443 or len(str(reply.get("tls_sha256", ""))) != 64):
        return None
    return reply


def discover(bundle, timeout, targets=("255.255.255.255",), port=PORT):
    """Broadcasts a nonce-bound request and returns every authenticated device reply."""
    nonce = secrets.token_hex(32)
    request = b"WARP-DISCOVER-1 " + nonce.encode()
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.3)
        deadline = time.monotonic() + timeout
        next_send = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                for target in targets:
                    sock.sendto(request, (target, port))
                next_send = time.monotonic() + 1
            try:
                packet, address = sock.recvfrom(2048)
            except socket.timeout:
                continue
            reply = parse_reply(packet, nonce, bundle)
            if reply is not None:
                reply["address"] = address[0]
                found[reply["mac"]] = reply
    return list(found.values())


def find_device(bundle, mac, timeout):
    for reply in discover(bundle, timeout):
        if reply["mac"] == mac:
            return reply
    return None


def read_json(response):
    try:
        return json.loads(response.read())
    except ValueError:
        raise update.UpdateError("Device returned malformed JSON. No upload performed.") from None


def upload(reply, bundle, ciphertext, timeout):
    """Pins the TLS certificate to the authenticated discovery fingerprint, then sends the tagged image."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Trust comes from the pinned fingerprint below, not from a CA.
    connection = http.client.HTTPSConnection(reply["address"], reply["tls_port"], context=context, timeout=timeout)
    try:
        connection.connect()
        der = connection.sock.getpeercert(binary_form=True)
        if der is None or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), reply["tls_sha256"]):
            raise update.UpdateError("Device TLS certificate does not match the authenticated fingerprint. No upload.")
        connection.request("GET", "/api/v1/hello")
        hello = read_json(connection.getresponse())
        target = reply["target"]
        if hello.get("target") != target or hello.get("target_size") != reply["target_size"]:
            raise update.UpdateError("Device target slot changed during the update. No upload.")
        challenge = hello.get("challenge", "")
        if len(challenge) != 64 or any(c not in "0123456789abcdef" for c in challenge):
            raise update.UpdateError("Malformed device challenge.")
        length = str(len(ciphertext))
        digest = hashlib.sha256(ciphertext).hexdigest()
        message = f"{challenge}\n{target}\n{length}\n{digest}\n".encode()
        tag = hmac.digest(device_key(bundle), UPLOAD_DOMAIN + message, "sha256").hex()
        connection.request("POST", "/api/v1/firmware", body=ciphertext, headers={
            "X-WARP-Challenge": challenge, "X-WARP-Target": str(target), "X-WARP-Length": length,
            "X-WARP-Sha256": digest, "X-WARP-Tag": tag})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise update.UpdateError("Device rejected the Wi-Fi update. Nothing was switched to the new image.")
        try:
            result = json.loads(body)
        except ValueError:
            raise update.UpdateError("Device returned malformed JSON after upload.") from None
        if result.get("result") != "staged" or result.get("target") != target:
            raise update.UpdateError("Device did not confirm the staged slot.")
    except (OSError, ssl.SSLError, http.client.HTTPException):
        raise update.UpdateError("Wi-Fi transfer failed. The device keeps its current image; check the network and retry.") from None
    finally:
        connection.close()


def wait_running(bundle, mac, app_sha, target, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(2)
        reply = find_device(bundle, mac, min(5, max(1, deadline - time.monotonic())))
        if reply is not None and reply["app_sha"] == app_sha and reply["slot"] == target:
            return reply
    raise update.UpdateError("Staged firmware did not start in the target slot before timeout. Update is not verified.")


def execute(package, vault, idf, timeout=180):
    store.check_security_tools(idf)
    bundle = update.load_owner(vault)
    package = store.plain_path(package)
    with store.transaction(package.parent) as work:
        plan, data = update.load_package(package, bundle, work)
        if plan.get("migration") is not None or "configuration" in plan:
            update.fail("Wi-Fi update accepts regular application packages only. Use USB for migration or configuration.")
        mac = plan["identity"]["mac"]
        reply = find_device(bundle, mac, min(timeout, 15))
        if reply is None:
            update.fail("Device with the package identity was not found on the network. Connect it to the same LAN and retry.")
        if reply["app_sha"] == plan["app_sha"] and reply["version_hex"] == plan["version_hex"]:
            return {"schema": 1, "result": "current", "identity": bundle["identity"], "app_sha": plan["app_sha"]}
        target = reply["target"]
        if target not in update.SLOTS or reply["slot"] == target:
            update.fail("Device did not report a valid inactive slot.")
        ciphertext = update.reencrypt(data, target, work)
        upload(reply, bundle, ciphertext, min(timeout, 60))
        wait_running(bundle, mac, plan["app_sha"], target, timeout)
        return {"schema": 1, "result": "verified", "identity": bundle["identity"], "app_sha": plan["app_sha"],
                "version_hex": plan["version_hex"], "address": target, "bytes": len(ciphertext), "transport": "wifi"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("discover", "update"))
    parser.add_argument("--vault", required=True)
    parser.add_argument("--package")
    parser.add_argument("--idf-path")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    events.enable(False)
    if not 5 <= args.timeout <= 900:
        update.fail("Timeout must be 5..900 seconds.")
    if args.action == "discover":
        bundle = update.load_owner(args.vault)
        devices = discover(bundle, min(args.timeout, 30))
        events.result({"schema": 1, "result": "found", "devices": [
            {"mac": d["mac"], "address": d["address"], "slot": d["slot"], "app_sha": d["app_sha"],
             "version_hex": d["version_hex"], "target": d["target"]} for d in devices]})
        return
    if not args.package or not args.idf_path:
        update.fail("update requires --package and --idf-path.")
    if not 15 <= args.timeout <= 900:
        update.fail("Verification timeout must be 15..900 seconds.")
    events.result(execute(args.package, args.vault, args.idf_path, args.timeout))


if __name__ == "__main__":
    main()
