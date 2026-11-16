"""Inspect Keenetic over verified HTTPS, connected directly to its LAN IP.

HTTP is used only to discover the public HTTPS redirect; credentials and cookies
are sent only over verified HTTPS. No router configuration is changed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE = 2 * 1024 * 1024


def parse_rci(status, data):
    if status != 200:
        raise ValueError(f"RCI request failed: HTTP {status}")
    result = json.loads(data)

    def has_error(value):
        if isinstance(value, dict):
            return value.get("status") == "error" or any(has_error(item) for item in value.values())
        if isinstance(value, list):
            return any(has_error(item) for item in value)
        return False

    if has_error(result):
        raise ValueError("RCI reported an error inside HTTP 200")
    return result


class LanHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, name, address, context, port=443):
        super().__init__(name, port=port, timeout=8, context=context)
        self.address = address
        self.tls_context = context

    def connect(self):
        tcp = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(tcp, server_hostname=self.host)
        except BaseException:
            tcp.close()
            raise


def discover_name(address, https_port=443):
    connection = http.client.HTTPConnection(address, timeout=5)
    try:
        connection.request("GET", "/", headers={"Host": "my.keenetic.net"})
        response = connection.getresponse()
        location = urlsplit(response.getheader("Location", ""))
        if (response.status not in (301, 302, 303, 307, 308)
                or location.scheme != "https" or not location.hostname
                or location.username or location.password
                or location.port not in (None, 443, https_port)):
            raise ValueError("No HTTPS-name redirect; supply --tls-name")
        return location.hostname
    finally:
        connection.close()


class Router:
    def __init__(self, address, name, ca_file=None, port=443):
        self.address, self.name = address, name
        self.port = port
        self.context = ssl.create_default_context(cafile=ca_file)
        self.cookies = SimpleCookie()
        self.certificate = None

    def request(self, method, path, payload=None):
        connection = LanHTTPSConnection(self.name, self.address, self.context, self.port)
        headers = {"Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{key}={item.value}" for key, item in self.cookies.items())
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.connect()  # Validate hostname/chain before sending anything.
            self.certificate = connection.sock.getpeercert()
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    self.cookies.load(value)
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise ValueError("Router response too large")
            # Neither cookies nor the challenge are returned to diagnostics.
            metadata = {key: response.getheader(key) for key in
                        ("X-NDM-Realm", "X-NDM-Challenge", "X-NDM-Product", "WWW-Authenticate")}
            return response.status, metadata, data
        finally:
            connection.close()

    def login(self, username, password):
        status, headers, _ = self.request("GET", "/auth")
        if status != 401 or not headers["X-NDM-Realm"] or not headers["X-NDM-Challenge"]:
            raise ValueError("Unexpected authentication challenge")
        digest = hashlib.md5(f"{username}:{headers['X-NDM-Realm']}:{password}".encode("utf-8")).hexdigest()
        proof = hashlib.sha256((headers["X-NDM-Challenge"] + digest).encode("utf-8")).hexdigest()
        status, _, _ = self.request("POST", "/auth", {"login": username, "password": proof})
        if status != 200:
            raise ValueError(f"Authentication failed: HTTP {status}")

    def read_json(self, path):
        # Only read-only RCI endpoints are available through this helper.
        if path not in ("/rci/show/version", "/rci/show/interface"):
            raise ValueError("Unsupported read endpoint")
        status, _, data = self.request("GET", path)
        result = parse_rci(status, data)
        if not isinstance(result, dict):
            raise ValueError("Unexpected RCI response shape")
        return result


def read_credentials(path):
    """Read the project's Login:/Password: format without logging values."""
    lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    credentials = {}
    pending = None
    for line in lines:
        if not line.strip():
            continue
        if pending:
            credentials[pending] = line
            pending = None
            continue
        if ":" not in line:
            raise ValueError("Expected Login:/Password: credentials format")
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key not in ("login", "password") or key in credentials:
            raise ValueError("Invalid credentials fields")
        if value.strip():
            credentials[key] = value.strip()
        else:
            pending = key
    if pending or not all(credentials.get(key) for key in ("login", "password")):
        raise ValueError("Incomplete credentials file")
    return credentials["login"], credentials["password"]


def inspect(address, name, credentials_path=None, ca_file=None):
    router = Router(address, name, ca_file)
    status, headers, _ = router.request("GET", "/auth")
    report = {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
              "address": address, "https_name": name,
              "tls_verified": True, "certificate": router.certificate,
              "auth_challenge_status": status,
              "auth_scheme": (headers["WWW-Authenticate"] or "").split(" ", 1)[0],
              "product": headers["X-NDM-Product"]}
    if credentials_path:
        router.login(*read_credentials(credentials_path))
        report["authenticated"] = True
        version = router.read_json("/rci/show/version")
        report["version"] = {key: version[key] for key in
                             ("release", "title", "model", "hw_id", "hw_version", "manufacturer") if key in version}
        if not report["version"].get("title") or not report["version"].get("hw_id"):
            raise ValueError("Incomplete router identity response")
        interfaces = router.read_json("/rci/show/interface")
        allowed = ("id", "description", "type", "state", "link", "connected")
        report["interfaces"] = {key: {field: value[field] for field in allowed if field in value}
                                for key, value in interfaces.items() if isinstance(value, dict)}
        if not report["interfaces"]:
            raise ValueError("Empty interface response")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True, type=ipaddress.IPv4Address)
    parser.add_argument("--tls-name", help="Otherwise discover from the router's HTTP redirect")
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--ca-file", help="Explicit trusted CA file; certificate validation stays enabled")
    args = parser.parse_args()
    address = str(args.address)
    name = args.tls_name or discover_name(address)
    report = inspect(address, name, args.credentials_file, args.ca_file)
    folder = ROOT / ".local" / "stage1"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (datetime.now(timezone.utc).strftime("router-%Y%m%dT%H%M%S%fZ.json"))
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"Filtered evidence: {path}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, http.client.HTTPException) as error:
        # No raw response bodies, credentials, auth proof, or cookies in errors.
        print(f"Inspection failed ({type(error).__name__}). No insecure retry.", file=sys.stderr)
        sys.exit(1)
