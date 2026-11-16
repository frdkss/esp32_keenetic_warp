"""Read Keenetic's verified HTTPS hostname and its existing WireGuard interfaces.

Connection details arrive in a private request file, never in command arguments.
Only public discovery, authentication and read-only RCI requests are performed.
"""

import argparse
import http.client
import ipaddress
import json
from pathlib import Path
import re
import ssl
import sys
import unicodedata

from inspect_router import Router, discover_name
import service_events


class DiscoveryError(ValueError):
    """A fixed message that is safe to display in SERVICE."""


def read_request(path, interfaces=False):
    if path.stat().st_size > 16384:
        raise ValueError("Request too large")
    request = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(request, dict):
        raise ValueError("Invalid request")
    address = str(ipaddress.IPv4Address(request["address"]))
    port = request["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid HTTPS port")
    if interfaces:
        for key, maximum in (("login", 128), ("password", 256)):
            value = request.get(key)
            if (not isinstance(value, str) or not value or "\x00" in value
                    or len(value.encode("utf-8")) > maximum):
                raise DiscoveryError("Сначала заполните логин и пароль Keenetic в CFG/LOGIN.")
    return {**request, "address": address, "port": port}


def wireguard_interfaces(response):
    interfaces = []
    for name, value in response.items():
        if (not re.fullmatch(r"Wireguard[0-9]{1,23}", name)
                or not isinstance(value, dict) or value.get("id", name) != name
                or value.get("type") != "Wireguard"):
            continue
        description = value.get("description", "")
        if not isinstance(description, str):
            description = ""
        # Router labels must not be able to write terminal control sequences.
        description = "".join(c if not unicodedata.category(c).startswith("C") else " "
                              for c in description)[:80].strip()
        interfaces.append({"id": name, "description": description,
                           "enabled": value.get("state") == "up",
                           "connected": value.get("connected") == "yes"})
    return sorted(interfaces, key=lambda item: (int(item["id"][9:]), item["id"]))


def discover(request, interfaces=False):
    service_events.emit("phase", phase="Получение HTTPS-имени Keenetic")
    try:
        name = discover_name(request["address"], request["port"])
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise DiscoveryError("Keenetic не сообщил HTTPS-имя. Проверьте адрес роутера и подключение к его сети.") from error
    router = Router(request["address"], name, port=request["port"])
    service_events.emit("phase", phase="Проверка HTTPS-сертификата Keenetic")
    if interfaces:
        service_events.emit("phase", phase="Чтение WireGuard-интерфейсов Keenetic")
        try:
            router.login(request["login"], request["password"])
        except ValueError as error:
            raise DiscoveryError("Keenetic не подтвердил вход. Проверьте логин, пароль и права пользователя.") from error
        try:
            values = router.read_json("/rci/show/interface")
        except ValueError as error:
            raise DiscoveryError("Не удалось прочитать интерфейсы Keenetic. Проверьте права пользователя.") from error
        result = {"interfaces": wireguard_interfaces(values)}
    else:
        status, headers, _ = router.request("GET", "/auth")
        if status != 401 or not headers.get("X-NDM-Realm") or not headers.get("X-NDM-Challenge"):
            raise DiscoveryError("По указанному адресу Keenetic не подтвердил HTTPS-интерфейс входа.")
        result = {}
    return {"https_name": name, "tls_verified": True, **result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--interfaces", action="store_true")
    parser.add_argument("--events", action="store_true")
    args = parser.parse_args(argv)
    service_events.enable(args.events)
    try:
        request = read_request(args.request, args.interfaces)
        service_events.result(discover(request, args.interfaces))
        return 0
    except DiscoveryError as error:
        message = str(error)
    except ssl.SSLError:
        message = "Не удалось проверить HTTPS-сертификат Keenetic. HTTPS-имя не изменено."
    except (OSError, http.client.HTTPException):
        message = "Нет HTTPS-соединения с Keenetic. Проверьте адрес, HTTPS-порт и подключение к сети."
    except (ValueError, KeyError, TypeError):
        message = "Некорректные параметры или ответ Keenetic. HTTPS-имя не изменено."
    if args.events:
        service_events.emit("error", message=message)
    else:
        print(message, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
