"""Small public-result adapter. Listing/probing never writes flash or eFuses."""
import argparse
from pathlib import Path
import subprocess
import sys

import security_store as store
import secure_update as update
import service_events as events

_stage = "argument parsing"

def probe_application(package, vault, port, idf):
    global _stage
    _stage = "owner key vault validation"
    bundle = update.load_owner(vault)
    _stage = "security tools validation"
    store.check_security_tools(idf)
    _stage = "signed firmware package validation"
    with store.transaction(Path(package).parent) as work:
        plan, _ = update.load_package(package, bundle, work)
        _stage = "USB application probe"
        try:
            proof = update.UsbDevice(port).probe(bundle, plan, work, 5)
        except update.ProbeUnavailableError:
            return {"running": False, "reason": "no-application-response"}
        return {"running": True, "service": proof.get("service", 0)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("identify", "vault-info", "probe"))
    parser.add_argument("--port")
    parser.add_argument("--vault")
    parser.add_argument("--package")
    parser.add_argument("--idf-path")
    parser.add_argument("--events", action="store_true")
    args = parser.parse_args()
    events.enable(args.events)
    global _stage
    if args.action == "identify":
        _stage = "USB device selection"
        events.result({"mac": update.usb_serial(args.port)})
    elif args.action == "vault-info":
        _stage = "owner key vault validation"
        try:
            bundle = store.load_vault(args.vault)
        except (store.VaultOwnershipError, OSError, subprocess.SubprocessError):
            raise
        except Exception:
            update.fail("Owner key vault data could not be decrypted or validated for the current Windows user. Existing keys were not replaced.")
        events.result(store.summary(bundle))
    else:
        events.result(probe_application(args.package, args.vault, args.port, args.idf_path))


def cli():
    try:
        main()
        return 0
    except update.UpdateError as error:
        events.error(str(error))
    except store.VaultOwnershipError:
        events.error("Key vault ownership verification failed. The vault must belong to the current Windows user and allow only that user.")
    except PermissionError:
        events.error("Windows denied access to the selected device metadata or owner key files.")
    except FileNotFoundError:
        events.error("The owner key vault or a required package file is missing. Existing keys were not replaced.")
    except subprocess.CalledProcessError:
        events.error("Windows key vault permission check failed. Check the directory owner and access rules.")
    except Exception as error:
        events.error("Device check failed at stage: " + _stage + " (" + type(error).__name__ + "). No device write was attempted.")
    return 1


if __name__ == "__main__":
    sys.exit(cli())
