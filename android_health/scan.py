"""Read-only device collection and schema for portable snapshots."""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import math
import re
import shlex
from . import parse
from .adb import AdbError

PROPERTIES = {
    "brand": "ro.product.manufacturer", "model": "ro.product.model",
    "android": "ro.build.version.release", "sdk": "ro.build.version.sdk",
    "patch": "ro.build.version.security_patch", "build": "ro.build.fingerprint",
    "verified_boot": "ro.boot.verifiedbootstate",
}
SPECIAL = {
    "accessibilita": "enabled_accessibility_services",
    "notifiche": "enabled_notification_listeners",
}


def usage(raw):
    stats = {"start_ms": None, "screen_on_ms": None, "traffic": {}, "energy_mah": {}}
    for row in csv.reader(raw.splitlines()):
        if len(row) < 5 or row[2] != "l" or not row[1].isdigit():
            continue
        uid, kind, *values = row[1:2] + row[3:]
        if uid == "0" and kind == "bt" and len(values) >= 6:
            stats["start_ms"] = int(values[5])
        elif uid == "0" and kind == "m":
            stats["screen_on_ms"] = int(values[0])
        elif uid != "0" and kind == "nt" and len(values) >= 4:
            stats["traffic"][uid] = sum(map(int, values[:4]))
        elif uid != "0" and kind == "pwi" and len(values) >= 2 and values[0] == "uid":
            power = float(values[1])
            if math.isfinite(power) and power >= 0:
                stats["energy_mah"][uid] = power
    if not stats["start_ms"]:
        raise ValueError("epoca batterystats non disponibile")
    return stats


def profile_id(raw):
    return int(raw.strip())


def digest(raw):
    value = raw.split(maxsplit=1)[0] if raw.strip() else ""
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("SHA-256 non disponibile")
    return value


def apk_paths(raw):
    paths = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if not line.startswith("package:/"):
            raise ValueError("Elenco dei percorsi APK non riconosciuto.")
        paths.append(line[len("package:"):])
    if not paths:
        raise ValueError("Android non ha restituito percorsi APK.")
    return list(dict.fromkeys(paths))


def security_checks(data, catalog):
    apps = data["apps"].values()
    splits = [split for app in apps for split in (app.get("split_apks") or [])]
    return {
        "indicators": len(catalog["sha256"]),
        "public_indicators": catalog.get("public_sha256", 0),
        "hashed_apps": sum(bool(app.get("base_sha256")) for app in apps),
        "split_apks": len(splits),
        "hashed_splits": sum(bool(split["sha256"]) for split in splits),
        "packages_listed": sum(app.get("split_apks") is not None for app in apps),
    }


def collect(adb, user=None, hash_apks=False):
    unavailable = {}

    def read(label, parser, *command):
        try:
            return parser(adb.shell(*command))
        except (AdbError, ValueError) as exc:
            unavailable[label] = str(exc)
            return None

    if user is None:
        user = profile_id(adb.shell("am", "get-current-user"))
    scope = ("--user", str(user))
    base = ("pm", "list", "packages")
    inventory = read("pacchetti", parse.packages, *base, "-f", "-i", "-U", "--show-versioncode", *scope)
    if inventory is None:
        inventory = parse.packages(adb.shell(*base, "-f", "-i", *scope))
    if not inventory:
        raise AdbError("Inventario vuoto. Verifica che il profilo esista e sia accessibile.")
    system = read("app di sistema", parse.packages, *base, "-s", *scope)
    disabled = read("app disabilitate", parse.packages, *base, "-d", *scope)
    grants = read("permessi", lambda raw: parse.grants(raw, user), "dumpsys", "-t", "25", "package")
    special = {kind: read(kind, parse.components, "settings", *scope, "get", "secure", key)
               for kind, key in SPECIAL.items()}

    def hash_package(item):
        name, app = item
        label = "elenco APK " + name
        paths = read(label, apk_paths, "pm", "path", *scope, name)
        app["split_apks"] = None
        if paths is not None:
            if app["path"] is None:
                app["path"] = paths[0]
            if paths[0] != app["path"]:
                unavailable[label] = "Percorso base cambiato durante la rilevazione."
                return
            app["split_apks"] = [
                {"path": path, "sha256": read(f"hash split {name}/{path.rsplit('/', 1)[-1]}",
                                              digest, "sha256sum", shlex.quote(path))}
                for path in paths[1:] if path.endswith(".apk")
            ]
        if app["path"] and app["path"].endswith(".apk") and not app.get("base_sha256"):
            app["base_sha256"] = read("hash " + name, digest, "sha256sum", shlex.quote(app["path"]))
        if paths is not None:
            unavailable.pop(label, None)

    for name, app in inventory.items():
        app["system"] = None if system is None else name in system
        app["disabled"] = None if disabled is None else name in disabled
        app["permissions"] = None if grants is None else grants.get(name)
        app["special"] = [kind for kind, names in special.items() if names is not None and name in names]
    if hash_apks:
        with ThreadPoolExecutor(max_workers=4) as workers:
            for _ in workers.map(hash_package, inventory.items()):
                pass
        # A vendor service can emit transient diagnostics while paths are queried in parallel.
        for item in inventory.items():
            if item[1]["split_apks"] is None:
                hash_package(item)

    properties = {name: read(name, lambda raw: raw.strip() or None, "getprop", prop)
                  for name, prop in PROPERTIES.items()}
    battery = read("batteria", parse.battery, "dumpsys", "battery")
    memory = read("RAM", parse.memory, "cat", "/proc/meminfo")
    storage = read("archiviazione", parse.storage, "df", "-k", "/data")
    processes = read("processi PSS", parse.process_pss, "dumpsys", "-t", "25", "meminfo")
    stats = read("batterystats", usage, "dumpsys", "-t", "25", "batterystats", "-c")
    if stats:
        profile_uids = {str(app["uid"]) for app in inventory.values() if app["uid"] is not None}
        for key in ("traffic", "energy_mah"):
            stats[key] = {uid: val for uid, val in stats[key].items() if uid in profile_uids}
        if not profile_uids:
            unavailable["attribuzione per UID"] = "UID dei pacchetti assenti"
    return {
        "schema": 1, "captured_at": datetime.now(timezone.utc).isoformat(),
        "device_id": hashlib.sha256(adb.serial.encode()).hexdigest(), "user": user,
        "device": properties, "battery": battery, "memory": memory, "storage": storage,
        "processes": processes, "usage": stats, "apps": inventory, "unavailable": unavailable,
    }
