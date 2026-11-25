"""Parsers for Android shell output. Unsupported formats surface as missing data."""
import re

PACKAGE = r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*"
SENSITIVE = set("""
ACCESS_BACKGROUND_LOCATION ACCESS_COARSE_LOCATION ACCESS_FINE_LOCATION
BODY_SENSORS BODY_SENSORS_BACKGROUND CALL_PHONE CAMERA READ_CALL_LOG
READ_CONTACTS READ_SMS RECEIVE_SMS RECORD_AUDIO SEND_SMS WRITE_CALL_LOG
WRITE_CONTACTS READ_PHONE_STATE READ_MEDIA_IMAGES READ_MEDIA_VIDEO
READ_MEDIA_AUDIO READ_CALENDAR WRITE_CALENDAR
""".split())


def packages(raw):
    rows = {}
    for line in raw.splitlines():
        match = re.fullmatch(rf"package:(?:(/[^ ]+)=(?={PACKAGE}(?:\s|$)))?({PACKAGE})(.*)", line.strip())
        if not match:
            continue
        path, name, tail = match.groups()
        installer = re.search(r"\binstaller=(\S+)", tail)
        uid = re.search(r"\buid:(\d+)", tail)
        version = re.search(r"\bversionCode:(\d+)", tail)
        rows[name] = {
            "path": path, "installer": installer[1] if installer and installer[1] != "null" else None,
            "uid": int(uid[1]) if uid else None, "version": int(version[1]) if version else None,
        }
    if raw.strip() and not rows:
        raise ValueError("formato elenco pacchetti non riconosciuto")
    return rows


def grants(raw, user):
    if not re.search(r"(?m)^Packages:\s*$", raw):
        raise ValueError("sezione Packages assente")
    result = {}
    package = active_user = None
    runtime = False
    for line in raw.splitlines():
        if line and not line[0].isspace():
            package = active_user = None
            runtime = False
        header = re.match(rf"^  Package \[({PACKAGE})\]", line)
        if header:
            package = header[1]
            active_user = None
            runtime = False
            continue
        if package is None:
            continue
        profile = re.match(r"^\s+User (\d+):", line)
        if profile:
            active_user = int(profile[1])
            runtime = False
        if active_user != user:
            continue
        result.setdefault(package, set())
        if line.strip() == "runtime permissions:":
            runtime = True
            continue
        permission = re.match(r"^\s+android\.permission\.([A-Z_]+): granted=true\b", line)
        if runtime and permission and permission[1] in SENSITIVE:
            result.setdefault(package, set()).add(permission[1])
    return {name: sorted(values) for name, values in result.items()}


def components(raw):
    if raw.strip() in {"", "null"}:
        return []
    return sorted(set(re.findall(rf"({PACKAGE})/[a-zA-Z0-9_.$]+", raw)))


def battery(raw):
    fields = dict(re.findall(r"(?m)^\s*([\w ]+):\s*([\w.-]+)\s*$", raw))
    if "level" not in fields or "scale" not in fields:
        raise ValueError("livello o scala batteria assenti")
    level, scale = int(fields["level"]), int(fields["scale"])
    if not 0 <= level <= scale or not scale:
        raise ValueError("scala batteria non valida")
    return {
        "percent": round(level * 100 / scale, 2),
        "temperature_c": int(fields["temperature"]) / 10 if "temperature" in fields else None,
        "health_code": int(fields["health"]) if "health" in fields else None,
        "powered": any(fields.get(f"{kind} powered") == "true" for kind in ("AC", "USB", "Wireless", "Dock"))
        if any(k.endswith(" powered") for k in fields) else None,
    }


def memory(raw):
    values = {key: int(value) for key, value in re.findall(r"(?m)^(\w+):\s+(\d+) kB", raw)}
    if "MemTotal" not in values or "MemAvailable" not in values:
        raise ValueError("MemTotal o MemAvailable assenti")
    return {"total_kib": values["MemTotal"], "available_kib": values["MemAvailable"]}


def storage(raw):
    # df receives a single path. Bind mounts can supply a different mount label.
    rows = [line.split(maxsplit=5) for line in raw.splitlines() if line.strip()]
    if len(rows) == 2 and len(rows[1]) == 6 and rows[1][4].endswith("%"):
        _, total, used, available, _, mount = rows[1]
        return {"total_kib": int(total), "used_kib": int(used),
                "available_kib": int(available), "reported_mount": mount}
    raise ValueError("risposta df per /data non riconosciuta")


def process_pss(raw):
    start = raw.partition("Total PSS by process:")
    if not start[1]:
        raise ValueError("sezione PSS per processo assente")
    section = re.split(r"(?m)^Total ", start[2], maxsplit=1)[0]
    rows = [{"process": name, "pss_kib": int(size.replace(",", "")), "pid": int(pid)}
            for size, name, pid in re.findall(r"(?m)^\s*([\d,]+)K:\s+(\S+)\s+\(pid\s+(\d+)\b", section)]
    if not rows:
        raise ValueError("nessun processo PSS interpretabile")
    return sorted(rows, key=lambda row: -row["pss_kib"])
