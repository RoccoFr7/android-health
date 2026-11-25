"""Reversible package actions scoped to the scanned ADB device and profile."""
import hashlib
import json
import os
import re
import shlex

from . import parse
from .adb import AdbError
from .scan import apk_paths, digest


def package_state(adb, name, user):
    raw = adb.shell("dumpsys", "package", name)
    match = re.search(rf"(?m)^\s+User {user}:\s+[^\n]*\binstalled=true\b[^\n]*\benabled=(\d+)\b", raw)
    if not match:
        raise AdbError("Stato del pacchetto non leggibile per questo profilo.")
    return int(match[1])


def write_journal(path, records):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def history(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def change(adb, serial, snapshot, name, journal, restore=False):
    with journal.with_suffix(".lock").open("a+b") as lock:
        try:
            if os.name == "nt":
                import msvcrt

                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AdbError("Un altro intervento è in corso. Riprova al termine.") from exc
        return change_locked(adb, serial, snapshot, name, journal, restore)


def change_locked(adb, serial, snapshot, name, journal, restore):
    if not re.fullmatch(parse.PACKAGE, name) or name not in snapshot["apps"]:
        raise ValueError("Pacchetto assente dall’inventario.")
    adb.select(serial)
    device = hashlib.sha256(adb.serial.encode()).hexdigest()
    user = snapshot["user"]
    if device != snapshot["device_id"] or adb.shell("am", "get-current-user").strip() != str(user):
        raise AdbError("Telefono o profilo cambiato. Esegui una nuova scansione.")
    scope = ("--user", str(user))
    current = parse.packages(adb.shell("pm", "list", "packages", "--show-versioncode", *scope, name))
    current_version = current.get(name, {}).get("version")
    if current_version is None or current_version != snapshot["apps"][name]["version"]:
        raise AdbError("Versione del pacchetto cambiata o non verificabile. Ripeti la scansione.")
    key = f"{device}/{user}/{name}"
    records = history(journal)
    state = package_state(adb, name, user)
    if restore:
        if key not in records:
            raise AdbError("Nessun intervento registrato per questo pacchetto.")
        expected = records[key]
        command = {0: "default-state", 1: "enable"}[expected]
        if state == 3:
            adb.shell("pm", command, *scope, name)
        if package_state(adb, name, user) != expected:
            raise AdbError("Ripristino non verificato. La voce resta nel registro.")
        del records[key]
        write_journal(journal, records)
        return "Riattivazione verificata."

    if state not in (0, 1) or key in records:
        raise AdbError("Il pacchetto è già disabilitato o ha un intervento in sospeso.")
    app = snapshot["apps"][name]
    splits = app.get("split_apks")
    expected = {app["path"]: app.get("base_sha256")}
    expected.update({entry["path"]: entry["sha256"] for entry in splits or []})
    if any(expected.values()):
        current_paths = set(apk_paths(adb.shell("pm", "path", *scope, name)))
        if splits is not None and current_paths != set(expected):
            raise AdbError("L’elenco degli APK è cambiato dopo la scansione.")
        for path, sha in expected.items():
            if sha and (path not in current_paths or digest(adb.shell("sha256sum", shlex.quote(path))) != sha):
                raise AdbError("Un APK è cambiato dopo la scansione.")
    records[key] = state
    write_journal(journal, records)
    adb.shell("pm", "disable-user", *scope, name)
    if package_state(adb, name, user) != 3:
        raise AdbError("Disattivazione non verificata. Controlla la voce nel registro.")
    return "Disattivazione verificata."
