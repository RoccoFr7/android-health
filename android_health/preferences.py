"""Local per-device and per-profile app preferences."""
from contextlib import closing
import sqlite3


def kept_apps(path, data):
    if not path.exists():
        return set()
    with closing(sqlite3.connect(path)) as db:
        return {row[0] for row in db.execute(
            "SELECT package FROM kept WHERE device = ? AND profile = ?",
            (data["device_id"], data["user"]),
        )}


def set_kept(path, data, name, keep):
    if name not in data["apps"]:
        raise ValueError("Pacchetto assente dall’inventario.")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS kept (
            device TEXT NOT NULL, profile INTEGER NOT NULL, package TEXT NOT NULL,
            PRIMARY KEY (device, profile, package)
        )""")
        values = (data["device_id"], data["user"], name)
        if keep:
            db.execute("INSERT OR IGNORE INTO kept VALUES (?, ?, ?)", values)
        else:
            db.execute("DELETE FROM kept WHERE device = ? AND profile = ? AND package = ?", values)
