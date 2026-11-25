"""Evidence-based findings and snapshot comparison."""
from datetime import datetime
import re

CATEGORIES = {"bloatware", "utility", "optional_preload"}
SENSITIVE_COMBINATION = {"READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECORD_AUDIO", "READ_CONTACTS"}


def validate_catalog(catalog):
    if not isinstance(catalog, dict):
        raise ValueError("Il catalogo deve essere un oggetto JSON.")
    packages, hashes = catalog.get("packages", {}), catalog.get("sha256", {})
    if not isinstance(packages, dict) or not isinstance(hashes, dict):
        raise ValueError("packages e sha256 devono essere oggetti JSON.")
    for name, item in packages.items():
        if (not re.fullmatch(r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*", name)
                or not isinstance(item, dict) or not isinstance(item.get("category"), str)
                or item["category"] not in CATEGORIES
                or not isinstance(item.get("reason"), str) or not item["reason"].strip()):
            raise ValueError(f"Voce catalogo non valida: {name}")
    for sha, item in hashes.items():
        if (not re.fullmatch(r"[0-9a-f]{64}", sha) or not isinstance(item, dict)
                or not isinstance(item.get("source"), str) or not item["source"].strip()):
            raise ValueError(f"Indicatore SHA-256 non valido: {sha}")
    return packages, hashes


def findings(snapshot, catalog):
    packages, hashes = validate_catalog(catalog)
    result = []

    def add(priority, subject, evidence, kind=None):
        row = {"priority": priority, "subject": subject, "evidence": evidence}
        if kind:
            row["kind"] = kind
        result.append(row)

    for name, app in snapshot["apps"].items():
        sha = app.get("base_sha256")
        if sha in hashes:
            add("Alta", name, f"SHA-256 APK base corrispondente al catalogo ({hashes[sha]['source']}): {sha}",
                "sha256_match")
        for split in app.get("split_apks") or []:
            sha = split["sha256"]
            if sha in hashes:
                filename = split["path"].rsplit("/", 1)[-1]
                add("Alta", name, f"SHA-256 APK split {filename} corrispondente al catalogo "
                    f"({hashes[sha]['source']}): {sha}", "sha256_match")
        item = packages.get(name)
        if item and (item["category"] != "optional_preload" or app["system"] is True):
            add("Inventario", name, f"{item['category']} secondo il catalogo locale: {item['reason']}")
        if app["system"] is False and "accessibilita" in app["special"]:
            sensitive = sorted(set(app["permissions"] or []) & SENSITIVE_COMBINATION)
            evidence = "Servizio di accessibilità abilitato per un'app non di sistema"
            if sensitive:
                evidence += " con permessi concessi: " + ", ".join(sensitive)
            add("Verifica", name, evidence)
        if app["system"] is False and "notifiche" in app["special"]:
            add("Verifica", name, "Accesso alle notifiche abilitato per un'app non di sistema")
    disk = snapshot.get("storage")
    if disk and disk["total_kib"] > 0:
        free = 100 * disk["available_kib"] / disk["total_kib"]
        if free < 10:
            add("Verifica", "/data", f"Spazio disponibile {free:.1f}% (soglia del report 10%)")
    if snapshot["device"].get("verified_boot") in {"orange", "red", "yellow"}:
        add("Verifica", "Verified Boot", "Stato riportato: " + snapshot["device"]["verified_boot"])
    return sorted(result, key=lambda row: (["Alta", "Verifica", "Inventario"].index(row["priority"]), row["subject"]))


def compare(before, after):
    for key in ("schema", "device_id", "user"):
        if before[key] != after[key]:
            raise ValueError("Confronto consentito solo fra snapshot dello stesso dispositivo e profilo.")
    elapsed = (datetime.fromisoformat(after["captured_at"]) -
               datetime.fromisoformat(before["captured_at"])).total_seconds() / 3600
    if elapsed <= 0:
        raise ValueError("Lo snapshot finale deve essere successivo al primo.")
    old, new = before["apps"], after["apps"]
    common = old.keys() & new.keys()
    result = {
        "hours": round(elapsed, 3), "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()), "updated": sorted(
            name for name in common if None not in (old[name]["version"], new[name]["version"])
            and old[name]["version"] != new[name]["version"]),
        "build_changed": before["device"].get("build") != after["device"].get("build"),
        "battery_delta_pp": None, "battery_drop_pp_per_hour": None,
        "screen_on_delta_min": None, "traffic_delta_bytes": None, "energy_delta_mah": None,
    }
    battery_a, battery_b = before.get("battery"), after.get("battery")
    if battery_a and battery_b:
        drop = battery_a["percent"] - battery_b["percent"]
        result["battery_delta_pp"] = round(-drop, 2)
        if battery_a["powered"] is False and battery_b["powered"] is False and drop >= 0:
            result["battery_drop_pp_per_hour"] = round(drop / elapsed, 3)
    a, b = before.get("usage"), after.get("usage")
    if a and b and a["start_ms"] == b["start_ms"] and not result["build_changed"]:
        if a["screen_on_ms"] is not None and b["screen_on_ms"] is not None:
            if b["screen_on_ms"] >= a["screen_on_ms"]:
                result["screen_on_delta_min"] = round((b["screen_on_ms"] - a["screen_on_ms"]) / 60000, 2)
        stable_uids = {str(new[name]["uid"]) for name in common if new[name]["uid"] == old[name]["uid"]}
        changed_uids = {str(old[name]["uid"]) for name in old.keys() - new.keys()}
        changed_uids.update(str(new[name]["uid"]) for name in new.keys() - old.keys())
        for name in common:
            if old[name]["uid"] != new[name]["uid"]:
                changed_uids.update((str(old[name]["uid"]), str(new[name]["uid"])))
        comparable_uids = stable_uids - changed_uids
        for field, output in (("traffic", "traffic_delta_bytes"), ("energy_mah", "energy_delta_mah")):
            left, right = a[field], b[field]
            if left and right and all(right.get(uid, -1) >= val for uid, val in left.items()):
                result[output] = {uid: round(val - left[uid], 5) for uid, val in right.items()
                                  if uid in left and uid in comparable_uids}
    return result
