"""Local HTML report, with device-provided strings escaped."""
from html import escape
from collections import defaultdict


def cell(value):
    if value is None:
        return "n.d."
    if isinstance(value, bool):
        return "sì" if value else "no"
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "—"
    return str(value)


def table(headers, rows):
    head = "".join(f"<th scope='col'>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(cell(v))}</td>" for v in row) + "</tr>" for row in rows)
    return f"<div class='scroll'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def mib(kib):
    return f"{kib / 1024:,.1f} MiB"


def render(snapshot, findings, diff=None):
    apps = snapshot["apps"]
    device = snapshot["device"]
    uid_apps = defaultdict(list)
    for name, app in sorted(apps.items()):
        if app["uid"] is not None:
            uid_apps[str(app["uid"])].append(name)

    def uid_table(values, label):
        if not values:
            return "<p>Dati per UID assenti o non confrontabili.</p>"
        return table(["UID", "Pacchetti associati", label],
                     ((uid, uid_apps[uid], value)
                      for uid, value in sorted(values.items(), key=lambda pair: -pair[1])))

    captions = [
        ("Pacchetti nel profilo", len(apps)),
        ("Pacchetti di sistema", sum(app["system"] is True for app in apps.values())
         if all(app["system"] is not None for app in apps.values()) else None),
        ("Android", device.get("android")), ("Patch", device.get("patch")),
        ("Profilo", snapshot["user"]), ("Acquisizione UTC", snapshot["captured_at"]),
    ]
    for section, fields in (
        ("battery", {"percent": "Carica (%)", "temperature_c": "Temperatura batteria (°C)",
                     "health_code": "Stato batteria (codice Android, 2 = buono)", "powered": "Alimentazione collegata"}),
        ("memory", {"available_kib": "RAM disponibile", "total_kib": "RAM totale"}),
        ("storage", {"available_kib": "Spazio disponibile per /data", "total_kib": "Capacità del filesystem di /data",
                     "reported_mount": "Mount indicato da df"}),
    ):
        data = snapshot.get(section) or {}
        for key, label in fields.items():
            value = data.get(key)
            captions.append((label, mib(value) if value is not None and key.endswith("_kib") else value))

    model = " ".join(device.get(key) or "" for key in ("brand", "model")).strip() or "Dispositivo Android"
    sections = [
        f"<h1>{escape(model)}</h1>", "<h2>Stato del dispositivo</h2>", table(["Misura", "Valore"], captions),
        "<h2>Segnalazioni</h2><p>I permessi e gli accessi speciali possono avere usi legittimi. "
        "Le corrispondenze SHA-256 dipendono dalla copertura e dalla qualità del catalogo scelto.</p>",
        table(["Priorità", "Pacchetto o risorsa", "Evidenza"],
              ((f["priority"], f["subject"], f["evidence"]) for f in findings)) if findings
        else "<p>Nessuna segnalazione con le regole e i dati disponibili.</p>",
    ]
    if checks := snapshot.get("security_checks"):
        coverage = (f"Indicatori SHA-256: {checks['indicators']} · "
                    f"APK base verificati: {checks['hashed_apps']} su {len(apps)}.")
        if "split_apks" in checks:
            coverage += (f" APK split verificati: {checks['hashed_splits']} su {checks['split_apks']} rilevati."
                         f" Elenco degli APK disponibile per {checks['packages_listed']} su {len(apps)} pacchetti.")
        sections.insert(3, "<p>" + escape(coverage) + "</p>")
    if diff is not None:
        sections += [
            "<h2>Confronto tra acquisizioni</h2><p>Il tasso di scarica è indicativo. "
            "Le due letture ai capi dell’intervallo non certificano l’assenza di ricariche intermedie.</p>",
            table(["Misura", "Valore"], [
                ("Ore trascorse", diff["hours"]), ("Variazione carica (punti percentuali)", diff["battery_delta_pp"]),
                ("Calo di carica (punti percentuali/ora)", diff["battery_drop_pp_per_hour"]),
                ("Incremento del tempo a schermo acceso a batteria (min)", diff["screen_on_delta_min"]),
                ("Build modificata", diff["build_changed"]), ("Pacchetti comparsi", diff["added"]),
                ("Pacchetti scomparsi", diff["removed"]), ("Versioni cambiate", diff["updated"]),
            ]),
            "<h3>Traffico registrato da Android nell’intervallo</h3>", uid_table(diff["traffic_delta_bytes"], "Byte"),
            "<h3>Energia stimata nell’intervallo</h3>", uid_table(diff["energy_delta_mah"], "mAh"),
        ]
    usage = snapshot.get("usage") or {}
    sections += [
        "<h2>Attività registrata da Android</h2><p>Contatori cumulativi batterystats, "
        "inclusi Wi-Fi e rete mobile. Gli UID condivisi possono aggregare più pacchetti.</p>",
        "<h3>Traffico</h3>", uid_table(usage.get("traffic"), "Byte"),
        "<h3>Energia stimata</h3>", uid_table(usage.get("energy_mah"), "mAh"),
        "<h2>Processi per RAM PSS</h2><p>Misura istantanea, comprensiva della quota proporzionale di memoria condivisa.</p>",
        table(["Processo", "PID", "RAM PSS"],
              ((p["process"], p["pid"], mib(p["pss_kib"])) for p in snapshot["processes"]))
        if snapshot.get("processes") else "<p>Dati PSS indisponibili.</p>",
        "<h2>Inventario pacchetti</h2>",
        table(["Pacchetto", "Sistema", "Disabilitato", "Installatore", "Versione", "UID",
               "Permessi runtime sensibili", "Accessi speciali rilevati"],
              ((name, app["system"], app["disabled"], app["installer"], app["version"], app["uid"],
                app["permissions"], app["special"]) for name, app in sorted(apps.items()))),
        "<h2>Rilevazioni incomplete</h2>",
        table(["Rilevazione", "Motivo"], snapshot["unavailable"].items())
        if snapshot["unavailable"] else "<p>Nessun errore di acquisizione registrato.</p>",
    ]
    return """<!doctype html><html lang="it"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnostica Android</title>
<style>
body{margin:0;background:#f2f5f7;color:#182b38;font:16px system-ui,sans-serif}
main{max-width:78rem;margin:auto;padding:clamp(1rem,4vw,3rem)}
h1{font-size:clamp(2rem,5vw,3.5rem);margin-top:0}
h2{margin-top:2.5rem} p{max-width:76ch;line-height:1.55}
.scroll{overflow:auto;border:1px solid #cad6db;border-radius:.55rem;background:#fff}
table{width:100%;border-collapse:collapse;font-size:.91rem;text-align:left}
th,td{padding:.65rem .85rem;border-bottom:1px solid #dfe7eb;overflow-wrap:anywhere}
th{background:#e2ecee} tr:last-child td{border-bottom:0} tr:nth-child(even){background:#f8fafb}
</style><main>""" + "\n".join(sections) + "</main></html>"
