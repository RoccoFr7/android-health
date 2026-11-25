"""Translate catalog evidence into review decisions for the desktop UI."""

# Standalone apps and optional, user-facing features. Exact IDs matter because
# adjacent packages can implement shared services rather than the feature itself.
OPTIONAL = {
    "com.google.android.apps.docs": ("Google Drive", "Se non apri o sincronizzi file con Drive."),
    "com.google.android.apps.maps": ("Google Maps", "Se usi un’altra app per mappe e navigazione."),
    "com.google.android.apps.photos": ("Google Foto", "Se non usi Google Foto per il backup o la gestione delle immagini."),
    "com.google.android.apps.tachyon": ("Google Meet", "Se non usi Meet per le videochiamate."),
    "com.google.android.apps.youtube.music": ("YouTube Music", "Se non ascolti musica con questa app."),
    "com.google.android.gm": ("Gmail", "Se leggi la posta con un’altra app."),
    "com.google.android.videos": ("Google TV", "Se non guardi contenuti con Google TV sul telefono."),
    "com.google.android.youtube": ("YouTube", "Se non usi l’app YouTube."),
    "com.hihonor.android.instantshare": ("HONOR Share", "Se non trasferisci file tramite HONOR Share."),
    "com.hihonor.android.mirrorshare": ("Proiezione schermo HONOR", "Se non proietti lo schermo su TV o monitor."),
    "com.hihonor.compass": ("Bussola HONOR", "Se non usi l’app Bussola."),
    "com.hihonor.soundrecorder": ("Registratore HONOR", "Se non usi l’app per registrare o consultare audio."),
    "com.hihonor.videoeditor": ("Editor video HONOR", "Se non modifichi video con l’editor integrato."),
    "com.microsoft.appmanager": ("Collegamento a Windows", "Se non usi Collegamento al telefono sul PC."),
    "com.microsoft.skydrive": ("Microsoft OneDrive", "Se non sincronizzi file o foto con OneDrive."),
}

KEEP = {
    "com.qualcomm.location": ("Localizzazione Qualcomm", "Può contribuire ai servizi di localizzazione del dispositivo."),
    "com.google.android.apps.restore": ("Ripristino Google", "Serve alla procedura di ripristino da un backup Google."),
    "com.google.android.adservices.api": ("API AdServices", "Fa parte dei componenti AdServices di Android."),
    "com.google.mainline.adservices": ("AdServices", "Fa parte dei componenti AdServices aggiornabili di Android."),
    "com.hihonor.securitypluginbase": ("Sicurezza HONOR", "Le dipendenze dai servizi di sicurezza HONOR richiedono verifica."),
    "com.hihonor.trustcircle": ("Autenticazione HONOR", "Le dipendenze dall’account e dai servizi HONOR richiedono verifica."),
}


def review_rows(data, signals, restored, always_keep=()):
    apps = data["apps"]
    pss = {}
    for process in data.get("processes") or []:
        name = process["process"].split(":", 1)[0]
        pss[name] = pss.get(name, 0) + process["pss_kib"]

    rows = {key: [] for key in ("optional", "keep", "security", "restore")}
    always_keep = set(always_keep)

    def append(key, name, title, reason, evidence, **fields):
        rows[key].append({
            "name": name, "title": title, "reason": reason, "evidence": evidence,
            "pss_mib": round(pss[name] / 1024) if name in pss else None,
            **fields,
        })

    inventory = {}
    alerts = {}
    for signal in signals:
        target = inventory if signal["priority"] == "Inventario" else alerts
        target.setdefault(signal["subject"], []).append(signal)

    def title_for(name):
        return OPTIONAL.get(name, KEEP.get(name, (name, "")))[0]

    for name, items in alerts.items():
        match = any(item.get("kind") == "sha256_match" for item in items)
        high = any(item["priority"] == "Alta" for item in items)
        reason = ("L’impronta dell’APK coincide con un indicatore locale. Verifica la fonte."
                  if match else "Controlla l’evidenza e verifica se l’accesso o lo stato è previsto.")
        if name in always_keep:
            reason += " Hai scelto Tieni sempre per questa app."
        if name in apps and apps[name]["disabled"] is True:
            reason += " App già disattivata."
        append("security", name, title_for(name), reason,
               "\n\n".join(item["evidence"] for item in items),
               level="Alta" if high else "Da verificare",
               actionable=match and name in apps and apps[name]["disabled"] is False and name not in restored)

    for name in set(inventory) | set(restored) | always_keep:
        if name not in apps:
            continue
        title = title_for(name)
        detail = "\n\n".join(item["evidence"] for item in inventory.get(name, ()))
        if name in restored:
            append("restore", name, title, "Ripristina lo stato registrato prima dell’intervento.", "")
        if name in always_keep:
            append("keep", name, title, "Tieni sempre è attivo per questa app.", detail, pinned=True)
            continue
        if (name in restored or apps[name]["disabled"] is not False or name not in inventory
                or any(item.get("kind") == "sha256_match" for item in alerts.get(name, ()))):
            continue
        if name in OPTIONAL:
            append("optional", name, title, OPTIONAL[name][1], detail)
        elif detail.startswith(("bloatware secondo il catalogo locale:", "utility secondo il catalogo locale:")):
            append("optional", name, title, "Voce del tuo catalogo. Verifica di non usare le funzioni associate.", detail)
        else:
            reason = KEEP.get(name, (name, "Tieni attivo finché non hai verificato funzione e dipendenze su questo modello."))[1]
            append("keep", name, title, reason, detail)

    for group in ("optional", "keep", "restore"):
        rows[group].sort(key=lambda row: (not row.get("pinned", False), -(row["pss_mib"] or 0), row["title"].casefold()))
    rows["security"].sort(key=lambda row: (row["level"] != "Alta", row["title"].casefold()))
    return rows
