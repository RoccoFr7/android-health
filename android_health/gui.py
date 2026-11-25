"""Desktop launcher for local USB scans."""
from datetime import datetime
import json
from pathlib import Path
from queue import Empty, Queue
from sqlite3 import Error as PreferenceError
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .adb import Adb, AdbError
from .analysis import findings
from .catalog import CACHE, FETCH_ERRORS, load_local, refresh, refresh_malware
from .cleanup import change, history
from .local_server import ExistingServer
from .preferences import kept_apps, set_kept
from .report import render
from .review import review_rows
from .scan import collect, security_checks


def transport(executable):
    if executable:
        return Adb(executable)
    server = ExistingServer()
    try:
        server.devices()
    except AdbError:
        bundled = Path(__file__).resolve().parent.parent / "platform-tools" / "adb.exe"
        return Adb(str(bundled) if bundled.is_file() else None)
    return server


def scan_phone(adb, serial, destination, catalog_path):
    adb.select(serial)
    catalog = load_local(catalog_path)
    data = collect(adb, hash_apks=bool(catalog.get("sha256")))
    data["security_checks"] = security_checks(data, catalog)
    signals = findings(data, catalog)
    html = render(data, signals)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    folder = destination / stamp
    folder.mkdir(parents=True)
    (folder / "snapshot.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = folder / "report.html"
    report.write_text(html, encoding="utf-8")
    return data, signals, report


class Application:
    def __init__(self, root):
        self.root = root
        self.results = Queue()
        self.report = None
        self.latest = None
        self.scanned_serial = None
        self.adb_path = None
        self.destination = Path(__file__).resolve().parent.parent / "scansioni"
        self.journal = self.destination.parent / "ripristino-app.json"
        self.preferences = self.destination.parent / "preferenze-app.sqlite3"
        self.catalog = Path(__file__).with_name("catalog.json")
        self.auto_catalog = tk.BooleanVar(value=False)

        root.title("Android Health")
        root.geometry("860x660")
        root.minsize(680, 560)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background="#edf2f7", foreground="#14263a")
        style.configure("TButton", padding=(13, 8))
        style.configure("Primary.TButton", background="#145bca", foreground="white", padding=(17, 8))
        style.map("Primary.TButton", background=[("disabled", "#e0e7ef"), ("active", "#104aab")],
                  foreground=[("disabled", "#63768b")])
        style.configure("Card.TFrame", background="white")
        style.configure("Card.TLabel", background="white")
        style.configure("Metric.TLabel", background="white", font=("Segoe UI", 17, "bold"))
        style.configure("Treeview", rowheight=32, background="white", fieldbackground="white")
        style.configure("TNotebook.Tab", padding=(12, 8))
        style.configure("Horizontal.TProgressbar", thickness=5, background="#145bca")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main = ttk.Frame(root, padding=24)
        main.grid(sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(7, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, sticky="ew", pady=(0, 18))
        ttk.Label(header, text="Android Health", font=("Segoe UI", 25, "bold")).pack(side="left")
        self.settings_toggle = ttk.Button(header, text="Impostazioni", command=self.toggle_settings)
        self.settings_toggle.pack(side="right")

        toolbar = ttk.Frame(main)
        toolbar.grid(row=1, sticky="ew")
        toolbar.columnconfigure(0, weight=1)
        self.devices = ttk.Combobox(toolbar, state="readonly")
        self.devices.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.devices.bind("<<ComboboxSelected>>", lambda _: self.update_buttons())
        self.refresh = ttk.Button(toolbar, text="Rileva telefoni", command=self.detect)
        self.refresh.grid(row=0, column=1, padx=(0, 8))
        self.start = ttk.Button(toolbar, text="Scansiona", command=self.scan, style="Primary.TButton")
        self.start.grid(row=0, column=2)

        settings = self.settings = ttk.Frame(main)
        settings.grid(row=2, sticky="w", pady=(10, 0))
        self.options = [
            ttk.Button(settings, text="Scegli ADB…", command=self.choose_adb),
            ttk.Button(settings, text="Scegli cartella…", command=self.choose_folder),
            ttk.Button(settings, text="Scegli catalogo…", command=self.choose_catalog),
            ttk.Button(settings, text="Aggiorna catalogo online", command=self.fetch_catalog),
            ttk.Button(settings, text="Aggiorna indicatori malware", command=self.fetch_malware),
        ]
        for index, button in enumerate(self.options):
            row, column = divmod(index, 3)
            button.grid(row=row, column=column, sticky="w", padx=(0, 8), pady=(0, 4))
        self.auto_option = ttk.Checkbutton(settings, text="Aggiorna i cataloghi prima di ogni scansione",
                                           variable=self.auto_catalog)
        self.auto_option.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))
        settings.grid_remove()

        self.status = tk.StringVar(value="In attesa di un telefono.")
        ttk.Label(main, textvariable=self.status, wraplength=610).grid(row=3, sticky="ew", pady=(12, 4))
        self.progress = ttk.Progressbar(main, mode="determinate", value=0)
        self.progress.grid(row=4, sticky="ew", pady=(0, 16))

        self.phone_title = tk.StringVar(value="Riepilogo dispositivo")
        ttk.Label(main, textvariable=self.phone_title, font=("Segoe UI", 15, "bold")).grid(row=5, sticky="w")
        metrics = ttk.Frame(main)
        metrics.grid(row=6, sticky="ew", pady=(8, 12))
        self.metrics = {}
        for column, title in enumerate(("Batteria", "RAM libera", "Spazio libero", "Pacchetti")):
            metrics.columnconfigure(column, weight=1, uniform="metric")
            card = ttk.Frame(metrics, style="Card.TFrame", padding=10)
            card.grid(row=0, column=column, sticky="ew", padx=(0, 7 if column < 3 else 0))
            ttk.Label(card, text=title, style="Card.TLabel").pack(anchor="w")
            value = tk.StringVar(value="—")
            ttk.Label(card, textvariable=value, style="Metric.TLabel").pack(anchor="w")
            self.metrics[title] = value

        panel = ttk.Frame(main)
        panel.grid(row=7, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(0, weight=1)
        self.summary = tk.Text(panel, wrap="word", font=("Segoe UI", 11), padx=14, pady=12,
                               relief="flat", background="white", foreground="#14263a")
        self.summary.insert("1.0", "Collega il telefono via USB e autorizza il debug. Premi Scansiona per iniziare.")
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=self.summary.yview)
        self.summary.configure(yscrollcommand=scrollbar.set, state="disabled")
        self.summary.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        actions = ttk.Frame(main)
        actions.grid(row=8, sticky="e", pady=(12, 0))
        self.open_report = ttk.Button(actions, text="Apri report", command=self.open)
        self.open_report.pack(side="left", padx=(0, 8))
        self.cleanup = ttk.Button(actions, text="Ripulisci…", command=self.review_cleanup)
        self.cleanup.pack(side="left", padx=(0, 8))
        self.security = ttk.Button(actions, text="Sicurezza", command=lambda: self.review_cleanup("security"))
        self.security.pack(side="left")
        self.busy = False
        self.inventory = []
        self.update_buttons()
        root.after(100, self.poll)
        root.after_idle(self.detect)

    def toggle_settings(self):
        if self.settings.winfo_manager():
            self.settings.grid_remove()
        else:
            self.settings.grid()

    def update_buttons(self):
        index = self.devices.current()
        ready = 0 <= index < len(self.inventory) and self.inventory[index][1] == "device"
        self.start.configure(state="normal" if ready and not self.busy else "disabled")
        self.open_report.configure(state="normal" if self.report else "disabled")
        same_phone = ready and self.inventory[index][0] == self.scanned_serial
        self.cleanup.configure(state="normal" if same_phone and self.latest and not self.busy else "disabled")
        self.security.configure(state="normal" if self.latest and not self.busy else "disabled")
        self.devices.configure(state="disabled" if self.busy else "readonly")
        for button in [self.refresh, self.auto_option, *self.options]:
            button.configure(state="disabled" if self.busy else "normal")

    def run(self, message, operation, callback):
        self.busy = True
        self.status.set(message)
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(12)
        self.update_buttons()

        def worker():
            try:
                self.results.put((callback, operation(), None))
            except Exception as exc:
                self.results.put((callback, None, str(exc)))

        Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            callback, value, error = self.results.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            if error:
                self.status.set("Errore. " + error)
            else:
                callback(value)
            self.update_buttons()
        self.root.after(100, self.poll)

    def detect(self):
        self.inventory = []
        self.devices.set("")
        self.devices.configure(values=[])
        self.run("Ricerca dei dispositivi ADB…", lambda: transport(self.adb_path).devices(), self.show_devices)

    def show_devices(self, devices):
        self.inventory = list(devices.items())
        labels = [f"{serial}  ·  {state}" for serial, state in self.inventory]
        self.devices.configure(values=labels)
        authorized = [i for i, (_, state) in enumerate(self.inventory) if state == "device"]
        if authorized:
            self.devices.current(authorized[0])
            self.status.set("Telefono pronto. La scansione avviene in sola lettura.")
        elif labels:
            self.devices.current(0)
            self.status.set("Sblocca il telefono, autorizza il debug USB e premi Rileva telefoni.")
        else:
            self.status.set("Nessun telefono rilevato. Controlla il cavo e il debug USB, poi riprova.")

    def scan(self):
        serial = self.inventory[self.devices.current()][0]
        auto = self.auto_catalog.get()

        def collect_result():
            notes = []
            if auto:
                for label, update in (("UAD-ng", lambda: refresh(CACHE)), ("Indicatori malware", refresh_malware)):
                    try:
                        notes.append(f"{label}: {update()} voci aggiornate.")
                    except FETCH_ERRORS:
                        notes.append(f"{label}: aggiornamento non riuscito. Uso della copia locale disponibile.")
            return scan_phone(transport(self.adb_path), serial, self.destination, self.catalog), " ".join(notes)

        def complete(result):
            scan, note = result
            self.show_result(scan, serial)
            if note:
                self.status.set(self.status.get() + " " + note)

        status = ("Aggiornamento catalogo e scansione USB in corso…" if auto else
                  "Scansione in corso. Mantieni il telefono collegato…")
        self.run(status, collect_result, complete)

    def fetch_catalog(self):
        self.run("Download del catalogo pubblico UAD-ng…", lambda: refresh(CACHE),
                 lambda count: self.status.set(
                     f"Catalogo aggiornato ({count} voci). Verrà usato dalla prossima scansione."))

    def fetch_malware(self):
        self.run("Download degli indicatori SHA-256 di Echap e Amnesty…", refresh_malware,
                 lambda count: self.status.set(
                     f"{count} indicatori SHA-256 aggiornati. Premi Scansiona per verificarli sul telefono."))

    def show_result(self, result, serial):
        data, signals, self.report = result
        self.latest = (data, signals)
        self.scanned_serial = serial
        device, apps = data["device"], data["apps"]
        name = " ".join(device[key] for key in ("brand", "model") if device.get(key))
        system_count = (sum(a["system"] is True for a in apps.values())
                        if all(a["system"] is not None for a in apps.values()) else "n.d.")
        self.phone_title.set(f"{name or 'Android'}  ·  Android {device.get('android') or 'n.d.'}")
        battery = data.get("battery")
        self.metrics["Batteria"].set(f"{battery['percent']:g}%" if battery else "n.d.")
        self.metrics["Pacchetti"].set(str(len(apps)))
        for key, title in (("memory", "RAM libera"), ("storage", "Spazio libero")):
            meter = data.get(key)
            self.metrics[title].set(f"{meter['available_kib'] / 1048576:.1f} GiB" if meter else "n.d.")
        lines = [f"Patch di sicurezza {device.get('patch') or 'n.d.'}   ·   {system_count} pacchetti di sistema"]
        if processes := data.get("processes"):
            lines += ["", "Processi con più RAM PSS"] + [
                f"{row['process']}  ·  {row['pss_kib'] / 1024:.0f} MiB" for row in processes[:5]]
        alerts = review_rows(data, signals, ())["security"]
        count_high = sum(row["level"] == "Alta" for row in alerts)
        label = (f"Sicurezza ({count_high} alta)" if count_high else
                 f"Sicurezza ({len(alerts)})" if alerts else "Sicurezza")
        self.security.configure(text=label)
        if alerts:
            lines += ["", f"Sicurezza: {count_high} ad alta priorità · {len(alerts) - count_high} da verificare."]
        if data["unavailable"]:
            lines += ["", "Dati incompleti: " + ", ".join(data["unavailable"])]
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("1.0", "\n".join(lines))
        self.summary.configure(state="disabled")
        self.status.set("Scansione completata. Report e snapshot salvati.")

    def review_cleanup(self, initial="optional"):
        data, signals = self.latest
        serial = self.scanned_serial
        prefix = f"{data['device_id']}/{data['user']}/"
        try:
            saved = {key.removeprefix(prefix) for key in history(self.journal) if key.startswith(prefix)}
            pinned = kept_apps(self.preferences, data)
        except (OSError, ValueError, PreferenceError) as exc:
            messagebox.showerror("Ripulisci", f"Preferenze o registro di ripristino illeggibili. {exc}", parent=self.root)
            return
        rows = review_rows(data, signals, saved, pinned)
        dialog = tk.Toplevel(self.root)
        dialog.title("Ripulisci")
        dialog.geometry(f"720x535+{max(0, self.root.winfo_rootx() + 35)}+{max(0, self.root.winfo_rooty() + 24)}")
        dialog.minsize(590, 470)
        dialog.transient(self.root)
        dialog.grab_set()
        panel = ttk.Frame(dialog, padding=20)
        panel.pack(fill="both", expand=True)
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(2, weight=1)
        title = tk.StringVar(value="Ripulisci")
        subtitle = tk.StringVar()
        ttk.Label(panel, textvariable=title, font=("Segoe UI", 21, "bold")).grid(row=0, sticky="w")
        ttk.Label(panel, textvariable=subtitle, wraplength=540).grid(row=1, sticky="w", pady=(4, 12))
        tabs = ttk.Notebook(panel)
        tabs.grid(row=2, sticky="nsew")
        groups = ("optional", "keep", "security", "restore")
        labels = ("Disattiva se non usi", "Tieni", "Sicurezza", "Ripristina")
        empty = ("Nessuna app da valutare. Puoi aggiornare il catalogo in Impostazioni e ripetere la scansione.",
                 "Nessun componente da tenere tra le voci del catalogo.",
                 "Nessuna segnalazione con i controlli disponibili nella scansione.",
                 "Nessun intervento da ripristinare per questo profilo.")
        tables = {}
        for group, label in zip(groups, labels):
            page = ttk.Frame(tabs, padding=6)
            tabs.add(page, text=f"{label}  ({len(rows[group])})")
            table = ttk.Treeview(page, columns=("app", "ram"), show="headings", selectmode="browse", height=7)
            table.heading("app", text="App o pacchetto")
            table.heading("ram", text="Priorità" if group == "security" else "RAM PSS")
            table.column("app", width=440)
            table.column("ram", width=105, stretch=False, anchor="e")
            scroll = ttk.Scrollbar(page, orient="vertical", command=table.yview)
            table.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            table.pack(side="left", fill="both", expand=True)
            table.tag_configure("high", foreground="#9b2635")
            tables[group] = table

        def populate():
            for index, (group, label) in enumerate(zip(groups, labels)):
                table = tables[group]
                selection = table.selection()
                table.delete(*table.get_children())
                tabs.tab(index, text=f"{label} ({len(rows[group])})")
                for row in rows[group]:
                    value = row.get("level") or (f"{row['pss_mib']} MiB" if row["pss_mib"] is not None else "—")
                    label = row["title"] + (" · Tieni sempre" if row.get("pinned") else "")
                    table.insert("", "end", iid=row["name"], values=(label, value),
                                 tags=("high",) if row.get("level") == "Alta" else ())
                if selection and table.exists(selection[0]):
                    table.selection_set(selection[0])

        detail_frame = ttk.Frame(panel)
        detail_frame.grid(row=3, sticky="ew", pady=(12, 8))
        detail = tk.Text(detail_frame, height=5, wrap="word", font=("Segoe UI", 10),
                         relief="flat", padx=10, pady=6, background="white", foreground="#14263a")
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=detail.yview)
        detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side="right", fill="y")
        detail.pack(side="left", fill="x", expand=True)

        actions = ttk.Frame(panel)
        actions.grid(row=4, sticky="ew")
        ttk.Button(actions, text="Chiudi", command=dialog.destroy).pack(side="right")

        def selected_row():
            index = tabs.index("current")
            group = groups[index]
            selection = tables[group].selection()
            row = next((item for item in rows[group] if selection and item["name"] == selection[0]), None)
            return group, row, index

        def can_apply(group, row):
            return (row and dict(self.inventory).get(serial) == "device"
                    and (group in {"optional", "restore"} or
                         (group == "security" and row.get("actionable"))))

        def apply():
            group, row, _ = selected_row()
            if not can_apply(group, row):
                return
            name, restore = row["name"], group == "restore"
            verb = "Ripristina" if restore else "Disattiva"
            message = f"{verb} {row['title']} nel profilo {data['user']}?\n\n{row['reason']}"
            if group == "security":
                message += "\n\n" + row["evidence"]
            if not restore:
                message += "\n\nI dati dell’app restano sul telefono. Le funzioni legate all’app potrebbero fermarsi."
                if data["apps"][name]["system"]:
                    message += "\nAndroid classifica questo pacchetto come app di sistema."
            if not messagebox.askyesno(verb, message, parent=dialog, default="no"):
                return
            dialog.destroy()

            def complete(status):
                data["apps"][name]["disabled"] = not restore
                self.status.set(status + " Esegui una nuova scansione per aggiornare il report.")

            self.run(f"{verb} {name}…",
                     lambda: change(transport(self.adb_path), serial, data, name, self.journal, restore),
                     complete)

        action = ttk.Button(actions, text="Disattiva…", command=apply, style="Primary.TButton")

        def change_preference():
            group, row, _ = selected_row()
            if not row or (group != "optional" and not (group == "keep" and row.get("pinned"))):
                return
            name = row["name"]
            keep = group == "optional"
            try:
                set_kept(self.preferences, data, name, keep)
            except (OSError, ValueError, PreferenceError) as exc:
                messagebox.showerror("Tieni sempre", str(exc), parent=dialog)
                return
            preference_status.set(f"{row['title']}: " +
                                  ("preferenza salvata." if keep else "preferenza rimossa."))
            if keep:
                pinned.add(name)
            else:
                pinned.discard(name)
            rows.update(review_rows(data, signals, saved, pinned))
            populate()
            describe()

        preference = ttk.Button(actions, text="Tieni sempre", command=change_preference)
        preference_status = tk.StringVar()
        ttk.Label(actions, textvariable=preference_status, wraplength=245).pack(side="left")
        checks = data.get("security_checks") or {}

        def describe(_=None):
            group, row, index = selected_row()
            if group == "security":
                title.set("Sicurezza")
                if checks.get("indicators"):
                    coverage = (f"Indicatori SHA-256: {checks['indicators']} "
                                f"({checks.get('public_indicators', 0)} pubblici)\n"
                                f"APK base: {checks['hashed_apps']} su {len(data['apps'])}")
                    if "split_apks" in checks:
                        coverage += f" · APK split: {checks['hashed_splits']} su {checks['split_apks']} rilevati"
                        missed = len(data["apps"]) - checks["packages_listed"]
                        if missed:
                            coverage += f"\nElenco degli split indisponibile per {missed} pacchetti."
                    subtitle.set(coverage)
                else:
                    subtitle.set("Nessun indicatore SHA-256 nel catalogo. "
                                 "Sono visibili le altre segnalazioni della scansione.")
            else:
                title.set("Ripulisci")
                subtitle.set("La disattivazione interviene su un’app alla volta e conserva APK e dati.")
            message = empty[index] if not rows[group] else "Seleziona una voce per vedere il motivo."
            if row:
                message = f"{row['name']}\n{row['reason']}"
                if row["evidence"]:
                    message += "\n\n" + row["evidence"]
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            detail.insert("1.0", message)
            detail.configure(state="disabled")
            action.pack_forget()
            preference.pack_forget()
            if group in {"optional", "restore"} or can_apply(group, row):
                action.configure(text="Ripristina…" if group == "restore" else "Disattiva…",
                                 state="normal" if can_apply(group, row) else "disabled")
                action.pack(side="right", padx=(0, 8))
            if group == "optional" or (group == "keep" and row and row.get("pinned")):
                preference.configure(text="Annulla Tieni sempre" if group == "keep" else "Tieni sempre",
                                     state="normal" if row else "disabled")
                preference.pack(side="right", padx=(0, 8))

        for table in tables.values():
            table.bind("<<TreeviewSelect>>", describe)
        tabs.bind("<<NotebookTabChanged>>", describe)
        dialog.bind("<Escape>", lambda _: dialog.destroy())
        populate()
        tabs.enable_traversal()
        tabs.select(groups.index(initial))
        table = tables[initial]
        if children := table.get_children():
            table.selection_set(children[0])
            table.focus(children[0])
        table.focus_set()
        describe()

    def open(self):
        if self.report and not webbrowser.open(self.report.resolve().as_uri()):
            self.status.set(f"Apri il file nel browser: {self.report}")

    def choose_adb(self):
        if path := filedialog.askopenfilename(title="Seleziona l’eseguibile ADB"):
            self.adb_path = path
            self.detect()

    def choose_folder(self):
        if path := filedialog.askdirectory(title="Cartella per le scansioni"):
            self.destination = Path(path)
            self.status.set(f"Destinazione: {path}")

    def choose_catalog(self):
        if path := filedialog.askopenfilename(title="Catalogo locale", filetypes=[("Catalogo JSON", "*.json")]):
            self.catalog = Path(path)
            self.status.set(f"Catalogo: {self.catalog.name}")


def main():
    root = tk.Tk()
    Application(root)
    root.mainloop()


if __name__ == "__main__":
    main()
