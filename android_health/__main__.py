"""Command line entry point."""
import argparse
import json
from pathlib import Path
import sys

from .adb import Adb, AdbError
from .analysis import compare, findings
from .catalog import load_local
from .report import render
from .scan import collect, security_checks


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def snapshot(path):
    data = load(path)
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError(f"Schema snapshot non supportato: {path}")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Diagnostica Android locale via ADB")
    parser.add_argument("--adb", help="percorso dell'eseguibile ADB")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("devices", help="elenca i dispositivi e lo stato ADB")
    scan = actions.add_parser("scan", help="acquisisce uno snapshot e genera il report")
    scan.add_argument("--serial", help="seriale ADB del dispositivo")
    scan.add_argument("--user", type=int, help="ID profilo Android, predefinito: profilo attivo")
    scan.add_argument("--hash-apks", action="store_true", help="calcola SHA-256 degli APK base e split leggibili")
    report = actions.add_parser("report", help="rigenera un report da uno snapshot")
    report.add_argument("snapshot", type=Path)
    diff = actions.add_parser("compare", help="confronta due snapshot dello stesso telefono")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    for action in (scan, report, diff):
        action.add_argument("--catalog", type=Path, help="catalogo JSON locale")
        action.add_argument("--out", type=Path, required=True, help="nuova cartella di destinazione")
    args = parser.parse_args(argv)

    try:
        if args.action == "devices":
            for serial, state in Adb(args.adb).devices().items():
                print(f"{serial}\t{state}")
            return 0
        if args.out.exists():
            raise ValueError(f"La destinazione esiste già: {args.out}. Scegli una cartella nuova.")
        catalog = load_local(args.catalog or Path(__file__).with_name("catalog.json"))
        delta = None
        if args.action == "scan":
            if args.user is not None and args.user < 0:
                raise ValueError("L'ID profilo deve essere non negativo.")
            adb = Adb(args.adb)
            adb.select(args.serial)
            data = collect(adb, args.user, args.hash_apks or bool(catalog.get("sha256")))
            data["security_checks"] = security_checks(data, catalog)
        elif args.action == "compare":
            data = snapshot(args.after)
            delta = compare(snapshot(args.before), data)
        else:
            data = snapshot(args.snapshot)
        signals = findings(data, catalog)
        html = render(data, signals, delta)
        args.out.mkdir(parents=True)
        (args.out / "report.html").write_text(html, encoding="utf-8")
        name = "confronto.json" if delta is not None else "snapshot.json"
        payload = delta if delta is not None else data
        (args.out / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(args.out / "report.html")
        return 0
    except (AdbError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
