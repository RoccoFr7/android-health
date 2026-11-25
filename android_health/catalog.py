"""Fetch the public UAD-ng package list and cache conservative review entries."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen
from http.client import HTTPException
import sys

from .analysis import validate_catalog

SOURCE = ("https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
          "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json")
MAX_BYTES = 8 * 1024 * 1024
CACHE = Path(__file__).resolve().parent.parent / "catalogo-online.json"
MALWARE_CACHE = CACHE.with_name("indicatori-malware.json")
ECHAP = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv"
AMNESTY = ("https://raw.githubusercontent.com/AmnestyTech/investigations/master/"
           "2024-12-16_serbia_novispy/sha256.txt")
FETCH_ERRORS = (OSError, ValueError, HTTPException)


def convert(raw):
    if not isinstance(raw, dict):
        raise ValueError("Formato UAD-ng inatteso.")
    packages = {}
    for name, item in raw.items():
        if not isinstance(item, dict) or item.get("removal") != "Recommended":
            continue
        description = item.get("description")
        if isinstance(description, str) and description.strip():
            packages[name] = {
                "category": "optional_preload",
                "reason": "UAD-ng (Recommended). " + description.strip(),
            }
    if not packages:
        raise ValueError("Nessuna voce Recommended utilizzabile nel catalogo UAD-ng.")
    result = {"packages": packages, "sha256": {}, "source": SOURCE,
              "fetched_at": datetime.now(timezone.utc).isoformat()}
    validate_catalog(result)
    return result


def download(url):
    with urlopen(url, timeout=8) as response:
        if response.geturl() != url:
            raise ValueError("La fonte del catalogo ha restituito un URL inatteso.")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Catalogo troppo grande.")
    return raw


def save_cache(path, catalog):
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", delete=False) as stream:
            temp = Path(stream.name)
            json.dump(catalog, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temp.replace(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def refresh(path):
    catalog = convert(json.loads(download(SOURCE)))
    save_cache(path, catalog)
    return len(catalog["packages"])


def malware_indicators(echap, amnesty):
    rows = csv.DictReader(echap.splitlines())
    if not rows.fieldnames or not {"SHA256", "App"} <= set(rows.fieldnames):
        raise ValueError("Formato del catalogo Echap inatteso.")
    hashes = {}
    digest = re.compile(r"[0-9a-f]{64}")
    for row in rows:
        sha = (row["SHA256"] or "").strip().lower()
        app = (row["App"] or "").strip()
        if digest.fullmatch(sha) and app:
            hashes[sha] = {"source": f"Echap · dataset stalkerware e watchware · {app} ({ECHAP})"}
    novispy = {line.strip().lower() for line in amnesty.splitlines() if line.strip()}
    if not hashes or not novispy or any(not digest.fullmatch(sha) for sha in novispy):
        raise ValueError("Catalogo indicatori incompleto o non valido.")
    for sha in novispy:
        hashes[sha] = {"source": f"Amnesty International Security Lab · NoviSpy ({AMNESTY})"}
    return hashes


def refresh_malware(path=MALWARE_CACHE):
    hashes = malware_indicators(download(ECHAP).decode("utf-8-sig"), download(AMNESTY).decode("utf-8-sig"))
    data = {"sha256": hashes, "sources": [ECHAP, AMNESTY],
            "fetched_at": datetime.now(timezone.utc).isoformat()}
    validate_catalog(data)
    save_cache(path, data)
    return len(hashes)


def load_local(path, cache=CACHE, malware_cache=MALWARE_CACHE):
    local = json.loads(path.read_text(encoding="utf-8-sig"))
    packages, hashes = validate_catalog(local)
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        online, _ = validate_catalog(cached)
        if cached.get("source") != SOURCE or any(
                item["category"] != "optional_preload" for item in online.values()):
            online = {}
    except (OSError, ValueError):
        online = {}
    try:
        cached = json.loads(malware_cache.read_text(encoding="utf-8"))
        _, public_hashes = validate_catalog(cached)
        if cached.get("sources") != [ECHAP, AMNESTY]:
            public_hashes = {}
    except (OSError, ValueError):
        public_hashes = {}
    return {"packages": online | packages, "sha256": public_hashes | hashes,
            "public_sha256": len(public_hashes)}


def main():
    parser = argparse.ArgumentParser(description="Scarica il catalogo pubblico UAD-ng per Android Health.")
    parser.add_argument("--out", type=Path, default=CACHE, help="file JSON di destinazione")
    parser.add_argument("--malware", action="store_true", help="aggiorna gli indicatori Echap e Amnesty")
    args = parser.parse_args()
    try:
        path = MALWARE_CACHE if args.malware and args.out == CACHE else args.out
        count = refresh_malware(path) if args.malware else refresh(path)
        print(f"{count} voci salvate in {path}")
    except FETCH_ERRORS as exc:
        print(f"Aggiornamento non riuscito. {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
