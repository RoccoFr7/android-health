import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from android_health.__main__ import main
from android_health.adb import AdbError
from android_health.analysis import compare, findings
from android_health.catalog import AMNESTY, ECHAP, load_local, refresh_malware
from android_health.cleanup import change, history
from android_health.parse import grants, storage
from android_health.preferences import kept_apps, set_kept
from android_health.review import review_rows
from android_health.scan import collect, security_checks

SYSTEM = "com.microsoft.skydrive"
APP = "com.example.monitor"
SHA = "a" * 64


class DemoPhone:
    serial = "demo"

    def __init__(self, executable=None):
        self.later = False

    def select(self, serial):
        pass

    def shell(self, *command):
        if command[:3] == ("pm", "list", "packages"):
            if "-s" in command:
                return f"package:{SYSTEM}\n"
            if "-d" in command:
                return ""
            return (
                f"package:/system/app/OneDrive/OneDrive.apk={SYSTEM} versionCode:21 installer=null uid:10042\n"
                f"package:/data/app/~~a==/com.example.monitor-b==/base.apk={APP} "
                "versionCode:4 installer=com.android.vending uid:10043\n"
                + ("package:/data/app/base.apk=com.example.new versionCode:1 installer=null uid:10044\n"
                   if self.later else "")
            )
        if command[-1] == "package":
            return f"""Packages:
  Package [{APP}] (abcdef):
    User 0: installed=true
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ USER_SET ]
    User 10: installed=true
      runtime permissions:
        android.permission.CAMERA: granted=true
"""
        if command[-1] == "enabled_accessibility_services":
            return f"{APP}/.Service\n"
        if command[-1] == "enabled_notification_listeners":
            return "null\n"
        if command[0] == "getprop":
            return {"ro.product.model": "<script>Demo</script>",
                    "ro.build.version.release": "15", "ro.build.fingerprint": "demo/build"}.get(command[-1], "")
        if command[-1] == "battery":
            return f"USB powered: false\nlevel: {90 if self.later else 98}\nscale: 100\nhealth: 2\n"
        if command[-1] == "/proc/meminfo":
            return "MemTotal: 8000000 kB\nMemAvailable: 4100000 kB\n"
        if command[-1] == "/data":
            return "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/dm 100 95 5 95% /data\n"
        if command[-1] == "meminfo":
            return f"Total PSS by process:\n    12,000K: {APP} (pid 300)\n\nTotal PSS by OOM adjustment:\n"
        if command[-2:] == ("batterystats", "-c"):
            return (
                "9,0,l,bt,1,10000,100,10000,100,1770000000000\n9,0,l,m,0\n"
                f"9,10043,l,nt,0,0,{3000 if self.later else 1000},0\n"
                f"9,10043,l,pwi,uid,{2.25 if self.later else 1.25}\n"
            )
        if command[:2] == ("pm", "path"):
            paths = {
                SYSTEM: "/system/app/OneDrive/OneDrive.apk",
                APP: "/data/app/~~a==/com.example.monitor-b==/base.apk",
                "com.example.new": "/data/app/base.apk",
            }
            base = paths[command[-1]]
            return f"package:{base}\n" + (
                "package:/data/app/~~a==/com.example.monitor-b==/split_config.it.apk\n"
                "package:/data/app/~~a==/com.example.monitor-b==/split_unreadable.apk\n"
                if command[-1] == APP else "")
        if command[0] == "sha256sum":
            if "split_config.it.apk" in command[-1]:
                return f"{'b' * 64}  split_config.it.apk"
            if "split_unreadable.apk" in command[-1]:
                raise AdbError("Permission denied")
            if "monitor" in command[-1]:
                return f"{SHA}  /data/app/base.apk"
            raise AdbError("Permission denied")
        if command == ("am", "get-current-user"):
            return "0\n"
        raise AssertionError(command)


class AndroidHealthTests(unittest.TestCase):
    def test_split_hash_match_visible_for_kept_app_and_partial_coverage(self):
        data = collect(DemoPhone(), hash_apks=True)
        catalog = {"packages": {}, "sha256": {"b" * 64: {"source": "Campione split sintetico"}}}
        checks = security_checks(data, catalog)
        self.assertEqual(
            (checks["hashed_apps"], checks["hashed_splits"], checks["split_apks"], checks["packages_listed"]),
            (1, 1, 2, 2),
        )
        self.assertIn(f"hash split {APP}/split_unreadable.apk", data["unavailable"])
        rows = review_rows(data, findings(data, catalog), (), (APP,))
        self.assertTrue(rows["keep"][0]["pinned"])
        self.assertEqual(rows["security"][0]["level"], "Alta")
        self.assertIn("APK split split_config.it.apk", rows["security"][0]["evidence"])

    def test_public_malware_cache_preserved_and_merged(self):
        samples = f"SHA256,App\n{SHA.upper()},Demo\n".encode()
        novispy = ("b" * 64).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malware.json"
            local = Path(directory) / "local.json"
            local.write_text(json.dumps({"sha256": {SHA: {"source": "Locale"}}}), encoding="utf-8")
            with patch("android_health.catalog.download", side_effect={ECHAP: samples, AMNESTY: novispy}.__getitem__):
                self.assertEqual(refresh_malware(path), 2)
            saved = path.read_bytes()
            with patch("android_health.catalog.download", return_value=b"formato errato"):
                with self.assertRaises(ValueError):
                    refresh_malware(path)
            self.assertEqual(path.read_bytes(), saved)
            merged = load_local(local, local.with_name("uad.json"), path)
            self.assertEqual(merged["sha256"][SHA]["source"], "Locale")
            self.assertIn("NoviSpy", merged["sha256"]["b" * 64]["source"])
            self.assertEqual(merged["public_sha256"], 2)

    def test_always_keep_does_not_hide_security(self):
        gmail = "com.google.android.gm"
        data = collect(DemoPhone())
        data["apps"][gmail] = {**data["apps"][APP], "base_sha256": SHA}
        catalog = {"packages": {gmail: {"category": "utility", "reason": "Test"}},
                   "sha256": {SHA: {"source": "Indicatore sintetico"}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preferences.sqlite3"
            signals = findings(data, {"packages": catalog["packages"]})
            self.assertIn(gmail, {r["name"] for r in review_rows(data, signals, ())["optional"]})
            set_kept(path, data, gmail, True)
            pinned = kept_apps(path, data)
            self.assertEqual(pinned, {gmail})
            self.assertFalse(kept_apps(path, {**data, "user": 10}))
            self.assertFalse(kept_apps(path, {**data, "device_id": "altro"}))
            rows = review_rows(data, findings(data, catalog), (), pinned)
            self.assertNotIn(gmail, {r["name"] for r in rows["optional"]})
            self.assertTrue(next(r for r in rows["keep"] if r["name"] == gmail)["pinned"])
            self.assertEqual(rows["security"][0]["name"], gmail)
            self.assertEqual(rows["security"][0]["level"], "Alta")
            self.assertIn("Indicatore sintetico", rows["security"][0]["evidence"])
            set_kept(path, data, gmail, False)
            self.assertFalse(kept_apps(path, data))

    def test_cleanup_roundtrip_and_stale_version(self):
        class MutablePhone(DemoPhone):
            state = 0
            version = 4

            def shell(self, *args):
                if args[:3] == ("pm", "list", "packages") and args[-1] == APP:
                    return f"package:{APP} versionCode:{self.version}\n"
                if args == ("dumpsys", "package", APP):
                    return f"    User 0: installed=true suspended=false enabled={self.state}\n"
                if args[:2] in (("pm", "disable-user"), ("pm", "default-state")):
                    self.state = 3 if args[1] == "disable-user" else 0
                    return ""
                return super().shell(*args)

        phone = MutablePhone()
        snapshot = collect(phone)
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "journal.json"
            phone.version = 5
            with self.assertRaisesRegex(AdbError, "Versione"):
                change(phone, phone.serial, snapshot, APP, journal)
            self.assertFalse(journal.exists())
            phone.version = 4
            change(phone, phone.serial, snapshot, APP, journal)
            self.assertEqual(phone.state, 3)
            self.assertEqual(list(history(journal).values()), [0])
            change(phone, phone.serial, snapshot, APP, journal, restore=True)
            self.assertEqual(phone.state, 0)
            self.assertEqual(history(journal), {})

    def test_storage_with_vendor_mount_alias(self):
        raw = ("Filesystem 1K-blocks Used Available Use% Mounted on\n"
               "/dev/block/dm-25 483487744 96813712 386542960 21% /storage/emulated/0/Android/obb\n")
        self.assertEqual(storage(raw)["available_kib"], 386542960)

    def test_profile_runtime_permissions(self):
        raw = DemoPhone().shell("dumpsys", "package")
        self.assertEqual(grants(raw, 0), {APP: ["READ_SMS"]})
        self.assertEqual(grants(raw, 10), {APP: ["CAMERA"]})

    def test_scan_and_compare_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "catalog.json"
            catalog.write_text(json.dumps({"sha256": {SHA: {"source": "fixture sintetica"}}}))
            phone = DemoPhone()
            with patch("android_health.__main__.Adb", return_value=phone):
                for stage in ("before", "after"):
                    self.assertEqual(main(["scan", "--catalog", str(catalog), "--out", str(root / stage)]), 0)
                    phone.later = True
            before = root / "before" / "snapshot.json"
            after = root / "after" / "snapshot.json"
            a = json.loads(before.read_text(encoding="utf-8"))
            b = json.loads(after.read_text(encoding="utf-8"))
            a["captured_at"], b["captured_at"] = "2026-11-23T07:00:00+00:00", "2026-11-24T07:00:00+00:00"
            before.write_text(json.dumps(a), encoding="utf-8")
            after.write_text(json.dumps(b), encoding="utf-8")
            self.assertEqual(main(["compare", str(before), str(after), "--catalog", str(catalog),
                                   "--out", str(root / "delta")]), 0)
            result = json.loads((root / "delta" / "confronto.json").read_text(encoding="utf-8"))
            self.assertEqual(result["added"], ["com.example.new"])
            self.assertEqual(result["battery_drop_pp_per_hour"], 0.333)
            self.assertEqual(result["traffic_delta_bytes"], {"10043": 2000})
            self.assertEqual(result["energy_delta_mah"], {"10043": 1.0})
            html = (root / "delta" / "report.html").read_text(encoding="utf-8")
            self.assertIn("SHA-256 APK base", html)
            self.assertIn("&lt;script&gt;Demo&lt;/script&gt;", html)
            self.assertIn(f"hash {SYSTEM}", b["unavailable"])
            self.assertIsNone(b["apps"][SYSTEM]["permissions"])

    def test_counter_reset(self):
        phone = DemoPhone()
        a, b = collect(phone), collect(phone)
        a["captured_at"], b["captured_at"] = "2026-11-23T07:00:00+00:00", "2026-11-24T07:00:00+00:00"
        b["usage"]["start_ms"] += 1000
        self.assertIsNone(compare(a, b)["traffic_delta_bytes"])
