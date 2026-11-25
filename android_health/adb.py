"""ADB transport. All phone-side commands are supplied by the collectors."""
import os
from pathlib import Path
import shutil
import subprocess


class AdbError(RuntimeError):
    pass


class Adb:
    def __init__(self, executable=None):
        sdk = Path(os.environ.get("LOCALAPPDATA", ".")) / "Android/Sdk/platform-tools/adb.exe"
        self.executable = executable or shutil.which("adb") or (str(sdk) if sdk.is_file() else None)
        self.serial = None
        if not self.executable:
            raise AdbError("ADB non trovato. Specifica --adb o aggiungi Platform-Tools al PATH.")

    def run(self, *args, timeout=40):
        command = [self.executable]
        if self.serial:
            command += ["-s", self.serial]
        try:
            result = subprocess.run(command + list(args), capture_output=True,
                                    encoding="utf-8", errors="replace", timeout=timeout,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdbError(f"ADB: {args[0]}: {exc}") from exc
        if result.returncode:
            raise AdbError((result.stderr or result.stdout).strip() or f"ADB: codice {result.returncode}")
        return result.stdout

    def devices(self):
        rows = self.run("devices").splitlines()
        return dict(line.split()[:2] for line in rows[1:] if len(line.split()) >= 2)

    def select(self, serial):
        devices = self.devices()
        if serial is None and len(devices) == 1:
            serial = next(iter(devices))
        if not serial:
            raise AdbError("Collega un dispositivo e autorizza il debug USB. Con più dispositivi usa --serial.")
        if devices.get(serial) != "device":
            raise AdbError(f"Dispositivo {serial}: {devices.get(serial, 'assente')}. Verifica debug USB e autorizzazione.")
        self.serial = serial

    def shell(self, *args):
        output = self.run("shell", *args)
        if any(line.strip().startswith(("Error:", "Exception occurred", "Can't find service:",
                                        "Permission Denial:", "*** SERVICE"))
               for line in output.splitlines()):
            raise AdbError(output.strip().splitlines()[0])
        return output
