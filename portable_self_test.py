from pathlib import Path
from unittest.mock import patch
import tkinter as tk

from android_health.adb import AdbError
from android_health.gui import Application, transport

root = tk.Tk()
root.withdraw()
app = Application(root)
root.update_idletasks()
assert not app.start.instate(["!disabled"])
with patch("android_health.gui.ExistingServer.devices", side_effect=AdbError("test")):
    adb = transport(None)
assert Path(adb.executable).resolve() == Path("platform-tools/adb.exe").resolve()
assert "Android Debug Bridge" in adb.run("version")
root.destroy()
