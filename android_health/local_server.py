"""Client for an already running ADB server on the local computer."""
import socket

from .adb import Adb, AdbError


def request(stream, connection, command):
    encoded = command.encode("utf-8")
    connection.sendall(f"{len(encoded):04x}".encode("ascii") + encoded)
    status = stream.read(4)
    if status == b"FAIL":
        detail = stream.read(int(stream.read(4), 16))
        raise AdbError(detail.decode("utf-8", errors="replace"))
    if status != b"OKAY":
        raise AdbError(f"Risposta server ADB incompleta: {status!r}")


class ExistingServer(Adb):
    def __init__(self):
        self.serial = None

    def run(self, *args, timeout=40):
        listing = args == ("devices",)
        try:
            with socket.create_connection(("127.0.0.1", 5037), 2 if listing else timeout) as connection:
                with connection.makefile("rb") as stream:
                    if listing:
                        request(stream, connection, "host:devices")
                        size = int(stream.read(4), 16)
                        return "List of devices attached\n" + stream.read(size).decode("utf-8")
                    if args[0] != "shell" or not self.serial:
                        raise AdbError("Operazione non prevista dal trasporto locale.")
                    request(stream, connection, "host:transport:" + self.serial)
                    request(stream, connection, "shell:" + " ".join(args[1:]))
                    return stream.read().decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            raise AdbError(str(exc)) from exc
