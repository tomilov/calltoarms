import contextlib
import ctypes
import sys
from collections.abc import Generator


@contextlib.contextmanager
def console() -> Generator[None]:
    if not ctypes.windll.kernel32.AllocConsole():
        raise RuntimeError("Cannot allocate console")
    try:
        sys.stdin = open("CONIN$")  # noqa: SIM115, PTH123
        sys.stdout = open("CONOUT$", "w")  # noqa: SIM115, PTH123
        sys.stderr = open("CONOUT$", "w")  # noqa: SIM115, PTH123
        yield
    finally:
        ctypes.windll.kernel32.FreeConsole()
