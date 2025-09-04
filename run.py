import contextlib
import logging
import sys
import traceback
from types import TracebackType

from calltoarms.gui import main
from calltoarms.util import get_base_path, is_frozen

logger = logging.getLogger(__name__)


def excepthook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_traceback: TracebackType | None,
) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    with (get_base_path() / "exceptionhook.log").open("a", encoding="utf-8") as f:
        print("\nUncaught exception:\n", file=f)
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)


if __name__ == "__main__":
    try:
        import flet_desktop  # type: ignore[import-untyped]

        assert flet_desktop is not None
    except Exception:
        logger.exception("%s", "No flet_desktop package installed")
    if is_frozen():
        sys.excepthook = excepthook
        base_path = get_base_path()
        with (
            (base_path / "stderr.log").open("a") as stderr,
            contextlib.redirect_stderr(stderr),
            (base_path / "stdout.log").open("a") as stdout,
            contextlib.redirect_stdout(stdout),
        ):
            main()
    else:
        main()
