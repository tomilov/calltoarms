import argparse
import contextlib
import logging
import logging.handlers
from collections.abc import Generator

from . import console, util


def setup_parser_logging(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        dest="verbosity",
        help="Increase logging verbosity (-v for INFO, -vv for DEBUG).",
    )
    parser.add_argument(
        "--quiet",
        action=argparse.BooleanOptionalAction,
        default=util.is_frozen(),
        help="Suppress console (stderr) logging.",
    )


@contextlib.contextmanager
def setup_logging(app_name: str, verbosity: int, quiet: bool) -> Generator[None]:
    log_levels: dict[int, int] = {0: logging.WARNING, 1: logging.INFO}
    level = log_levels.get(verbosity, logging.DEBUG)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    log_file = util.get_base_path() / f"{app_name}.log"
    file_handler = logging.handlers.TimedRotatingFileHandler(log_file, when="midnight")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    if quiet:
        yield
    else:
        with console.console() if util.is_frozen() else contextlib.nullcontext():
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            root_logger.addHandler(stream_handler)
            yield
