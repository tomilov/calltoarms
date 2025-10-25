import argparse
import asyncio
import json
import logging
import logging.handlers
import sys
from pathlib import Path

import yaml
from tabulate import tabulate

from . import util
from .logging import setup_logging, setup_parser_logging
from .settings import Account, Settings, setup_parser_settings
from .task_manager import TaskManager

logger = logging.getLogger(__name__)


async def _cmd_exe_path_set(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        settings.exe_path = args.exe_path


async def _cmd_set(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        account = settings.find_account(args.alias)
        if account is None:
            account = Account()
            settings.accounts.append(account)
        attrs = Account.model_json_schema()["properties"].keys()
        for attr in attrs:
            setattr(account, attr, getattr(args, attr))


async def _cmd_rm(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        account = settings.remove_account(args.alias)
        if account is None:
            raise RuntimeError(f"There is no account '{args.alias}'")


async def _cmd_ls(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        pass
    if args.format is None:
        attrs = Account.model_json_schema()["properties"].keys()
        headers = ["#"]
        headers.extend(attr.title().replace("_", "") for attr in attrs)
        table = [
            [getattr(account, attr) for attr in attrs] for account in settings.accounts
        ]
        if settings.exe_path is not None:
            print(f"ExePath: {settings.exe_path}")
        print(
            tabulate(table, headers=headers, tablefmt="simple_grid", showindex="always")
        )
        return
    if args.format == "json":
        print(json.dumps(settings.model_dump()))
    elif args.format == "yaml":
        print(yaml.dump(settings.model_dump()))
    else:
        util.raise_assert(f"{args.format}")


async def _cmd_run(args: argparse.Namespace) -> None:
    if args.exe_path is None:
        raise RuntimeError("No exe_path is specified")
    async with TaskManager.run_task_manager() as task_manager:
        await task_manager.run_process(
            token=args.alias,
            args=[str(args.exe_path)],
            login=args.login,
            password=args.password,
            network=args.network,
            fast_relogin=args.fast_relogin,
        )


async def _cmd_load(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        pass
    if settings.exe_path is None:
        raise RuntimeError("There is no executable path")
    account = settings.find_account(args.alias)
    if account is None:
        raise RuntimeError(f"There is no account '{args.alias}'")
    async with TaskManager.run_task_manager() as task_manager:
        await task_manager.run_process(
            token="",
            args=[str(settings.exe_path)],
            login=account.login,
            password=account.password,
            network=account.network,
            fast_relogin=account.fast_relogin,
        )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="calltoarms-cli",
        description="Launches app and enters login and password automatically.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    setup_parser_logging(parser)
    setup_parser_settings(parser)

    async def print_help(_: argparse.Namespace) -> None:
        parser.print_help(sys.stderr)

    parser.set_defaults(command=print_help)
    subparsers = parser.add_subparsers()

    exe_path_parser = argparse.ArgumentParser(add_help=False)
    exe_path_parser.add_argument("exe_path", type=Path, help="Path to executable.")

    exe_path_set_parser = subparsers.add_parser(
        "set-exe-path", parents=[exe_path_parser], help="Set or update account."
    )
    exe_path_set_parser.set_defaults(command=_cmd_exe_path_set)

    alias_parser = argparse.ArgumentParser(add_help=False)
    alias_parser.add_argument("alias", help="Alias of account.")

    credentials_parser = argparse.ArgumentParser(add_help=False)
    credentials_parser.add_argument(
        "--fast-relogin",
        action=argparse.BooleanOptionalAction,
        help="Open restart confirmation dialog on login.",
    )
    credentials_parser.add_argument("login", nargs="?", help="Login.")
    credentials_parser.add_argument("password", nargs="?", help="Password.")
    credentials_parser.add_argument("network", nargs="?", help="Network.")

    set_parser = subparsers.add_parser(
        "set", parents=[alias_parser, credentials_parser], help="Set or update account."
    )
    set_parser.add_argument("comment", nargs="?", help="Comment.")
    set_parser.set_defaults(command=_cmd_set)

    rm_parser = subparsers.add_parser(
        "rm", aliases=["remove"], parents=[alias_parser], help="Remove account."
    )
    rm_parser.set_defaults(command=_cmd_rm)

    ls_parser = subparsers.add_parser("ls", aliases=["list"], help="List all.")
    ls_format_group = ls_parser.add_mutually_exclusive_group()
    ls_format_group.add_argument(
        "-j",
        "--json",
        action="store_const",
        const="json",
        dest="format",
        help="Output in JSON format.",
    )
    ls_format_group.add_argument(
        "-y",
        "--yaml",
        action="store_const",
        const="yaml",
        dest="format",
        help="Output in YAML format.",
    )
    ls_parser.set_defaults(command=_cmd_ls)

    run_parser = subparsers.add_parser(
        "run",
        parents=[exe_path_parser, credentials_parser],
        help="Run executable and login into using credentials"
        " provided on command line.",
    )
    run_parser.set_defaults(command=_cmd_run)

    load_parser = subparsers.add_parser(
        "load",
        parents=[alias_parser],
        help="Run executable and login into using alias.",
    )
    load_parser.set_defaults(command=_cmd_load)

    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    with setup_logging("cli", args.verbosity, args.quiet):
        logger.debug("%s", f"{args = }")
        try:
            asyncio.run(args.command(args))
        except KeyboardInterrupt:
            logger.warning("Interrupted by user")


if __name__ == "__main__":
    main()
