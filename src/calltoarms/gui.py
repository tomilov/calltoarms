import argparse
import asyncio
import dataclasses
import logging
from pathlib import Path

import flet as ft  # type: ignore[import-untyped]

from . import network, util
from .logging import setup_logging, setup_parser_logging
from .process import is_32bit_executable
from .settings import Account, Settings, setup_parser_settings
from .task_manager import TaskManager

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class RowData:
    row_index: ft.Text | None = None
    checkbox: ft.Checkbox | None = None
    networks: ft.DropdownM2 | None = None


class CallToArmsApp:
    def __init__(
        self, args: argparse.Namespace, settings: Settings, task_manager: TaskManager
    ):
        self.args = args
        self.settings = settings
        self.task_manager = task_manager
        self.interfaces: list[network.Interface] = []

    def on_keyboard_event(self, e: ft.KeyboardEvent) -> None:
        if e.ctrl and e.key == "S" and not e.shift and not e.alt and not e.meta:
            self.settings.save()

    def get_network_dd_opts(self) -> list[ft.dropdownm2.Option]:
        options = [
            ft.dropdownm2.Option(key="", content=ft.Text("Do not force", no_wrap=True))
        ]
        options.extend(
            ft.dropdownm2.Option(
                key=interface.ipv4, content=ft.Text(interface.ipv4, no_wrap=True)
            )
            for interface in self.interfaces
        )
        return options

    def build(self, page: ft.Page) -> None:  # noqa: C901, PLR0915
        networks = ft.DataTable(
            columns=[ft.DataColumn(ft.Text("#"), numeric=True)], sort_column_index=0
        )
        networks.columns.extend(
            ft.DataColumn(ft.Text(field.name.title().replace("_", "")))
            for field in dataclasses.fields(network.Interface)
        )

        def get_exe_path_error_text(exe_path: Path | None) -> str | None:
            if not exe_path:
                return "File is not specified"
            if not exe_path.is_file():
                return f"'{exe_path}' is not a file"
            if not is_32bit_executable(exe_path):
                return f"'{exe_path}' is not a 32-bit executable"
            return None

        def set_exe_path(control: ft.Control, exe_path: str | None) -> None:
            self.settings.exe_path = Path(exe_path) if exe_path else None
            control.error_text = get_exe_path_error_text(self.settings.exe_path)
            control.update()

        exe_path_text_field = ft.TextField(
            label="ExePath",
            value=self.settings.exe_path,
            on_change=lambda ev: set_exe_path(ev.control, ev.data),
            error_text=get_exe_path_error_text(self.settings.exe_path),
            expand=True,
        )

        def on_result(ev: ft.FilePickerResultEvent) -> None:
            if ev.files is None:
                return
            for file in ev.files:
                exe_path_text_field.value = file.path
                set_exe_path(exe_path_text_field, file.path)
                break

        file_picker = ft.FilePicker(on_result=on_result)

        def pick_file() -> None:
            initial_directory = None
            exe_path = self.settings.exe_path
            if exe_path and exe_path.is_file():
                initial_directory = exe_path.parent
            file_picker.pick_files(
                dialog_title="Pick executable file",
                initial_directory=initial_directory,
                file_type=ft.FilePickerFileType.ANY,
                allowed_extensions=["exe"],
            )

        exe_path_button = ft.IconButton(
            ft.Icons.FILE_OPEN,
            icon_color=ft.Colors.GREY,
            on_click=lambda _: pick_file(),
        )

        accounts = ft.DataTable(
            columns=[ft.DataColumn(ft.Text("#"), numeric=True)], sort_column_index=0
        )
        check_all = ft.Checkbox()
        accounts.columns.append(ft.DataColumn(check_all))
        accounts.columns.append(ft.DataColumn(ft.Text("Run")))
        attrs = Account.model_json_schema()["properties"].keys()
        accounts.columns.extend(
            ft.DataColumn(ft.Text(attr.title().replace("_", ""))) for attr in attrs
        )

        token: int = 0

        def add_account(row_index: int, account: Account) -> None:  # noqa: PLR0915, C901
            row_data = RowData(
                row_index=ft.Text(row_index),
                checkbox=ft.Checkbox(),
            )

            run_button = ft.IconButton(
                icon=ft.Icons.PLAY_CIRCLE, icon_color=ft.Colors.GREEN, tooltip="Run"
            )

            async def run() -> None:
                exe_path = self.settings.exe_path
                if not exe_path:
                    return
                if not exe_path.is_file():
                    return

                def update_run_button_state(progress: str) -> None:
                    run_button.disabled = progress == "process_created"
                    if progress == "process_created":
                        pass
                    elif progress == "process_started":
                        run_button.icon = ft.Icons.STOP_CIRCLE
                        run_button.icon_color = ft.Colors.YELLOW
                        run_button.tooltip = "Stop"
                    elif progress == "window_appeared":
                        pass
                    elif progress in ("login_failed", "login_succeeded"):
                        run_button.icon_color = ft.Colors.BLUE
                    elif progress == "process_exited":
                        run_button.icon = ft.Icons.PLAY_CIRCLE
                        run_button.icon_color = ft.Colors.GREEN
                        run_button.tooltip = "Run"
                        run_button.on_click = lambda _: page.run_task(run)
                    else:
                        util.raise_assert(f"{progress = }")
                    run_button.update()

                nonlocal token
                process_task = self.task_manager.run_process(
                    token=f"{token}",
                    args=[str(exe_path)],
                    login=account.login,
                    network=account.network,
                    password=account.password,
                    fast_relogin=account.fast_relogin,
                    callback=update_run_button_state,
                )
                token += 1
                run_button.on_click = lambda _: process_task.cancel()
                try:
                    await process_task
                except asyncio.CancelledError:
                    logger.info("%s", "Process task cancelled")

            run_button.on_click = lambda _: page.run_task(run)
            row = ft.DataRow(
                cells=[
                    ft.DataCell(row_data.row_index),
                    ft.DataCell(row_data.checkbox),
                    ft.DataCell(run_button),
                ],
                data=row_data,
            )
            colors: list[ft.Color] = [
                color for color in list(ft.Colors) if color.name.isalpha()
            ]
            for attr in attrs:
                value = getattr(account, attr)
                control: ft.Control
                if attr == "fast_relogin":
                    control = ft.Checkbox(value=value)
                elif attr == "network":
                    control = ft.DropdownM2(
                        value=value, options=self.get_network_dd_opts()
                    )
                    row_data.networks = control
                elif attr == "color":
                    options = [
                        ft.dropdownm2.Option(
                            key=color.value,
                            content=ft.Row(
                                controls=[
                                    ft.Icon(name=ft.Icons.CIRCLE, color=color),
                                    ft.Text(
                                        color.value
                                        if color.value != ft.Colors.SURFACE
                                        else "",
                                        no_wrap=True,
                                    ),
                                ]
                            ),
                        )
                        for color in colors
                    ]
                    row.color = value
                    control = ft.DropdownM2(value=value, options=options)
                else:
                    control = ft.TextField()
                    if attr == "password":
                        control.password = True
                        control.can_reveal_password = True
                    elif attr == "login":
                        control.max_length = 16
                    control.value = value

                def on_attr_change(
                    ev: ft.ControlEvent, account: Account = account, attr: str = attr
                ) -> None:
                    value = ev.control.value
                    if attr == "color":
                        if value == ft.Colors.SURFACE:
                            value = None
                        row.color = value
                        row.update()
                    elif attr == "network":
                        if value.startswith("_"):
                            value = None
                    elif value == "":
                        value = None
                    setattr(account, attr, value)

                control.on_change = on_attr_change
                control.expand = True
                row.cells.append(ft.DataCell(control))
            assert row_data.networks is not None
            accounts.rows.append(row)

        def do_check_all() -> None:
            for row in accounts.rows:
                row.data.checkbox.value = check_all.value
            accounts.update()

        check_all.on_change = lambda _: do_check_all()

        for row_index, account in enumerate(self.settings.accounts):
            add_account(row_index, account)

        def add_new_account() -> None:
            account = Account()
            add_account(len(self.settings.accounts), account)
            self.settings.accounts.append(account)
            accounts.update()

        confirm_delete_dlg = ft.AlertDialog(
            title=ft.Text("Please confirm"),
            content=ft.Text("Do you really want to delete all those accounts?"),
        )

        pagelet = ft.Pagelet(content=accounts)

        def on_delete(_: ft.ControlEvent) -> None:
            indices = [
                i for i, row in enumerate(accounts.rows) if not row.data.checkbox.value
            ]
            accounts.rows = [accounts.rows[i] for i in indices]
            self.settings.accounts = [self.settings.accounts[i] for i in indices]
            for i, row in enumerate(accounts.rows):
                row.data.row_index.value = i
            accounts.update()
            page.close(confirm_delete_dlg)

        confirm_delete_dlg.actions = [
            ft.TextButton("Yes", on_click=on_delete),
            ft.TextButton("No", on_click=lambda _: page.close(confirm_delete_dlg)),
        ]

        def partition_accounts() -> None:
            indices = sorted(
                range(len(accounts.rows)),
                key=lambda i: not accounts.rows[i].data.checkbox.value,
            )
            accounts.rows = [accounts.rows[i] for i in indices]
            self.settings.accounts = [self.settings.accounts[i] for i in indices]
            for i, row in enumerate(accounts.rows):
                row.data.row_index.value = i
            accounts.update()

        pagelet.appbar = ft.AppBar(
            automatically_imply_leading=False,
            actions=[
                ft.IconButton(
                    icon=ft.Icons.ARROW_UPWARD,
                    tooltip="Move up",
                    on_click=lambda _: partition_accounts(),
                ),
                ft.IconButton(
                    icon=ft.Icons.ADD,
                    icon_color=ft.Colors.GREEN,
                    tooltip="Add account",
                    on_click=lambda _: add_new_account(),
                ),
                ft.IconButton(
                    ft.Icons.DELETE,
                    icon_color=ft.Colors.RED,
                    tooltip="Delete selected accounts",
                    on_click=lambda _: page.open(confirm_delete_dlg),
                ),
            ],
        )

        def update_networks() -> None:
            networks.rows.clear()
            for i, interface in enumerate(self.interfaces):
                cells = [ft.DataCell(ft.Text(i))]
                cells.extend(
                    ft.DataCell(ft.Text(getattr(interface, field.name)))
                    for field in dataclasses.fields(interface)
                )
                networks.rows.append(ft.DataRow(cells=cells))
            networks.update()
            for row in accounts.rows:
                row.data.networks.options = self.get_network_dd_opts()
            accounts.update()

        def toggle_theme_mode(control: ft.Control) -> None:
            is_init = False
            if page.theme_mode == ft.ThemeMode.LIGHT:
                page.theme_mode = ft.ThemeMode.DARK
            elif page.theme_mode == ft.ThemeMode.DARK:
                page.theme_mode = ft.ThemeMode.LIGHT
            elif page.theme_mode == ft.ThemeMode.SYSTEM:
                is_init = True
                if page.platform_brightness == ft.Brightness.LIGHT:
                    page.theme_mode = ft.ThemeMode.LIGHT
                elif page.platform_brightness == ft.Brightness.DARK:
                    page.theme_mode = ft.ThemeMode.DARK
                else:
                    util.raise_assert(f"{page.platform_brightness = }")
            else:
                util.raise_assert(f"{page.theme_mode = }")
            control.icon = (
                ft.Icons.LIGHT_MODE
                if page.theme_mode == ft.ThemeMode.DARK
                else ft.Icons.DARK_MODE
            )
            control.icon_color = (
                ft.Colors.WHITE
                if page.theme_mode == ft.ThemeMode.DARK
                else ft.Colors.BLACK
            )
            if not is_init:
                page.update()

        theme_mode_btn = ft.IconButton(
            tooltip="Theme mode", on_click=lambda ev: toggle_theme_mode(ev.control)
        )
        toggle_theme_mode(theme_mode_btn)

        page.appbar = ft.AppBar(
            automatically_imply_leading=False, actions=[theme_mode_btn]
        )

        tabs = ft.Tabs(expand=1)

        def add_tab(icon: str, name: str, *controls: ft.Control) -> None:
            tabs.tabs.append(
                ft.Tab(
                    tab_content=ft.Row(
                        controls=[ft.Icon(name=icon), ft.Text(name, size=18)]
                    ),
                    content=ft.Column(controls=controls),
                )
            )

        add_tab(ft.Icons.SWITCH_ACCOUNT, "Accounts", pagelet)
        add_tab(ft.Icons.SETTINGS_ETHERNET, "Networks", networks)
        add_tab(
            ft.Icons.SETTINGS,
            "Settings",
            ft.Row(controls=[exe_path_button, exe_path_text_field]),
        )
        page.add(tabs)

        def on_window_event(ev: ft.WindowEvent) -> None:
            if ev.data == "close":
                self.settings.windowleft = page.window.left
                self.settings.windowtop = page.window.top
                self.settings.windowwidth = page.window.width
                self.settings.windowheight = page.window.height
                page.window.destroy()

        page.window.prevent_close = True
        page.window.on_event = on_window_event

        page.window.left = self.settings.windowleft
        page.window.top = self.settings.windowtop
        page.window.width = self.settings.windowwidth
        page.window.height = self.settings.windowheight

        page.window.to_front()

        async def update_page() -> None:
            while True:
                interfaces = sorted(await asyncio.to_thread(network.get_interfaces))
                if interfaces != self.interfaces:
                    self.interfaces = interfaces
                    update_networks()
                await asyncio.sleep(0.1)

        page.title = "Call to Arms"
        page.scroll = ft.ScrollMode.ADAPTIVE
        page.on_keyboard_event = self.on_keyboard_event
        page.overlay.append(file_picker)
        page.run_task(update_page)
        page.update()


async def main_async(args: argparse.Namespace) -> None:
    with Settings.get_settings(args.config, timeout=0.1) as settings:
        async with (
            TaskManager.run_task_manager() as task_manager,
            util.run_hotkey_listener(
                "shift+esc", task_manager.resize_window_to_work_area
            ),
        ):
            app = CallToArmsApp(args, settings, task_manager)
            await ft.app_async(app.build, name="calltoarms-gui")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="calltoarms-gui",
        description="Launches apps and changes its states.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    setup_parser_logging(parser)
    setup_parser_settings(parser)
    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    with setup_logging("gui", args.verbosity, args.quiet):
        asyncio.run(main_async(args))


if __name__ == "main":
    main()
