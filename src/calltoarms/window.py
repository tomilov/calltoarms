import asyncio
import logging
import time
from collections.abc import Awaitable
from typing import TYPE_CHECKING, Any

import keyboard
import pyautogui
import pygetwindow as gw  # type: ignore[import-untyped]
import pyscreeze
import win32api
import win32con
import win32gui
import win32process

from . import util

logger = logging.getLogger(__name__)


@util.make_async
def _find_windows_for_pid(pid: int) -> list[gw.Win32Window]:
    def _callback(hwnd: int, windows: list[gw.Win32Window]) -> bool:
        try:
            _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
            if found_pid == pid and win32gui.IsWindowVisible(hwnd):
                window = gw.Win32Window(hwnd)
                windows.append(window)
        except Exception:
            logger.exception("%s", f"Failed to get widnow for PID {pid}")
        return True

    windows: list[gw.Win32Window] = []
    win32gui.EnumWindows(_callback, windows)
    return windows


@util.retry_with_delay
async def find_window_for_pid(pid: int) -> gw.Win32Window | None:
    try:
        for window in await _find_windows_for_pid(pid):
            return window
        logger.warning("%s", f"There is no window for {pid = } yet")
    except gw.PyGetWindowException as e:
        logger.warning("%s", f"PyGetWindowException for {pid = }: {e}")
    return None


@util.make_async
def find_region(
    image_name: str, region: tuple[int, int, int, int], *, confidence: float
) -> pyscreeze.Point | None:
    logger.info("%s", f"Try to find image {image_name} in the window")
    try:
        image = util.get_image(image_name)
        image_location = pyautogui.locateCenterOnScreen(
            image, region=region, confidence=confidence
        )
        if image_location is not None:
            logger.info(
                "%s", f"'{image_name}' found at {image_location} in region {region}"
            )
            pyautogui.moveTo(image_location)
        else:
            logger.debug("%s", f"Image '{image_name}' is not found in region {region}")
    except pyautogui.ImageNotFoundException as e:
        logger.warning(
            "%s", f"Image {image_name} is not found in the region {region}: {e}"
        )
        return None
    except FileNotFoundError:
        logger.exception("%s", f"Error: Cannot find image file {image_name}")
        raise
    else:
        return image_location


@util.make_async
def click(*, delay: float) -> None:
    pyautogui.mouseDown()
    time.sleep(delay)
    pyautogui.mouseUp()


async def find_and_click_region(
    image_name: str,
    region: tuple[int, int, int, int],
    *,
    confidence: float,
    delay: float,
) -> pyscreeze.Point | None:
    location = await find_region(image_name, region, confidence=confidence)
    if location is not None:
        await click(delay=delay)
    return location


class Window:
    def __init__(self, window: gw.Win32Window):
        self.window = window
        self.login_event = asyncio.Event()

    def get_window_region(self) -> tuple[int, int, int, int]:
        return (
            self.window.left,
            self.window.top,
            self.window.width,
            self.window.height,
        )

    @util.make_async
    def _modify_window_style(
        self, *, add_styles: int = 0, remove_styles: int = 0
    ) -> None:
        hwnd: int = self.window._hWnd  # noqa: SLF001
        current_style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
        new_style = (current_style & ~remove_styles) | add_styles
        if new_style == current_style:
            logger.info("Window style is already as desired.")
            return
        logger.info("%s", f"Updating style for HWND {hwnd}...")
        win32gui.SetWindowLong(hwnd, win32con.GWL_STYLE, new_style)
        flags = (
            win32con.SWP_FRAMECHANGED
            | win32con.SWP_NOMOVE
            | win32con.SWP_NOSIZE
            | win32con.SWP_NOZORDER
        )
        win32gui.SetWindowPos(hwnd, 0, 0, 0, 0, 0, flags)
        logger.info("Style updated successfully.")

    def prevent_maximizing(self) -> Awaitable[None]:
        return self._modify_window_style(remove_styles=win32con.WS_MAXIMIZEBOX)

    def allow_maximizing(self) -> Awaitable[None]:
        return self._modify_window_style(add_styles=win32con.WS_MAXIMIZEBOX)

    @util.make_async
    def resize_window_to_work_area(self) -> None:
        hwnd: int = self.window._hWnd  # noqa: SLF001
        monitor_info = win32api.GetMonitorInfo(
            win32api.MonitorFromWindow(hwnd, win32con.MONITOR_DEFAULTTONEAREST)
        )
        work_area = monitor_info["Work"]
        x, y = work_area[:2]
        width = work_area[2] - x
        height = work_area[3] - y
        win32gui.MoveWindow(hwnd, x, y, width, height, True)

    async def bring_window_to_front(self) -> None:
        if self.window.isMinimized:
            await asyncio.to_thread(self.window.restore)
            await asyncio.sleep(0.1)
        await asyncio.to_thread(self.window.activate)
        await asyncio.sleep(0.1)
        await self.resize_window_to_work_area()
        await self.prevent_maximizing()

    def make_topmost_and_focus(self) -> bool:
        hwnd: int = self.window._hWnd  # noqa: SLF001
        assert win32gui.IsWindow(hwnd)
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        else:
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
        flags = win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
        win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, flags)
        try:
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetForegroundWindow(hwnd)
            win32gui.SetActiveWindow(hwnd)
        except win32gui.error:
            logger.exception("%s", "Failed to make window topmost")
        return win32gui.GetForegroundWindow() == hwnd

    def is_top_level_window(self) -> bool:
        is_active = self.window.isActive
        if TYPE_CHECKING:
            assert isinstance(is_active, bool)
        return is_active

    async def _track_login_conditions(self) -> None:
        while self.window.isActive:
            try:
                await asyncio.wait_for(self.login_event.wait(), timeout=0.1)
            except TimeoutError:
                logger.debug("%s", f"Window '{self.window.title}' focus is not lost")
            else:
                return
        raise RuntimeError(f"Window '{self.window.title}' focus is lost")

    @util.retry_with_delay
    async def find_image(
        self, image_name: str, *, confidence: float
    ) -> pyscreeze.Point | None:
        return await find_region(
            image_name, self.get_window_region(), confidence=confidence
        )

    @util.retry_with_delay
    async def find_and_click_image(
        self, image_name: str, *, confidence: float, delay: float
    ) -> pyscreeze.Point | None:
        return await find_and_click_region(
            image_name, self.get_window_region(), confidence=confidence, delay=delay
        )

    async def type_in_field(
        self,
        image_name: str,
        text_to_type: str,
        *,
        confidence: float,
        timeout: float,
        delay: float,
    ) -> None:
        await self.find_and_click_image(
            image_name, confidence=confidence, timeout=timeout, delay=delay
        )
        await asyncio.sleep(delay)
        for letter in text_to_type:
            while util.is_modifier_pressed():
                logger.warning("Modifier key pressed")
                await asyncio.sleep(delay)
            keyboard.write(letter)

    async def _do_login_steps(
        self, login: str | None, password: str | None, *, fast_relogin: bool | None
    ) -> None:
        if not login:
            logger.info(
                "%s", "Login is not provided or empty. Login sequence terminated"
            )
            return
        params: dict[str, Any] = {"confidence": 0.8, "timeout": 7.0, "delay": 0.1}
        await self.type_in_field("id_field", login, **params)
        if not password:
            logger.info(
                "%s", "Password is not provided or empty. Login sequence terminated"
            )
            return
        await self.type_in_field("password_field", password, **params)
        await self.find_and_click_image("login_button", **params)
        await self.find_and_click_image("agree_button", **params)
        await self.find_and_click_image("confirm_button", **params)
        await self.find_and_click_image("start_button", **params)
        if fast_relogin is True:
            await self.find_and_click_image("system_menu_button", **params)
            await self.find_and_click_image("restart_button", **params)
            await self.find_image("confirm_button", **params)

    async def login(
        self, login: str | None, password: str | None, *, fast_relogin: bool | None
    ) -> bool:
        try:
            async with asyncio.TaskGroup() as tg:
                login_conditions_task = tg.create_task(
                    self._track_login_conditions(), name="login_conditions"
                )
                login_conditions_task.add_done_callback(
                    lambda _: self.login_event.clear()
                )
                login_steps_task = tg.create_task(
                    self._do_login_steps(login, password, fast_relogin=fast_relogin),
                    name="login_steps",
                )
                login_steps_task.add_done_callback(lambda _: self.login_event.set())
        except* Exception as eg:
            for ex in eg.exceptions:
                logger.exception(
                    "%s", f"Failed to login to the window '{self.window.title}': {ex}"
                )
        else:
            return True
        return False


@util.retry_with_delay
async def wait_process_window(pid: int, signature_image: str) -> Window | None:
    try:
        window = Window(await find_window_for_pid(pid, timeout=5, delay=0.1))
        await window.bring_window_to_front()
        if (
            await window.find_image(
                signature_image, confidence=0.8, timeout=1, delay=0.1
            )
            is not None
        ):
            return window
    except gw.PyGetWindowException:
        logger.warning("%s", "PyGetWindowException")
    except TimeoutError:
        logger.warning("%s", "Timeout")
    return None
