import asyncio
import contextlib
import logging
import subprocess
from collections.abc import AsyncGenerator, Callable, Coroutine
from functools import wraps
from typing import TYPE_CHECKING, Any

from . import util
from .network import get_interfaces
from .process import Debugger
from .window import wait_process_window

if TYPE_CHECKING:
    from .window import Window

logger = logging.getLogger(__name__)


def _taskgroup_task[T, **P](
    f: Callable[P, Coroutine[None, None, T]],
) -> Callable[P, asyncio.Task[T]]:
    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> asyncio.Task[T]:
        if TYPE_CHECKING:
            assert len(args) > 0
            assert hasattr(args[0], "tg")
            assert isinstance(args[0].tg, asyncio.TaskGroup)
        task = args[0].tg.create_task(f(*args, **kwargs), name=f.__name__)
        task.add_done_callback(lambda t: logger.info("Done: %s", f"{t.get_name()}"))
        return task

    return wrapper


def _null_callback(progres: str) -> None:
    pass


class TaskManager:
    def __init__(
        self,
        tg: asyncio.TaskGroup,
        stop_event: asyncio.Event,
        stop_event_task: asyncio.Task[Any],
        debugger: Debugger,
    ) -> None:
        self.tg: asyncio.TaskGroup = tg
        self.stop_event: asyncio.Event = stop_event
        self.stop_event_task: asyncio.Task[Any] = stop_event_task
        self.debugger: Debugger = debugger
        self.lock: asyncio.Lock = asyncio.Lock()
        self.processes: dict[str, subprocess.Popen[str]] = {}
        self.windows: dict[str, Window] = {}
        self.login_semaphore: asyncio.Semaphore = (
            asyncio.Semaphore()
        )  # the only process can work with pyautogui

    @contextlib.asynccontextmanager
    async def _run_process(
        self, token: str, args: list[str], *, if_index: int | None = None
    ) -> AsyncGenerator[subprocess.Popen[str]]:
        process: subprocess.Popen[str]
        async with util.make_asynccontextmanager(
            self.debugger.run_process(token, args, if_index=if_index)
        ) as process:
            yield process
            process_task = self.tg.create_task(
                asyncio.to_thread(process.wait), name=f"wait {token}"
            )
            try:
                _, pending = await asyncio.wait(
                    (process_task, self.stop_event_task),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if self.stop_event.is_set():
                    for task in pending:
                        task.cancel()
                    await asyncio.wait(pending)
                else:
                    logger.info(
                        "%s", f"Subprocess exited with code {process_task.result()}"
                    )
            finally:
                process_task.cancel()
                try:
                    await process_task
                except asyncio.CancelledError:
                    print("cancelled")

    @_taskgroup_task
    async def run_process(  # noqa: PLR0913
        self,
        *,
        token: str,
        args: list[str],
        login: str | None,
        password: str | None,
        network: str | None,
        fast_relogin: bool | None,
        callback: Callable[[str], None] = _null_callback,
    ) -> None:
        if_index = None
        for interface in get_interfaces():
            if interface.ipv4 == network:
                if_index = interface.if_index
                break
        try:
            callback("process_created")
            async with (
                self.login_semaphore,
                self._run_process(token, args, if_index=if_index) as process,
            ):
                async with self.lock:
                    self.processes[token] = process
                callback("process_started")
                window = await wait_process_window(
                    process.pid, "id_field", timeout=20.0, delay=0.1
                )
                async with self.lock:
                    self.windows[token] = window
                callback("window_appeared")
                cm = (
                    util.make_asynccontextmanager(self.debugger.debug(process))
                    if if_index is not None
                    else contextlib.nullcontext()
                )
                async with cm:
                    if await window.login(login, password, fast_relogin=fast_relogin):
                        callback("login_succeeded")
                    else:
                        callback("login_failed")
                self.login_semaphore.release()
        finally:
            callback("process_exited")
            async with self.lock:
                self.windows.pop(token, None)
                self.processes.pop(token, None)

    async def resize_window_to_work_area(self) -> None:
        async with self.lock:
            for window in self.windows.values():
                if window.is_top_level_window():
                    break
            else:
                return
        await window.resize_window_to_work_area()

    async def make_topmost_and_focus(self, token: str) -> None:
        async with self.lock:
            window = self.windows.get(token)
        if window is not None:
            await window.bring_window_to_front()

    @classmethod
    @contextlib.asynccontextmanager
    async def run_task_manager(cls) -> AsyncGenerator["TaskManager"]:
        async with asyncio.TaskGroup() as tg:
            with Debugger.run_debugger() as debugger:
                stop_event: asyncio.Event = asyncio.Event()
                stop_event_task = tg.create_task(stop_event.wait())
                try:
                    yield cls(tg, stop_event, stop_event_task, debugger)
                finally:
                    stop_event.set()
