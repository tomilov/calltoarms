import asyncio
import contextlib
import ctypes
import io
import logging
import sys
import time
import types
from collections.abc import AsyncGenerator, Awaitable, Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from functools import cache, partial, wraps
from importlib.resources import read_binary
from inspect import signature
from pathlib import Path
from typing import TYPE_CHECKING, Any, overload

import keyboard
import win32api
import win32con
from PIL import Image
from PIL.ImageFile import ImageFile
from tenacity import RetryCallState

logger = logging.getLogger(__name__)


def is_frozen() -> bool:
    frozen = getattr(sys, "frozen", False)
    if TYPE_CHECKING:
        assert isinstance(frozen, bool)
    return frozen


def get_base_path() -> Path:
    if is_frozen():
        return Path(sys.argv[0]).parent
    return Path(__file__).parent.parent.parent


def make_async[T, **P](f: Callable[P, T]) -> Callable[P, Awaitable[T]]:
    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Awaitable[T]:
        return asyncio.to_thread(f, *args, **kwargs)

    return wrapper


@overload
def retry_with_delay[T](
    f: Callable[..., Awaitable[T | None]],
) -> Callable[..., Awaitable[T]]: ...


@overload
def retry_with_delay(*, timeout: float, delay: float) -> AsyncGenerator[None]: ...


def retry_with_delay[T, **P](  # noqa: C901
    f: Callable[P, Awaitable[T | None]] | None = None,
    *,
    timeout: float | None = None,
    delay: float | None = None,
) -> Any:
    if callable(f):

        @wraps(f)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            params = signature(f).parameters
            t = kwargs["timeout"] if "timeout" in params else kwargs.pop("timeout")
            if TYPE_CHECKING:
                assert isinstance(t, (float, int)), f"{type(t)}"
            d = kwargs["delay"] if "delay" in params else kwargs.pop("delay")
            if TYPE_CHECKING:
                assert isinstance(d, (float, int))
            deadline = time.monotonic() + t
            while time.monotonic() < deadline:
                if (res := await f(*args, **kwargs)) is not None:
                    return res
                if deadline - time.monotonic() <= d:
                    break
                await asyncio.sleep(d)
            raise TimeoutError

        return wrapper

    if timeout is not None and delay is not None:

        async def gen() -> AsyncGenerator[None]:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                yield
                if deadline - time.monotonic() <= delay:
                    break
                await asyncio.sleep(delay)
            raise TimeoutError

        return gen()

    raise TypeError("Invalid use of retry_with_delay")


@contextlib.asynccontextmanager
async def run_hotkey_listener[**P](
    hotkey: str,
    callback: Callable[P, Coroutine[Any, Any, None]],
    *args: P.args,
    **kwargs: P.kwargs,
) -> AsyncGenerator[None]:
    loop = asyncio.get_running_loop()
    bound_callback = partial(callback, *args, **kwargs)

    def sync_wrapper() -> None:
        asyncio.run_coroutine_threadsafe(bound_callback(), loop)

    keyboard.add_hotkey(hotkey, sync_wrapper)
    try:
        yield
    finally:
        keyboard.remove_hotkey(hotkey)


def retry_if_exception_group_contains(
    *target_exceptions: type[Exception],
) -> Callable[[RetryCallState], bool]:
    def _predicate(retry_state: RetryCallState) -> bool:
        assert retry_state.outcome is not None
        exc = retry_state.outcome.exception()
        if isinstance(exc, ExceptionGroup):
            for inner_exc in exc.exceptions:
                if isinstance(inner_exc, target_exceptions):
                    return True
            return False
        return isinstance(exc, target_exceptions)

    return _predicate


def is_admin() -> bool:
    try:
        is_user_an_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if TYPE_CHECKING:
            assert isinstance(is_user_an_admin, bool), f"{type(is_user_an_admin)}"
    except Exception as _:
        return False
    else:
        return is_user_an_admin


@cache
def get_image(image_name: str) -> ImageFile:
    image_bytes = read_binary("calltoarms.assets", image_name + ".jpg")
    image_stream = io.BytesIO(image_bytes)
    return Image.open(image_stream)


MODIFIER_KEYS = {
    "shift": win32con.VK_SHIFT,
    "ctrl": win32con.VK_CONTROL,
    "alt": win32con.VK_MENU,
    "tab": win32con.VK_TAB,
}


def is_modifier_pressed() -> bool:
    for vk_code in MODIFIER_KEYS.values():
        if win32api.GetAsyncKeyState(vk_code) < 0:
            return True
    return False


class MakeAsyncContextManager[T](contextlib.AbstractAsyncContextManager[T]):
    def __init__(self, cm: contextlib.AbstractContextManager[T]):
        self.cm: contextlib.AbstractContextManager[T] = cm

    async def __aenter__(self) -> T:
        return await asyncio.to_thread(self.cm.__enter__)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool | None:
        return await asyncio.to_thread(self.cm.__exit__, exc_type, exc_value, traceback)


# expect single-threaded ThreadPoolExecutor if __enter__ and
# __exit__ should run in the same thread
@contextlib.asynccontextmanager
async def make_asynccontextmanager[T](
    cm: contextlib.AbstractContextManager[T],
    *,
    executor: ThreadPoolExecutor | None = None,
) -> AsyncGenerator[T]:
    loop = asyncio.get_running_loop()
    value = await loop.run_in_executor(executor, cm.__enter__)
    try:
        yield value
    except BaseException as e:
        suppress = await loop.run_in_executor(
            executor, cm.__exit__, type(e), e, e.__traceback__
        )
        if not suppress:
            raise
    else:
        await loop.run_in_executor(executor, cm.__exit__, None, None, None)


def raise_assert(message: str, ex: BaseException | None = None) -> None:
    raise AssertionError(message) from ex
