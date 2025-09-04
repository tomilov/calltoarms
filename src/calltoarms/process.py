import contextlib
import ctypes
import logging
import queue
import struct
import subprocess
import threading
import typing
from collections.abc import Generator
from ctypes import POINTER, Structure, Union, byref, sizeof
from ctypes.wintypes import (
    BOOL,
    BYTE,
    DWORD,
    HANDLE,
    HMODULE,
    LONG,
    LPCSTR,
    LPCVOID,
    LPCWSTR,
    LPVOID,
    LPWSTR,
    MAX_PATH,
    ULONG,
    USHORT,
    WORD,
)
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import psutil
import win32con
import winerror
from addict import Dict  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


INT3 = b"\xcc"

DWORD64 = ctypes.c_uint64
SIZE_T = ctypes.c_size_t
LONGLONG = ctypes.c_int64
ULONGLONG = ctypes.c_uint64


class WOW64_FLOATING_SAVE_AREA(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]


MAXIMUM_SUPPORTED_EXTENSION = 512


class WOW64_CONTEXT(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("ContextFlags", DWORD),
        # Debug
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        # FPU
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        # Segments
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        # Integer
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        # Control
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        # SSE state
        ("ExtendedRegisters", BYTE * MAXIMUM_SUPPORTED_EXTENSION),
    ]


class M128A(Structure):
    _fields_: typing.ClassVar = [("Low", ULONGLONG), ("High", LONGLONG)]


class XMM_SAVE_AREA32(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]


WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x00000001
WOW64_CONTEXT_INTEGER = WOW64_CONTEXT_i386 | 0x00000002
WOW64_CONTEXT_SEGMENTS = WOW64_CONTEXT_i386 | 0x00000004
WOW64_CONTEXT_FLOATING_POINT = WOW64_CONTEXT_i386 | 0x00000008
WOW64_CONTEXT_DEBUG_REGISTERS = WOW64_CONTEXT_i386 | 0x00000010
WOW64_CONTEXT_EXTENDED_REGISTERS = WOW64_CONTEXT_i386 | 0x00000020
WOW64_CONTEXT_FULL = (
    WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS
)
WOW64_CONTEXT_ALL = (
    WOW64_CONTEXT_FULL
    | WOW64_CONTEXT_FLOATING_POINT
    | WOW64_CONTEXT_DEBUG_REGISTERS
    | WOW64_CONTEXT_EXTENDED_REGISTERS
)


class CONTEXT(Structure):
    _fields_: typing.ClassVar = [
        # Home regs
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        # Segments and EFlags
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        # Debug registers
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        # Integer registers
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        # Instruction pointer
        ("Rip", DWORD64),
        # Floating-point/XMM state
        ("FltSave", XMM_SAVE_AREA32),
        # Vector registers
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
        # Special debug controls
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
    ]


CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
CONTEXT_XSTATE = CONTEXT_AMD64 | 0x00000040
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = (
    CONTEXT_CONTROL
    | CONTEXT_INTEGER
    | CONTEXT_SEGMENTS
    | CONTEXT_FLOATING_POINT
    | CONTEXT_DEBUG_REGISTERS
)


INFINITE = DWORD(-1)

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF

EXCEPTION_BREAKPOINT = 0x80000003


class SOCKADDR_IN(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("sin_family", ctypes.c_short),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ulong),  # IP address
        ("sin_zero", ctypes.c_char * 8),
    ]


class EXCEPTION_RECORD(Structure):  # noqa: N801
    _fields_: typing.ClassVar[typing.Any]


EXCEPTION_MAXIMUM_PARAMETERS = 15
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("pExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", LPVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", POINTER(ULONG) * EXCEPTION_MAXIMUM_PARAMETERS),
]


class EXCEPTION_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("dwExitCode", DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [("dwExitCode", DWORD)]


class LOAD_DLL_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("lpBaseOfDll", LPVOID),
    ]


class OUTPUT_DEBUG_STRING_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("lpDebugStringData", LPVOID),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]


class RIP_INFO(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("dwError", DWORD),
        ("dwType", DWORD),
    ]


class DEBUG_EVENT_UNION(Union):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


if sizeof(ctypes.c_void_p) == 4:  # noqa: PLR2004
    assert sizeof(DEBUG_EVENT_UNION) == 84, f"{sizeof(DEBUG_EVENT_UNION) = }"  # noqa: PLR2004
else:
    assert sizeof(DEBUG_EVENT_UNION) == 160, f"{sizeof(DEBUG_EVENT_UNION) = }"  # noqa: PLR2004


class DEBUG_EVENT(Structure):  # noqa: N801
    _fields_: typing.ClassVar = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

IsWow64Process2 = getattr(kernel32, "IsWow64Process2", None)
if IsWow64Process2 is not None:
    IsWow64Process2.argtypes = (HANDLE, POINTER(USHORT), POINTER(USHORT))
    IsWow64Process2.restype = BOOL

IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x014C  # x86 (32)
IMAGE_FILE_MACHINE_AMD64 = 0x8664  # x64 (64)
IMAGE_FILE_MACHINE_ARM64 = 0xAA64  # ARM64 (64)
IMAGE_FILE_MACHINE_ARMNT = 0x01C4  # ARM (32)
IMAGE_FILE_MACHINE_IA64 = 0x0200  # Itanium (64)

IsWow64Process = kernel32.IsWow64Process
IsWow64Process.argtypes = (HANDLE, POINTER(BOOL))
IsWow64Process.restype = BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = (HANDLE,)
CloseHandle.restype = BOOL

OpenThread = kernel32.OpenThread
OpenThread.argtypes = (DWORD, BOOL, DWORD)
OpenThread.restype = HANDLE

SuspendThread = kernel32.SuspendThread
SuspendThread.argtypes = (HANDLE,)
SuspendThread.restype = DWORD

Wow64SuspendThread = getattr(kernel32, "Wow64SuspendThread", None)
if Wow64SuspendThread is not None:
    Wow64SuspendThread.argtypes = (HANDLE,)
    Wow64SuspendThread.restype = DWORD

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (HANDLE,)
ResumeThread.restype = DWORD

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (
    HANDLE,
    LPVOID,
    SIZE_T,
    LPVOID,
    LPVOID,
    DWORD,
    POINTER(DWORD),
)
CreateRemoteThread.restype = HANDLE

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = (HANDLE, DWORD)
WaitForSingleObject.restype = DWORD

GetExitCodeThread = kernel32.GetExitCodeThread
GetExitCodeThread.argtypes = (HANDLE, POINTER(DWORD))
GetExitCodeThread.restype = BOOL

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (
    HANDLE,
    LPVOID,
    SIZE_T,
    DWORD,
    DWORD,
)
VirtualAllocEx.restype = LPVOID

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.argtypes = (
    HANDLE,
    LPVOID,
    SIZE_T,
    DWORD,
)
VirtualFreeEx.restype = BOOL

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD))
VirtualProtectEx.restype = BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T))
ReadProcessMemory.restype = BOOL

FlushInstructionCache = kernel32.FlushInstructionCache
FlushInstructionCache.argtypes = (HANDLE, LPCVOID, SIZE_T)
FlushInstructionCache.restype = BOOL

GetThreadContext = kernel32.GetThreadContext
GetThreadContext.argtypes = (HANDLE, POINTER(CONTEXT))
GetThreadContext.restype = BOOL

Wow64GetThreadContext = (
    kernel32.Wow64GetThreadContext
    if sizeof(ctypes.c_void_p) == 8  # noqa: PLR2004
    else kernel32.GetThreadContext
)
Wow64GetThreadContext.argtypes = (HANDLE, POINTER(WOW64_CONTEXT))
Wow64GetThreadContext.restype = BOOL

SetThreadContext = kernel32.SetThreadContext
SetThreadContext.argtypes = (HANDLE, POINTER(CONTEXT))
SetThreadContext.restype = BOOL

Wow64SetThreadContext = (
    kernel32.Wow64SetThreadContext
    if sizeof(ctypes.c_void_p) == 8  # noqa: PLR2004
    else kernel32.SetThreadContext
)
Wow64SetThreadContext.argtypes = (HANDLE, POINTER(WOW64_CONTEXT))
Wow64SetThreadContext.restype = BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (DWORD, BOOL, DWORD)
OpenProcess.restype = HANDLE

GetProcessId = kernel32.GetProcessId
GetProcessId.argtypes = (HANDLE,)
GetProcessId.restype = DWORD

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = ()
GetCurrentProcess.restype = HANDLE

GetCurrentProcessId = kernel32.GetCurrentProcessId
GetCurrentProcessId.argtypes = ()
GetCurrentProcessId.restype = DWORD

DebugActiveProcess = kernel32.DebugActiveProcess
DebugActiveProcess.argtypes = (DWORD,)
DebugActiveProcess.restype = BOOL

DebugActiveProcessStop = kernel32.DebugActiveProcessStop
DebugActiveProcessStop.argtypes = (DWORD,)
DebugActiveProcessStop.restype = BOOL

WaitForDebugEvent = kernel32.WaitForDebugEvent
WaitForDebugEvent.argtypes = (POINTER(DEBUG_EVENT), DWORD)
WaitForDebugEvent.restype = BOOL

ContinueDebugEvent = kernel32.ContinueDebugEvent
ContinueDebugEvent.argtypes = (DWORD, DWORD, DWORD)
ContinueDebugEvent.restype = BOOL

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x00010001

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = (LPCSTR,)
GetModuleHandleA.restype = HMODULE

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.argtypes = (LPCWSTR,)
GetModuleHandleW.restype = HMODULE

LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.argtypes = (LPCSTR,)
LoadLibraryA.restype = HMODULE

LoadLibraryW = kernel32.LoadLibraryW
LoadLibraryW.argtypes = (LPCWSTR,)
LoadLibraryW.restype = HMODULE

FreeLibrary = kernel32.FreeLibrary
FreeLibrary.argtypes = (HMODULE,)
FreeLibrary.restype = BOOL

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (HMODULE, LPCSTR)
GetProcAddress.restype = LPVOID

GetFinalPathNameByHandleW = kernel32.GetFinalPathNameByHandleW
GetFinalPathNameByHandleW.argtypes = (
    HANDLE,
    LPWSTR,
    DWORD,
    DWORD,
)
GetFinalPathNameByHandleW.restype = DWORD

VOLUME_NAME_DOS = 0x0  # Return a DOS path (\\?\C:\..., or \\?\UNC\server\share\...)
FILE_NAME_NORMALIZED = 0x0  # Normalized path
DUPLICATE_SAME_ACCESS = 0x2

psapi = ctypes.WinDLL("psapi", use_last_error=True)

EnumProcessModulesEx = psapi.EnumProcessModulesEx
EnumProcessModulesEx.argtypes = (
    HANDLE,
    POINTER(HMODULE),
    DWORD,
    POINTER(DWORD),
    DWORD,
)
EnumProcessModulesEx.restype = BOOL

GetModuleFileNameExW = psapi.GetModuleFileNameExW
GetModuleFileNameExW.argtypes = (
    HANDLE,
    HMODULE,
    LPWSTR,
    DWORD,
)
GetModuleFileNameExW.restype = DWORD

ntdll = ctypes.WinDLL("ntdll")

NtSuspendProcess = ntdll.NtSuspendProcess
NtSuspendProcess.argtypes = (HANDLE,)
NtSuspendProcess.restype = LONG  # NTSTATUS

NtResumeProcess = ntdll.NtResumeProcess
NtResumeProcess.argtypes = (HANDLE,)
NtResumeProcess.restype = LONG

SCS_32BIT_BINARY = 0
SCS_64BIT_BINARY = 6

GetBinaryTypeW = kernel32.GetBinaryTypeW
GetBinaryTypeW.argtypes = (LPCWSTR, POINTER(DWORD))
GetBinaryTypeW.restype = BOOL

IPPROTO_IP = 0  # level
IP_UNICAST_IF = 31  # optname (DWORD IfIndex)

EFLAGS_TF = 0x100  # EFlags Trap Flag


@dataclass(kw_only=True)
class Dll:
    image_file: HANDLE


@dataclass(kw_only=True)
class Process:
    pid: int
    token: str
    if_index: int | None

    functions: Dict[bytes, LPVOID] = field(default_factory=Dict)
    orig_code: bytes = b""

    exit_code: DWORD | None = None

    h_process: HANDLE = field(default_factory=HANDLE)
    h_thread: HANDLE = field(default_factory=HANDLE)
    h_module: dict[bytes, HANDLE] = field(default_factory=dict)
    image_file: HANDLE = field(default_factory=HANDLE)
    threads: dict[DWORD, HANDLE] = field(default_factory=dict)
    dlls: dict[LPVOID, Dll] = field(default_factory=dict)  # lpBaseOfDll to hFile


def _check[T](condition: T, ex: Exception | None = None, descr: str | None = None) -> T:
    if not condition:
        raise ctypes.WinError(ctypes.get_last_error(), descr) from ex
    return condition


def is_32bit_executable(path: Path) -> bool:
    bt = DWORD()
    _check(GetBinaryTypeW(str(path), byref(bt)))
    return bt.value == SCS_32BIT_BINARY


def get_process_bitness(h_process: HANDLE) -> typing.Literal[32, 64]:
    if IsWow64Process2:
        pm, nm = USHORT(), USHORT()
        _check(IsWow64Process2(h_process, byref(pm), byref(nm)))
        if pm.value != IMAGE_FILE_MACHINE_UNKNOWN:
            # WOW64 process => 32-bit (emulated)
            return 32
        # not WOW64 -> native bitness by nativeMachine
        if nm.value in (
            IMAGE_FILE_MACHINE_AMD64,
            IMAGE_FILE_MACHINE_ARM64,
            IMAGE_FILE_MACHINE_IA64,
        ):
            return 64
        return 32
    # rollback to IsWow64Process (Vista+)
    is_wow = BOOL()
    _check(IsWow64Process(h_process, byref(is_wow)))
    if is_wow.value:
        # WOW64 => 32-bit process
        return 32
    # Not WOW64: bitness must match bitness of the current process.
    return 64 if sizeof(ctypes.c_void_p) == 8 else 32  # noqa: PLR2004


@contextlib.contextmanager
def open_process(pid: int) -> Generator[HANDLE]:
    h_process: HANDLE = _check(OpenProcess(PROCESS_ALL_ACCESS, False, pid))
    try:
        yield h_process
    finally:
        _check(CloseHandle(h_process))


@contextlib.contextmanager
def suspend_process(h_process: HANDLE) -> Generator[None]:
    _check(NtSuspendProcess(h_process) >= 0)
    try:
        yield
    finally:
        _check(NtResumeProcess(h_process) >= 0)


@contextlib.contextmanager
def open_thread(tid: int) -> Generator[HANDLE]:
    h_thread: HANDLE = _check(OpenThread(THREAD_ALL_ACCESS, False, tid))
    try:
        yield h_thread
    finally:
        _check(CloseHandle(h_thread))


def normalize_final_path(p: str) -> str:
    # Convert \\?\C:\... -> C:\...
    # Convert \\?\UNC\server\share\... -> \\server\share\...
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def get_final_path_from_handle(h_file: HANDLE) -> str:
    size = MAX_PATH
    flags = VOLUME_NAME_DOS | FILE_NAME_NORMALIZED
    while True:
        buf = ctypes.create_unicode_buffer(size)
        n = _check(GetFinalPathNameByHandleW(h_file, buf, size, flags))
        if n < size:
            return normalize_final_path(buf.value)
        size = n + 1


def get_dll_name(h_process: HANDLE, load_dll: LOAD_DLL_DEBUG_INFO) -> str:
    assert h_process
    if not load_dll.lpImageName:
        return ""
    remote_process_bitness = get_process_bitness(h_process)
    local_ptr_size = sizeof(ctypes.c_void_p)
    if remote_process_bitness == 64 and local_ptr_size == 4:  # noqa: PLR2004
        raise NotImplementedError("32-bit debugger cannot read 64-bit process")
    p_name_ptr = (
        ctypes.c_uint64() if remote_process_bitness == 64 else ctypes.c_uint32()  # noqa: PLR2004
    )
    read = SIZE_T(0)
    _check(
        ReadProcessMemory(
            h_process,
            load_dll.lpImageName,
            byref(p_name_ptr),
            sizeof(p_name_ptr),
            byref(read),
        )
    )
    if not p_name_ptr.value:
        raise RuntimeError(f"{p_name_ptr.value = }")
    name_addr = p_name_ptr.value
    name: str
    if load_dll.fUnicode:
        buf_w = ctypes.create_unicode_buffer(MAX_PATH)
        _check(
            ReadProcessMemory(
                h_process,
                LPVOID(name_addr),
                buf_w,
                sizeof(buf_w),
                byref(read),
            )
        )
        name = buf_w.value
    else:
        buf_a = ctypes.create_string_buffer(MAX_PATH)
        _check(
            ReadProcessMemory(
                h_process,
                LPVOID(name_addr),
                buf_a,
                sizeof(buf_a),
                byref(read),
            )
        )
        name = buf_a.value.decode("mbcs", errors="replace")
    if not name:
        raise RuntimeError(f"{name = }")
    return Path(name).name.lower()


def alloc_memory(h_process: HANDLE, n: SIZE_T) -> LPVOID:
    alloc_type = win32con.MEM_COMMIT | win32con.MEM_RESERVE
    prot = win32con.PAGE_READWRITE
    p_memory = LPVOID(VirtualAllocEx(h_process, None, n, alloc_type, prot))
    return _check(p_memory)


def free_memory(h_process: HANDLE, p_memory: LPVOID) -> None:
    _check(VirtualFreeEx(h_process, p_memory, 0, win32con.MEM_RELEASE))


@contextlib.contextmanager
def get_memory(h_process: HANDLE, n: SIZE_T) -> Generator[LPVOID]:
    p_memory: LPVOID = alloc_memory(h_process, n)
    try:
        yield p_memory
    finally:
        free_memory(h_process, p_memory)


def load_library(h_process: HANDLE, dll_name: bytes) -> HMODULE:
    with contextlib.ExitStack() as exit_stack:
        dll_name_len = SIZE_T(len(dll_name) + 1)
        p_memory: LPVOID = exit_stack.enter_context(get_memory(h_process, dll_name_len))
        written = SIZE_T(0)
        _check(
            WriteProcessMemory(
                h_process, p_memory, dll_name + b"\x00", dll_name_len, byref(written)
            )
        )
        if written.value <= len(dll_name):
            raise RuntimeError(f"{written.value = }")
        k32 = _check(GetModuleHandleA(b"kernel32.dll"))
        load_library_ptr = GetProcAddress(k32, b"LoadLibraryA")
        tid = DWORD(0)
        # it is almost guaranteed base adress of kernel32.dll module in local process
        # and in remote process are the same if remote is child process
        # created with CREATE_SUSPENDED and it is not yet resumed
        h_thread = _check(
            CreateRemoteThread(
                h_process, None, 0, load_library_ptr, p_memory, 0, byref(tid)
            )
        )
        exit_stack.callback(lambda: _check(CloseHandle(h_thread)))
        _check(WaitForSingleObject(h_thread, INFINITE) == win32con.WAIT_OBJECT_0)
        exit_code = DWORD(0)
        _check(GetExitCodeThread(h_thread, byref(exit_code)))
        _check(exit_code.value != 0)
        return HMODULE(exit_code.value)


def get_export_addresses(
    h_module_remote: HMODULE, dll_name: bytes, *func_names: bytes
) -> Generator[LPVOID]:
    if typing.TYPE_CHECKING:
        assert h_module_remote.value is not None
    with contextlib.ExitStack() as exit_stack:
        h_module_local = GetModuleHandleA(dll_name)
        if not h_module_local:
            h_module_local = _check(LoadLibraryA(dll_name))
            exit_stack.callback(FreeLibrary, h_module_local)
        for func_name in func_names:
            p_func_addr_local = _check(GetProcAddress(h_module_local, func_name))
            rva = DWORD(p_func_addr_local).value - DWORD(h_module_local).value
            yield LPVOID(DWORD(h_module_remote.value).value + rva)


def read_process_memory(h_process: HANDLE, addr: LPVOID, n: int) -> bytes:
    orig_code = (ctypes.c_ubyte * n)()
    read = SIZE_T(0)
    _check(ReadProcessMemory(h_process, addr, orig_code, n, byref(read)))
    if read.value != n:
        raise RuntimeError(f"Cannot read original code from process memory: {read = }")
    return bytes(orig_code)


def write_process_memory(h_process: HANDLE, addr: LPVOID, code: bytes) -> None:
    orig_prot = DWORD(0)
    _check(
        VirtualProtectEx(
            h_process,
            addr,
            len(code),
            win32con.PAGE_EXECUTE_READWRITE,
            byref(orig_prot),
        )
    )
    try:
        written = SIZE_T(0)
        _check(WriteProcessMemory(h_process, addr, code, len(code), byref(written)))
        if written.value != len(code):
            raise RuntimeError(f"Cannot write new code to process memory: {written = }")
        _check(FlushInstructionCache(h_process, addr, len(code)))
    finally:
        _check(
            VirtualProtectEx(
                h_process,
                addr,
                len(code),
                orig_prot.value,
                byref(orig_prot),
            )
        )


def get_context(h_thread: HANDLE) -> WOW64_CONTEXT:
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_ALL
    _check(Wow64GetThreadContext(h_thread, byref(ctx)))
    return ctx


def set_context(h_thread: HANDLE, ctx: WOW64_CONTEXT) -> None:
    _check(Wow64SetThreadContext(h_thread, byref(ctx)))


class Command(Enum):
    RUN_PROCESS = 1
    START_DEBUG = 2
    STOP_DEBUG = 3
    TERMINATE_PROCESS = 4
    STOP = 5


@dataclass(kw_only=True)
class Message:
    cmd: Command
    payload: tuple[typing.Any, ...] = ()
    result: tuple[typing.Any, ...] = ()

    done: threading.Event


class MessageArgs(typing.TypedDict):
    cmd: Command
    payload: typing.NotRequired[tuple[typing.Any, ...]]
    result: typing.NotRequired[tuple[typing.Any, ...]]


class Debugger:
    def __init__(self) -> None:
        current_process_bintess = get_process_bitness(GetCurrentProcess())
        if current_process_bintess != 32:  # noqa: PLR2004
            raise RuntimeError(
                f"{current_process_bintess}-bit debugger is not implemented"
            )

        self.queue: queue.Queue[Message] = queue.Queue()
        self.barrier: threading.Barrier = threading.Barrier(2)
        self.lock: threading.Lock = threading.Lock()
        self.events: list[threading.Event] = []
        self.pending_second_break_tids: dict[int, LPVOID] = {}
        self.pending_single_step_tids: set[int] = set()

    def send(self, **kwargs: typing.Unpack[MessageArgs]) -> tuple[typing.Any, ...]:
        done: threading.Event
        with self.lock:
            done = self.events.pop() if self.events else threading.Event()
        msg = Message(**kwargs, done=done)
        self.queue.put(msg)
        msg.done.wait()
        msg.done.clear()
        with self.lock:
            self.events.append(msg.done)
        return msg.result

    def handle_load_dll(self, process: Process, load_dll: LOAD_DLL_DEBUG_INFO) -> None:
        process.dlls[load_dll.lpBaseOfDll] = Dll(image_file=load_dll.hFile)
        dll_name = get_final_path_from_handle(load_dll.hFile)
        logger.debug("%s", f"{dll_name = }")

    def handle_unload_dll(
        self, process: Process, unload_dll: UNLOAD_DLL_DEBUG_INFO
    ) -> None:
        dll = process.dlls.pop(unload_dll.lpBaseOfDll, None)
        if dll is not None and dll.image_file.value is not None:
            _check(CloseHandle(dll.image_file))

    def handle_connect_break(self, process: Process, tid: int) -> None:
        assert process.if_index is not None
        with (
            open_process(process.pid) as h_process,
            open_thread(tid) as h_thread,
        ):
            if typing.TYPE_CHECKING:
                assert process.functions.connect.value is not None
                assert process.functions.setsockopt.value is not None
            ctx = get_context(h_thread)
            if tid in self.pending_single_step_tids:
                write_process_memory(h_process, process.functions.connect, INT3)
                ctx.EFlags &= ~EFLAGS_TF
                self.pending_single_step_tids.remove(tid)
            elif tid in self.pending_second_break_tids:
                write_process_memory(
                    h_process, process.functions.connect, process.orig_code
                )
                ctx.Eip = process.functions.connect.value
                ctx.EFlags |= EFLAGS_TF  # arm single-step

                logger.info("%s", f"EAX = 0x{ctx.Eax:08X}")

                p_if_index_memory = self.pending_second_break_tids.pop(tid)
                free_memory(h_process, p_if_index_memory)
                self.pending_single_step_tids.add(tid)
            else:
                s_value: bytes = read_process_memory(
                    h_process, ctx.Esp + sizeof(DWORD), sizeof(DWORD)
                )
                p_if_index_memory = alloc_memory(h_process, SIZE_T(sizeof(DWORD)))
                if typing.TYPE_CHECKING:
                    assert p_if_index_memory.value is not None
                if_index = struct.pack("!I", process.if_index & 0xFFFFFF)
                write_process_memory(h_process, p_if_index_memory, if_index)

                stack: list[bytes] = []

                def push_dword(value: int | bytes) -> None:
                    ctx.Esp -= sizeof(DWORD)
                    if isinstance(value, bytes):
                        assert len(value) == sizeof(DWORD), f"{len(value) = }"
                        stack.append(value)
                    else:
                        stack.append(struct.pack("<I", value))

                # make stack for setsockopt(s, level=IPPROTO_IP, optname=IP_UNICAST_IF, optval=&IfIndex, optlen=4)  # noqa: E501
                push_dword(  # return to breakpoint on ws2_32!connect
                    process.functions.connect.value
                )
                push_dword(s_value)
                push_dword(IPPROTO_IP)
                push_dword(IP_UNICAST_IF)
                push_dword(p_if_index_memory.value)
                push_dword(sizeof(DWORD))
                write_process_memory(h_process, ctx.Esp, b"".join(stack))

                ctx.Eip = process.functions.setsockopt.value
                ctx.EFlags &= ~EFLAGS_TF

                self.pending_second_break_tids[tid] = p_if_index_memory
            set_context(h_thread, ctx)

    def debug_loop(self) -> None:  # noqa: PLR0912, PLR0915, C901
        pids_to_debug: set[int] = set()
        processes: dict[int, Process] = {}  # pid to process
        debug_event = DEBUG_EVENT()
        self.barrier.wait()
        while True:
            msg: Message
            try:
                if pids_to_debug:
                    msg = self.queue.get(block=False)
                else:
                    msg = self.queue.get(timeout=0.1)
            except queue.Empty as ex:
                if not pids_to_debug:
                    continue
                timeout = DWORD(100)  # milliseconds
                if not WaitForDebugEvent(byref(debug_event), timeout):
                    last_error = ctypes.get_last_error()
                    if last_error == winerror.ERROR_SEM_TIMEOUT:
                        continue
                    raise ctypes.WinError(last_error) from None
                pid = debug_event.dwProcessId
                if pid not in pids_to_debug:
                    continue
                tid = debug_event.dwThreadId
                process = processes[pid]
                event_code = debug_event.dwDebugEventCode
                continue_status = DBG_CONTINUE
                if event_code == win32con.CREATE_PROCESS_DEBUG_EVENT:
                    logger.debug("%s", "CREATE_PROCESS_DEBUG_EVENT")
                    create_process_info = debug_event.u.CreateProcessInfo
                    process.h_process = create_process_info.hProcess
                    process.h_thread = create_process_info.hThread
                    process.image_file = create_process_info.hFile
                elif event_code == win32con.CREATE_THREAD_DEBUG_EVENT:
                    logger.debug("%s", "CREATE_THREAD_DEBUG_EVENT")
                    process.threads[tid] = debug_event.u.CreateThread.hThread
                elif event_code == win32con.EXCEPTION_DEBUG_EVENT:
                    logger.debug("%s", "EXCEPTION_DEBUG_EVENT")
                    exception = debug_event.u.Exception
                    exception_record = exception.ExceptionRecord
                    exception_code = exception_record.ExceptionCode  # noqa: F841
                    exception_address = exception_record.ExceptionAddress
                    if typing.TYPE_CHECKING:
                        assert process.functions.connect.value is not None
                    max_instr_sz = 8
                    offset = exception_address - process.functions.connect.value
                    if 0 <= offset < max_instr_sz:
                        self.handle_connect_break(process, tid)
                    else:
                        continue_status = DBG_EXCEPTION_NOT_HANDLED
                elif event_code == win32con.EXIT_PROCESS_DEBUG_EVENT:
                    logger.debug("%s", "EXIT_PROCESS_DEBUG_EVENT")
                    exit_process = debug_event.u.ExitProcess
                    process.exit_code = exit_process.dwExitCode
                    if process.image_file.value is not None:
                        _check(CloseHandle(process.image_file), ex)
                elif event_code == win32con.EXIT_THREAD_DEBUG_EVENT:
                    logger.debug("%s", "EXIT_THREAD_DEBUG_EVENT")
                    exit_code = debug_event.u.ExitThread.dwExitCode  # noqa: F841
                    h_thread = process.threads.pop(tid)
                elif event_code == win32con.LOAD_DLL_DEBUG_EVENT:
                    logger.debug("%s", "LOAD_DLL_DEBUG_EVENT")
                    self.handle_load_dll(process, debug_event.u.LoadDll)
                elif event_code == win32con.UNLOAD_DLL_DEBUG_EVENT:
                    logger.debug("%s", "LOAD_DLL_DEBUG_EVENT")
                    self.handle_unload_dll(process, debug_event.u.UnloadDll)
                elif event_code == win32con.OUTPUT_DEBUG_STRING_EVENT:
                    logger.debug("%s", "OUTPUT_DEBUG_STRING_EVENT")
                elif event_code == win32con.RIP_EVENT:
                    logger.debug("%s", "RIP_EVENT")
                else:
                    raise AssertionError(f"{event_code = }") from None
                _check(ContinueDebugEvent(pid, debug_event.dwThreadId, continue_status))
            else:
                try:
                    if msg.cmd == Command.RUN_PROCESS:
                        token, args, if_index = msg.payload
                        creationflags: int = win32con.CREATE_SUSPENDED
                        proc: subprocess.Popen[str] = subprocess.Popen(  # noqa: S603
                            args,
                            creationflags=creationflags,
                            cwd=Path(args[0]).parent,
                            text=True,
                        )
                        with open_process(proc.pid) as h_process:
                            process_bitness = get_process_bitness(h_process)
                            if process_bitness != 32:  # noqa: PLR2004
                                raise RuntimeError(
                                    f"{process_bitness}-bit debugee is not supported"
                                )
                            threads = psutil.Process(pid=proc.pid).threads()
                            if len(threads) != 1:
                                raise AssertionError(f"{len(threads) = }")
                            tid = threads[0].id
                            with open_thread(tid) as h_thread:
                                process = Process(
                                    pid=proc.pid,
                                    token=token,
                                    if_index=if_index,
                                )
                                dll_name = b"ws2_32.dll"
                                h_module = load_library(h_process, dll_name)
                                functions = ("connect", "setsockopt")
                                (
                                    process.functions.connect,
                                    process.functions.setsockopt,
                                ) = get_export_addresses(
                                    h_module, dll_name, *(f.encode() for f in functions)
                                )
                                process.h_module[dll_name] = h_module
                                process.orig_code = read_process_memory(
                                    h_process, process.functions.connect, len(INT3)
                                )
                                _check(ResumeThread(h_thread))
                        processes[proc.pid] = process
                        msg.result = (proc,)
                    elif msg.cmd == Command.START_DEBUG:
                        (proc,) = msg.payload
                        pids_to_debug.add(proc.pid)
                        process = processes[proc.pid]
                        with open_process(proc.pid) as h_process:
                            write_process_memory(
                                h_process, process.functions.connect, INT3
                            )
                        _check(DebugActiveProcess(proc.pid))
                    elif msg.cmd == Command.STOP_DEBUG:
                        (proc,) = msg.payload
                        pids_to_debug.remove(proc.pid)
                        process = processes[proc.pid]
                        with open_process(proc.pid) as h_process:
                            write_process_memory(
                                h_process, process.functions.connect, process.orig_code
                            )
                        _check(DebugActiveProcessStop(proc.pid))
                    elif msg.cmd == Command.TERMINATE_PROCESS:
                        (proc,) = msg.payload
                        process = processes.pop(proc.pid)
                        if proc.returncode is None:
                            try:
                                logger.info("Terminate process...")
                                proc.terminate()
                            except ProcessLookupError:
                                logger.info("Subprocess exited on its own")
                            else:
                                returncode = proc.wait()
                                logger.info(
                                    "%s", f"Subprocess terminated: {returncode = }"
                                )
                    elif msg.cmd == Command.STOP:
                        # TODO(tomilov): cleanup pids_to_debug and processes?
                        break
                    else:
                        raise AssertionError(f"{msg.cmd = }")
                finally:
                    msg.done.set()
                    self.queue.task_done()

    @contextlib.contextmanager
    def run_process(
        self, token: str, args: list[str], *, if_index: int | None = None
    ) -> Generator[subprocess.Popen[str]]:
        result = self.send(
            cmd=Command.RUN_PROCESS,
            payload=(token, args, if_index),
        )
        try:
            if typing.TYPE_CHECKING:
                assert isinstance(result[0], subprocess.Popen)
            yield result[0]
        finally:
            self.send(
                cmd=Command.TERMINATE_PROCESS,
                payload=(result[0],),
            )

    @contextlib.contextmanager
    def debug(self, proc: subprocess.Popen[str]) -> Generator[None]:
        self.send(cmd=Command.START_DEBUG, payload=(proc,))
        try:
            yield
        finally:
            self.send(cmd=Command.STOP_DEBUG, payload=(proc,))

    @classmethod
    @contextlib.contextmanager
    def run_debugger(cls) -> Generator["Debugger"]:
        debugger = cls()
        debug_loop = threading.Thread(target=debugger.debug_loop)
        debug_loop.start()
        debugger.barrier.wait()
        try:
            yield debugger
        finally:
            debugger.send(cmd=Command.STOP)
            debugger.queue.join()
            debug_loop.join()
