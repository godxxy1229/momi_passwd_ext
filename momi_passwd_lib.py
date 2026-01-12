import csv
import ctypes
import datetime
import locale
import re
import subprocess
import sys
from dataclasses import dataclass
from ctypes import wintypes
from typing import List, Optional

KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

URL_REGEX = re.compile(rb"http://[^\x00\r\n\s]+")
PASSWD_REGEX = re.compile(r"[\?&]Passwd=([^&]+)")
VALID_PASSWD_REGEX = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
DATE_TIME_REGEX = re.compile(r"[\?&]Date=(\d{8})&Time=(\d{6}).*?Passwd=([^&]+)")

ALLOWED_URL_BYTES = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/?&=._%-")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * wintypes.MAX_PATH),
    ]


KERNEL32.OpenProcess.restype = wintypes.HANDLE
KERNEL32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

KERNEL32.ReadProcessMemory.restype = wintypes.BOOL
KERNEL32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

KERNEL32.VirtualQueryEx.restype = ctypes.c_size_t
KERNEL32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]

KERNEL32.CloseHandle.restype = wintypes.BOOL
KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]

KERNEL32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
KERNEL32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

KERNEL32.Process32FirstW.restype = wintypes.BOOL
KERNEL32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

KERNEL32.Process32NextW.restype = wintypes.BOOL
KERNEL32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


@dataclass(frozen=True)
class ProcessInfo:
    name: str
    pid: int
    exe: str


@dataclass(frozen=True)
class ScanResult:
    process: str
    pid: int
    passwords: List[str]
    urls: List[str]


def normalize_process_name(name: str) -> str:
    name = name.strip().lower()
    if name.endswith(".exe"):
        return name[:-4]
    return name


def unique_preserve_order(items):
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def iter_processes_by_name(names):
    wanted = {normalize_process_name(n) for n in names if n}
    if not wanted:
        return []

    snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return iter_processes_by_name_tasklist(names)

    processes = []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        if not KERNEL32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return []

        while True:
            exe = entry.szExeFile
            base = normalize_process_name(exe)
            if base in wanted:
                display_name = exe[:-4] if exe.lower().endswith(".exe") else exe
                processes.append(ProcessInfo(display_name, entry.th32ProcessID, exe))
            if not KERNEL32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        KERNEL32.CloseHandle(snapshot)

    if processes:
        return processes

    fallback = iter_processes_by_name_tasklist(names)
    return fallback


def iter_processes_by_name_tasklist(names):
    wanted = {normalize_process_name(n) for n in names if n}
    if not wanted:
        return []

    try:
        encoding = locale.getpreferredencoding(False)
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="ignore",
            check=False,
        )
    except Exception:
        return []

    if result.returncode != 0 or not result.stdout:
        return []

    processes = []
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) < 2:
            continue
        image = row[0].strip()
        pid_text = row[1].strip()
        base = normalize_process_name(image)
        if base not in wanted:
            continue
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        display_name = image[:-4] if image.lower().endswith(".exe") else image
        processes.append(ProcessInfo(display_name, pid, image))

    return processes


def open_process(pid: int):
    desired_access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = KERNEL32.OpenProcess(desired_access, False, pid)
    if not handle:
        return None
    return handle


def close_handle(handle):
    if handle:
        KERNEL32.CloseHandle(handle)


def is_readable_region(mbi: MEMORY_BASIC_INFORMATION) -> bool:
    if mbi.State != MEM_COMMIT:
        return False
    if mbi.Protect & PAGE_NOACCESS:
        return False
    if mbi.Protect & PAGE_GUARD:
        return False
    if mbi.Type not in (MEM_PRIVATE, MEM_MAPPED):
        return False
    return True


def is_allowed_url_bytes(url_bytes: bytes) -> bool:
    for b in url_bytes:
        if b not in ALLOWED_URL_BYTES:
            return False
    return True


def scan_process_urls(pid: int, region_size_limit_mb: int, process_name: Optional[str] = None):
    handle = open_process(pid)
    if not handle:
        if process_name:
            print(f"OpenProcess failed for {process_name} ({pid})", file=sys.stderr)
        return []

    urls = []
    try:
        limit_bytes = int(region_size_limit_mb) * 1024 * 1024
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)
        addr = 0

        while True:
            ret = KERNEL32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
            if not ret:
                break

            base = mbi.BaseAddress
            if hasattr(base, "value"):
                base = base.value
            if base is None:
                base = 0
            base = int(base)
            region_size = int(mbi.RegionSize)

            if is_readable_region(mbi) and 0 < region_size < limit_bytes:
                buffer = ctypes.create_string_buffer(region_size)
                bytes_read = ctypes.c_size_t(0)
                if KERNEL32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(base),
                    buffer,
                    region_size,
                    ctypes.byref(bytes_read),
                ):
                    data = buffer.raw[: bytes_read.value]
                    if b"Passwd=" in data:
                        for match in URL_REGEX.finditer(data):
                            url_bytes = match.group(0)
                            if b"Passwd=" not in url_bytes:
                                continue
                            if not is_allowed_url_bytes(url_bytes):
                                continue
                            urls.append(url_bytes.decode("ascii"))

            next_addr = base + region_size
            if next_addr <= addr:
                break
            addr = next_addr
    finally:
        close_handle(handle)

    return unique_preserve_order(urls)


def extract_passwords(urls):
    passwords = []
    for url in urls:
        for match in PASSWD_REGEX.finditer(url):
            pw = match.group(1)
            if VALID_PASSWD_REGEX.match(pw):
                passwords.append(pw)
    return unique_preserve_order(passwords)


def get_latest_password(urls, passwords):
    latest = None
    for url in urls:
        match = DATE_TIME_REGEX.search(url)
        if not match:
            continue
        dt_text = match.group(1) + match.group(2)
        try:
            dt = datetime.datetime.strptime(dt_text, "%Y%m%d%H%M%S")
        except ValueError:
            continue
        if latest is None or dt > latest[0]:
            latest = (dt, match.group(3))

    if latest:
        return latest[1]
    return passwords[0] if passwords else None


def scan_process(pid: int, process_name: str, region_size_limit_mb: int, max_urls_per_process: int):
    urls = scan_process_urls(pid, region_size_limit_mb, process_name=process_name)
    passwords = extract_passwords(urls)
    if max_urls_per_process is not None:
        urls = urls[: max_urls_per_process]
    return ScanResult(process=process_name, pid=pid, passwords=passwords, urls=urls)
