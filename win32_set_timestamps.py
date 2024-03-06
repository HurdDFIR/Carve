import os
from datetime import datetime as dt
from carve_log import l

try:
    from ctypes import byref, get_last_error, wintypes, WinDLL, WinError

    kernel32 = WinDLL("kernel32", use_last_error=True)

    CreateFileW = kernel32.CreateFileW
    SetFileTime = kernel32.SetFileTime
    CloseHandle = kernel32.CloseHandle

    CreateFileW.argtypes = (
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    CreateFileW.restype = wintypes.HANDLE

    SetFileTime.argtypes = (
        wintypes.HANDLE,
        wintypes.PFILETIME,
        wintypes.PFILETIME,
        wintypes.PFILETIME,
    )
    SetFileTime.restype = wintypes.BOOL

    CloseHandle.argtypes = (wintypes.HANDLE,)
    CloseHandle.restype = wintypes.BOOL
except (ImportError, AttributeError, OSError, ValueError):
    SUPPORTED = False
else:
    SUPPORTED = os.name == "nt"


def set_timestamps(filepath, ctime: dt, atime: dt, mtime: dt, *,
                   follow_symlinks=True):
    try:
        if not SUPPORTED:
            raise OSError("This function is only available for the Windows platform.")

        filepath = os.path.normpath(os.path.abspath(str(filepath)))

        ctime = ctime.timestamp()
        atime = atime.timestamp()
        mtime = mtime.timestamp()

        ctime = int(ctime * 10000000) + 116444736000000000
        atime = int(atime * 10000000) + 116444736000000000
        mtime = int(mtime * 10000000) + 116444736000000000

        atime = wintypes.FILETIME(atime & 0xFFFFFFFF, atime >> 32)
        mtime = wintypes.FILETIME(mtime & 0xFFFFFFFF, mtime >> 32)
        ctime = wintypes.FILETIME(ctime & 0xFFFFFFFF, ctime >> 32)

        flags = 128 | 0x02000000

        if not follow_symlinks:
            flags |= 0x00200000

        handle = wintypes.HANDLE(CreateFileW(filepath, 256, 0,
                                            None, 3, flags, None))

        if handle.value == wintypes.HANDLE(-1).value:
            raise WinError(get_last_error())

        if not wintypes.BOOL(SetFileTime(handle, byref(ctime),
                                        byref(atime), byref(mtime))):
            raise WinError(get_last_error())

        if not wintypes.BOOL(CloseHandle(handle)):
            raise WinError(get_last_error())
    
    except Exception as e:
        l.error(f"Error {e}")
