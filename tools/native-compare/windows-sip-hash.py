"""Read-only native catalog SIP hashes of explicitly supplied controlled files."""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import sys


def sip_hash(path, algorithm):
    wintrust = c.WinDLL("wintrust", use_last_error=True, winmode=0x800)
    kernel = c.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    wintrust.CryptCATAdminAcquireContext2.argtypes = [c.POINTER(w.HANDLE), c.c_void_p, w.LPCWSTR, c.c_void_p, w.DWORD]
    wintrust.CryptCATAdminAcquireContext2.restype = w.BOOL
    wintrust.CryptCATAdminReleaseContext.argtypes = [w.HANDLE, w.DWORD]
    wintrust.CryptCATAdminReleaseContext.restype = w.BOOL
    wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.DWORD), c.c_void_p, w.DWORD]
    wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = w.BOOL
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    context = w.HANDLE()
    if not wintrust.CryptCATAdminAcquireContext2(c.byref(context), None, algorithm, None, 0):
        raise c.WinError(c.get_last_error())
    handle = None
    try:
        handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x00200000 | 0x00100000, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        length = w.DWORD(64)
        digest = (c.c_ubyte * 64)()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle2(context, handle, c.byref(length), digest, 0):
            raise c.WinError(c.get_last_error())
        if length.value > len(digest):
            raise ValueError("native digest exceeded the reference budget")
        return bytes(digest[:length.value]).hex()
    finally:
        if handle and handle != c.c_void_p(-1).value:
            kernel.CloseHandle(handle)
        wintrust.CryptCATAdminReleaseContext(context, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("native SIP hashing requires Windows")
    result = []
    for path in args.samples:
        before = path.read_bytes()
        result.append({"sample": path.name, "sha256": hashlib.sha256(before).hexdigest(),
                       "size": len(before), "sip_sha1": sip_hash(path, "SHA1"),
                       "sip_sha256": sip_hash(path, "SHA256")})
        assert path.read_bytes() == before, "input changed"
    text = json.dumps({"reference": "CryptCATAdminCalcHashFromFileHandle2", "samples": result}, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
