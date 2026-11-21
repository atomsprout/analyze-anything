"""Read a controlled block map and check supplied content with Windows AppxPackaging COM.

This development reference opens only read-only streams; it never deploys a package,
loads its code, registers a catalog or consults an installed package's content.
"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys
import uuid
import xml.etree.ElementTree as ET


class Guid(c.Structure):
    _fields_ = [("data", c.c_ubyte * 16)]


def guid(text):
    return Guid((c.c_ubyte * 16).from_buffer_copy(uuid.UUID(text).bytes_le))


def call(pointer, slot, argtypes=(), args=(), result=c.c_long):
    table = c.cast(pointer, c.POINTER(c.POINTER(c.c_void_p))).contents
    return c.WINFUNCTYPE(result, c.c_void_p, *argtypes)(table[slot])(pointer, *args)


def checked(status):
    if status < 0:
        raise OSError("AppxPackaging HRESULT 0x%08x" % (status & 0xffffffff))


def release(pointer):
    if pointer:
        call(pointer, 2, result=w.ULONG)


def native(blockmap, directory):
    ole = c.WinDLL("ole32", winmode=0x800)
    shell = c.WinDLL("shlwapi", winmode=0x800)
    ole.CoInitializeEx.argtypes = [c.c_void_p, w.DWORD]
    ole.CoInitializeEx.restype = c.c_long
    ole.CoUninitialize.argtypes = []
    ole.CoCreateInstance.argtypes = [c.POINTER(Guid), c.c_void_p, w.DWORD, c.POINTER(Guid), c.POINTER(c.c_void_p)]
    ole.CoCreateInstance.restype = c.c_long
    ole.CoTaskMemFree.argtypes = [c.c_void_p]
    shell.SHCreateStreamOnFileEx.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.BOOL, c.c_void_p, c.POINTER(c.c_void_p)]
    shell.SHCreateStreamOnFileEx.restype = c.c_long

    def stream(path):
        pointer = c.c_void_p()
        checked(shell.SHCreateStreamOnFileEx(str(path.resolve()), 0x20, 0, False, None, c.byref(pointer)))
        return pointer

    def pointer_out(owner, slot):
        value = c.c_void_p()
        checked(call(owner, slot, (c.POINTER(c.c_void_p),), (c.byref(value),)))
        return value

    def number_out(owner, slot, kind):
        value = kind()
        checked(call(owner, slot, (c.POINTER(kind),), (c.byref(value),)))
        return value.value

    checked(ole.CoInitializeEx(None, 2))
    factory = c.c_void_p()
    input_stream = reader = files = None
    result = []
    count = 0
    try:
        checked(ole.CoCreateInstance(c.byref(guid("5842a140-ff9f-4166-8f5c-62f5b7b0c781")), None, 1,
                                    c.byref(guid("beb94909-e451-438b-b5a7-d79e767b75d8")), c.byref(factory)))
        input_stream = stream(blockmap)
        reader = c.c_void_p()
        checked(call(factory, 6, (c.c_void_p, c.POINTER(c.c_void_p)), (input_stream, c.byref(reader))))
        files = pointer_out(reader, 4)
        while number_out(files, 4, w.BOOL):
            if len(result) >= 4096:
                raise ValueError("native file-count budget exceeded")
            member = pointer_out(files, 3)
            blocks = None
            try:
                name_pointer = pointer_out(member, 5)
                try:
                    name = c.wstring_at(name_pointer)
                finally:
                    ole.CoTaskMemFree(name_pointer)
                relative = PureWindowsPath(name)
                if relative.is_absolute() or relative.drive or not relative.parts or any(p in (".", "..") or ":" in p for p in relative.parts):
                    raise ValueError("reference filename is outside the relative-name profile")
                target = directory.joinpath(*relative.parts).resolve()
                if not target.is_relative_to(directory.resolve()):
                    raise ValueError("reference filename leaves the supplied content directory")
                item = {"name": name, "size": number_out(member, 6, c.c_uint64),
                        "local_file_header_size": number_out(member, 4, c.c_uint32), "blocks": []}
                version2 = c.c_void_p()
                status = call(member, 0, (c.POINTER(Guid), c.POINTER(c.c_void_p)),
                              (c.byref(guid("54785f78-40e9-11ee-be56-0242ac120002")), c.byref(version2)))
                item["native_block_size"] = None
                if status >= 0:
                    try:
                        item["native_block_size"] = number_out(version2, 8, c.c_uint64)
                    finally:
                        release(version2)
                blocks = pointer_out(member, 3)
                while number_out(blocks, 4, w.BOOL):
                    if count >= 32768:
                        raise ValueError("native block-count budget exceeded")
                    block = pointer_out(blocks, 3)
                    buffer = c.c_void_p()
                    try:
                        size = c.c_uint32()
                        checked(call(block, 3, (c.POINTER(c.c_uint32), c.POINTER(c.c_void_p)), (c.byref(size), c.byref(buffer))))
                        if size.value > 64:
                            raise ValueError("native digest exceeded its byte budget")
                        item["blocks"].append({"digest": c.string_at(buffer, size.value).hex(),
                                               "native_compressed_size": number_out(block, 4, c.c_uint32)})
                    finally:
                        if buffer:
                            ole.CoTaskMemFree(buffer)
                        release(block)
                    count += 1
                    number_out(blocks, 5, w.BOOL)
                if target.is_file():
                    if target.stat().st_size > 64 * 1024 * 1024:
                        raise ValueError("native reference content exceeds 64 MiB")
                    before = target.read_bytes()
                    payload = stream(target)
                    try:
                        valid = w.BOOL()
                        status = call(member, 7, (c.c_void_p, c.POINTER(w.BOOL)), (payload, c.byref(valid)))
                        item["validation_hresult"] = "0x%08x" % (status & 0xffffffff)
                        item["content_matches"] = bool(valid.value) if status >= 0 else None
                    finally:
                        release(payload)
                    assert target.read_bytes() == before, "reference input changed"
                    item["sha256"] = hashlib.sha256(before).hexdigest()
                else:
                    item["content_matches"] = None
                    item["reason"] = "file-not-supplied"
                result.append(item)
            finally:
                release(blocks)
                release(member)
            number_out(files, 5, w.BOOL)
        return result
    finally:
        release(files)
        release(reader)
        release(input_stream)
        release(factory)
        ole.CoUninitialize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blockmap", type=Path, required=True)
    parser.add_argument("--content", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("the AppxPackaging reference requires Windows")
    before = args.blockmap.read_bytes()
    if len(before) > 8 * 1024 * 1024:
        parser.error("block map exceeds the reference byte budget")
    rows = native(args.blockmap, args.content)
    assert args.blockmap.read_bytes() == before, "block map changed"
    root = ET.fromstring(before)
    for item in rows:
        declaration = next(f for f in root if f.get("Name") == item["name"])
        value = declaration.find("{http://schemas.microsoft.com/appx/2021/blockmap}FileHash")
        item["file_hash_base64_declared"] = value.get("Hash") if value is not None else None
    record = {"reference": "IAppxBlockMapReader/IAppxBlockMapFile/IAppxBlockMapBlock", "sha256": hashlib.sha256(before).hexdigest(),
              "hash_method_declared": root.get("HashMethod"), "files": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("read", len(rows), "native block-map file records")


if __name__ == "__main__":
    main()
