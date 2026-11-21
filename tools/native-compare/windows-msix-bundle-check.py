"""Compare bundle declarations with read-only AppxPackaging APIs and raw ZIP records."""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zipfile
import zlib


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def native(path, api, include_families=False):
    ole = c.WinDLL("ole32", winmode=0x800)
    shell = c.WinDLL("shlwapi", winmode=0x800)
    ole.CoInitializeEx.argtypes = [c.c_void_p, w.DWORD]
    ole.CoInitializeEx.restype = c.c_long
    ole.CoUninitialize.argtypes = []
    ole.CoCreateInstance.argtypes = [c.POINTER(api.Guid), c.c_void_p, w.DWORD, c.POINTER(api.Guid), c.POINTER(c.c_void_p)]
    ole.CoCreateInstance.restype = c.c_long
    ole.CoTaskMemFree.argtypes = [c.c_void_p]
    shell.SHCreateStreamOnFileEx.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.BOOL, c.c_void_p, c.POINTER(c.c_void_p)]
    shell.SHCreateStreamOnFileEx.restype = c.c_long
    def pointer(owner, slot):
        value = c.c_void_p()
        api.checked(api.call(owner, slot, (c.POINTER(c.c_void_p),), (c.byref(value),)))
        return value
    def number(owner, slot, kind=w.DWORD):
        value = kind()
        api.checked(api.call(owner, slot, (c.POINTER(kind),), (c.byref(value),)))
        return value.value
    def text(owner, slot):
        value = pointer(owner, slot)
        try:
            result = c.wstring_at(value) if value else ""
            assert len(result) <= 8192
            return result
        finally:
            ole.CoTaskMemFree(value)
    def version(value):
        return ".".join(str((value >> shift) & 65535) for shift in [48, 32, 16, 0])
    def identity(owner):
        return {"name": text(owner, 3), "architecture": {0:"x86", 5:"arm", 9:"x64", 11:"neutral", 12:"arm64"}[number(owner, 4)],
                "publisher": text(owner, 5), "version": version(number(owner, 6, c.c_uint64)), "resource_id": text(owner, 7)}
    def enumerate_rows(owner, slot, read):
        rows = []
        enumerator = pointer(owner, slot)
        try:
            while number(enumerator, 4, w.BOOL):
                assert len(rows) < 1024
                item = pointer(enumerator, 3)
                try:
                    rows.append(read(item))
                finally:
                    api.release(item)
                number(enumerator, 5, w.BOOL)
            return rows
        finally:
            api.release(enumerator)
    def package(item):
        package_id = pointer(item, 4)
        try:
            result = {"identity": identity(package_id), "type": {0:"application", 1:"resource"}[number(item, 3)],
                      "file_name": text(item, 5), "offset": number(item, 6, c.c_uint64), "size": number(item, 7, c.c_uint64)}
            result["resources"] = enumerate_rows(item, 8, lambda resource: {
                "language": text(resource, 3) or None, "scale": number(resource, 4) or None, "dx_feature_level": number(resource, 5) or None})
            if include_families:
                info3 = c.c_void_p()
                api.checked(api.call(item, 0, (c.POINTER(api.Guid), c.POINTER(c.c_void_p)),
                                     (c.byref(api.guid("6ba74b98-bb74-4296-80d0-5f4256a99675")), c.byref(info3))))
                try:
                    result["target_device_families"] = enumerate_rows(info3, 3, lambda family: {"Name": text(family, 3),
                        "MinVersion": version(number(family, 4, c.c_uint64)), "MaxVersionTested": version(number(family, 5, c.c_uint64))})
                finally:
                    api.release(info3)
            return result
        finally:
            api.release(package_id)
    api.checked(ole.CoInitializeEx(None, 2))
    factory, stream, reader, package_id = c.c_void_p(), c.c_void_p(), None, None
    try:
        api.checked(ole.CoCreateInstance(c.byref(api.guid("378e0446-5384-43b7-8877-e7dbdd883446")), None, 1,
                                        c.byref(api.guid("bba65864-965f-4a5f-855f-f074bdbf3a7b")), c.byref(factory)))
        api.checked(shell.SHCreateStreamOnFileEx(str(path), 0x20, 0, False, None, c.byref(stream)))
        reader = c.c_void_p()
        api.checked(api.call(factory, 5, (c.c_void_p, c.POINTER(c.c_void_p)), (stream, c.byref(reader))))
        package_id = pointer(reader, 3)
        return {"source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "identity": identity(package_id),
                "packages": enumerate_rows(reader, 4, package), "api": "IAppxBundleManifestReader/IAppxBundleManifestPackageInfo"}
    finally:
        for value in [package_id, reader, stream, factory]:
            api.release(value)
        ole.CoUninitialize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if sys.platform != "win32" or output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh directory below this Windows checkout's out directory")
    output.mkdir(parents=True)
    api = module("appx_reference", Path(__file__).with_name("windows-msix-blockmap.py"))
    signature = module("signature_reference", Path(__file__).with_name("windows-msix-signature-check.py"))
    cli = str(args.cli.resolve())
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    def report_for(source, destination):
        before = source.read_bytes()
        previous = None
        for _ in range(2):
            done = subprocess.run([cli, str(source), "-o", str(destination), "--format", "json,md,html", *no_ai], capture_output=True,
                                  timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
            assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
            data = (destination / "report.json").read_bytes()
            assert previous is None or data == previous
            previous = data
        assert source.read_bytes() == before
        report = json.loads(data)
        return next(a for a in report["artifacts"] if a["parent"] is None)
    results = []
    for name in ["native-msix-bundle.appxbundle", "upstream-BundleWithIntlPackage.appxbundle", "upstream-SignedUntrustedCert.appxbundle"]:
        source = repository / "crates/aa-windows/tests/data" / name
        original = source.read_bytes()
        folder = output / name
        folder.mkdir()
        with zipfile.ZipFile(io.BytesIO(original)) as archive:
            manifest = folder / "AppxBundleManifest.xml"
            manifest.write_bytes(archive.read("AppxMetadata/AppxBundleManifest.xml"))
            expected = native(manifest, api)
            for row in expected["packages"]:
                from urllib.parse import quote
                entry = archive.getinfo(quote(row["file_name"], safe="-._~"))
                lengths = struct.unpack_from("<HH", original, entry.header_offset + 26)
                assert row["offset"] == entry.header_offset + 30 + sum(lengths) and row["size"] == entry.file_size
            signed = "AppxSignature.p7x" in archive.namelist()
            if signed:
                assert signature.native_verify(archive.read("AppxSignature.p7x"))["verified"]
                crypt = c.WinDLL("crypt32", use_last_error=True, winmode=0x800)
                crypt.CryptSIPRetrieveSubjectGuid.argtypes = [w.LPCWSTR, c.c_void_p, c.POINTER(api.Guid)]
                crypt.CryptSIPRetrieveSubjectGuid.restype = w.BOOL
                guid = api.Guid()
                assert crypt.CryptSIPRetrieveSubjectGuid(str(source), None, c.byref(guid))
                native_guid = str(uuid.UUID(bytes_le=c.string_at(c.byref(guid), 16)))
                assert native_guid == "0f5f58b3-aade-4b9a-a434-95742d92eceb"
                signed_bytes, comparisons = signature.independent(original)
                assert all(row["matches"] for row in comparisons)
        (output / (name + ".bundle.ref.json")).write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        destination = folder / "report"
        root = report_for(source, destination)
        assert root["kind"] == "msix-bundle"
        assert "Package declarations in an MSIX bundle" in (destination / "report.md").read_text(encoding="utf-8")
        if len(expected["packages"]) == 1:
            assert "preserves 1 declaration of" in (destination / "report.md").read_text(encoding="utf-8")
        assert "windows.msix-bundle-checks" in (destination / "report.html").read_text(encoding="utf-8")
        checks = root["facts"]["windows.msix-bundle-checks"]
        assert checks["packages_corresponding"] == len(expected["packages"]), (name, checks)
        assert checks["packages_differing"] == checks["packages_unresolved"] == checks["packages_partial"] == 0
        assert all(r["result"]["bundle_signed_byte_coverage"] == signed for r in checks["records"])
        if signed:
            assert root["facts"]["windows.msix-signature-binding"]["publisher_manifest_signed_coverage"]
            assert root["facts"]["windows.msix-signature-binding"]["publisher_matches"]
        assert source.read_bytes() == original
        results.append({"case":name,"native":expected,"native_sip_guid":native_guid if signed else None,
                        "independent_digests":comparisons if signed else None,"input_unchanged":True,"repeated_json_identical":True})
    for case, differing, unresolved, extra in [("ManifestPackageHasIncorrectArchitecture",1,0,0),("ManifestPackageHasIncorrectSize",1,0,0),
            ("ManifestPackageHasInvalidOffset",1,0,0),("ManifestHasExtraPackage",0,1,0),("PayloadPackageNotListedInManifest",0,0,1),("PayloadPackageIsCompressed",0,1,0)]:
        source = repository / "crates/aa-windows/tests/data" / ("upstream-" + case + ".appxbundle")
        root = report_for(source, output / (case + "-report"))
        checked = root["facts"]["windows.msix-bundle-checks"]
        assert checked["packages_differing"] == differing and checked["packages_unresolved"] == unresolved
        assert len(checked["undeclared_packages"]) == extra
        results.append({"case":case,"checks":checked,"input_unchanged":True,"repeated_json_identical":True})
    original = (repository / "crates/aa-windows/tests/data/upstream-SignedUntrustedCert.appxbundle").read_bytes()
    p7x, _ = signature.independent(original)
    bad_cms = signature.replace_signature(original, p7x[:-1] + bytes([p7x[-1] ^ 1]))
    changed = bytearray(original)
    outer, central, _ = signature.layout(original)
    entry = outer.getinfo("Basic.appx")
    nl, xl = struct.unpack_from("<HH", original, entry.header_offset + 26)
    start = entry.header_offset + 30 + nl + xl
    inner_bytes = bytearray(outer.read(entry))
    inner = zipfile.ZipFile(io.BytesIO(inner_bytes))
    inner_bytes[inner.infolist()[0].header_offset + 10] ^= 1
    inner_bytes[inner.start_dir + 12] ^= 1
    changed[start:start + len(inner_bytes)] = inner_bytes
    crc = zlib.crc32(inner_bytes)
    struct.pack_into("<I", changed, entry.header_offset + 14, crc)
    struct.pack_into("<I", changed, central[entry.filename][0] + 16, crc)
    if entry.flag_bits & 8:
        descriptor = start + entry.compress_size
        if changed[descriptor:descriptor + 4] == b"PK\x07\x08":
            descriptor += 4
        struct.pack_into("<I", changed, descriptor, crc)
    for case, raw, cms, mismatches in [("changed-inner-package-bytes", changed, True, 2),("changed-bundle-cms",bad_cms,False,0)]:
        source = output / (case + ".appxbundle")
        source.write_bytes(raw)
        p7x, independent = signature.independent(raw)
        assert signature.native_verify(p7x)["verified"] == cms
        root = report_for(source, output / (case + "-report"))
        binding = root["facts"]["windows.msix-signature-binding"]
        checked = root["facts"]["windows.msix-bundle-checks"]
        assert binding["cms_signature_verified"] == cms and binding["mismatching_digests"] == mismatches
        assert sum(not c["matches"] for c in independent) == mismatches
        assert checked["packages_corresponding"] == 2 and not any(r["result"]["bundle_signed_byte_coverage"] for r in checked["records"])
        results.append({"case":case,"cms_verified":cms,"independent_digests":independent,"checks":checked,"input_unchanged":True,"repeated_json_identical":True})
    chinese_source = repository / "crates/aa-windows/tests/data/upstream-ManifestPackageHasIncorrectSize.appxbundle"
    chinese_before = chinese_source.read_bytes()
    chinese = output / "chinese-report"
    done = subprocess.run([cli, str(chinese_source), "-o", str(chinese), "--format", "json,md", "--lang", "zh", *no_ai], capture_output=True,
                          timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
    assert done.returncode in (0, 2)
    assert "MSIX bundle 声明与内部包不符" in (chinese / "report.md").read_text(encoding="utf-8")
    assert chinese_source.read_bytes() == chinese_before
    (output / "checks.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print("compared three bundles, six independent negatives and two signed-byte/CMS mutations")


if __name__ == "__main__":
    main()
