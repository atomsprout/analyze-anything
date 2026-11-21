"""Compare bounded MSIX manifest projections with read-only AppxPackaging APIs.

Only repository fixtures and controlled XML variants are used. No package is installed,
no executable/icon/resource is opened, and no external package or installed state is resolved.
"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile


def native(path, api, compare_publishers=None, include_resources=False):
    ole, shell = c.WinDLL("ole32", winmode=0x800), c.WinDLL("shlwapi", winmode=0x800)
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
    def number(owner, slot, kind):
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
    def enumerate_rows(owner, slot, read):
        enumerator = pointer(owner, slot)
        rows = []
        try:
            while number(enumerator, 4, w.BOOL):
                assert len(rows) < 128
                item = pointer(enumerator, 3)
                try:
                    rows.append(read(item))
                finally:
                    api.release(item)
                number(enumerator, 5, w.BOOL)
            return rows
        finally:
            api.release(enumerator)
    api.checked(ole.CoInitializeEx(None, 2))
    factory = c.c_void_p()
    stream = c.c_void_p()
    reader = package_id = reader3 = None
    try:
        api.checked(ole.CoCreateInstance(c.byref(api.guid("5842a140-ff9f-4166-8f5c-62f5b7b0c781")), None, 1,
                                        c.byref(api.guid("beb94909-e451-438b-b5a7-d79e767b75d8")), c.byref(factory)))
        api.checked(shell.SHCreateStreamOnFileEx(str(path), 0x20, 0, False, None, c.byref(stream)))
        reader = c.c_void_p()
        api.checked(api.call(factory, 5, (c.c_void_p, c.POINTER(c.c_void_p)), (stream, c.byref(reader))))
        package_id = pointer(reader, 3)
        architecture = number(package_id, 4, w.DWORD)
        identity = {"name": text(package_id, 3), "publisher": text(package_id, 5), "version": version(number(package_id, 6, c.c_uint64)),
                    "architecture": {0: "x86", 5: "arm", 9: "x64", 11: "neutral", 12: "arm64"}.get(architecture), "resource_id": text(package_id, 7)}
        dependencies = enumerate_rows(reader, 5, lambda item: {"Name": text(item, 3), "Publisher": text(item, 4), "MinVersion": version(number(item, 5, c.c_uint64))})
        reader3 = c.c_void_p()
        api.checked(api.call(reader, 0, (c.POINTER(api.Guid), c.POINTER(c.c_void_p)), (c.byref(api.guid("C43825AB-69B7-400A-9709-CC37F5A72D24")), c.byref(reader3))))
        families_error = None
        try:
            families = enumerate_rows(reader3, 14, lambda item: {"Name": text(item, 3), "MinVersion": version(number(item, 4, c.c_uint64)), "MaxVersionTested": version(number(item, 5, c.c_uint64))})
        except OSError as error:
            if not include_resources or "0x80070490" not in str(error):
                raise
            families, families_error = None, str(error)
        result = {"api": "IAppxManifestReader/IAppxManifestPackageId/IAppxManifestReader3", "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "identity": identity, "dependencies": dependencies, "target_device_families": families}
        if include_resources:
            if families_error:
                result["target_device_families_error"] = families_error
            result["resources"] = enumerate_rows(reader3, 12, lambda resource: {"language": text(resource, 3) or None,
                "scale": number(resource, 4, w.DWORD) or None, "dx_feature_level": number(resource, 5, w.DWORD) or None})
        if compare_publishers is not None:
            result["publisher_comparisons"] = []
            for other in compare_publishers:
                same = w.BOOL()
                status = api.call(package_id, 8, (w.LPCWSTR, c.POINTER(w.BOOL)), (other, c.byref(same)))
                result["publisher_comparisons"].append({"other": other, "hresult": "0x%08x" % (status & 0xffffffff), "matches": bool(same.value) if status >= 0 else None})
        return result
    finally:
        for value in [reader3, package_id, reader, stream, factory]:
            api.release(value)
        ole.CoUninitialize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("native AppxPackaging reference requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh directory below this checkout's out directory")
    spec = importlib.util.spec_from_file_location("appx_reference", Path(__file__).with_name("windows-msix-blockmap.py"))
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    cli, flags = str(args.cli.resolve()), subprocess.CREATE_NO_WINDOW
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=flags)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True)
    cases, preserved = [], []
    for name in ["native-msix-sha256.msix", "native-msix-sha384.msix", "native-msix-sha512.msix", "upstream-TestAppxPackage_Win32.appx"]:
        package = repository / "crates/aa-windows/tests/data" / name
        before = package.read_bytes()
        assert len(before) < 16 * 1024 * 1024
        with zipfile.ZipFile(io.BytesIO(before)) as archive:
            xml = archive.read("AppxManifest.xml")
        folder = output / name
        folder.mkdir()
        path = folder / "AppxManifest.xml"
        path.write_bytes(xml)
        expected = native(path, api)
        (output / (name + ".manifest.ref.json")).write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        cases.append((name, path, expected, "unique"))
        preserved.append((package, before))
        if name == "native-msix-sha256.msix":
            original_xml = xml.decode("utf-8")
    identity = re.search(r"<Identity\b[^>]*/>", original_xml).group()
    foreign = identity.replace("Identity", "evil:Identity", 1).replace("<evil:Identity", '<evil:Identity xmlns:evil="urn:foreign"', 1).replace("AnalyzeAnything.BlockMapFixture", "Foreign.App")
    variants = {
        "foreign-identity": (original_xml.replace(identity, foreign + identity), "unique"),
        "nested-identity": (original_xml.replace(identity, "<Wrapper>" + identity + "</Wrapper>" + identity), "unique"),
        "duplicate-identity": (original_xml.replace(identity, identity + identity), "ambiguous"),
        "wrong-root-namespace": (original_xml.replace("http://schemas.microsoft.com/appx/manifest/foundation/windows10", "urn:foreign-root"), "unread"),
        "invalid-identity-version": (original_xml.replace('Version="1.0.0.0"', 'Version="65536.0.0.0"'), "unsupported"),
    }
    for case, (xml, status) in variants.items():
        folder = output / case
        folder.mkdir()
        path = folder / "AppxManifest.xml"
        path.write_text(xml, encoding="utf-8")
        try:
            observed = native(path, api)
        except OSError as error:
            observed = {"reader_error": str(error)}
        cases.append((case, path, observed, status))
    results = []
    for case, path, observed, status in cases:
        before = path.read_bytes()
        destination = path.parent / "report"
        for repeat in range(2):
            done = subprocess.run([cli, str(path), "-o", str(destination), "--format", "json,md,html", *no_ai], capture_output=True, timeout=120, creationflags=flags)
            assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
            data = (destination / "report.json").read_bytes()
            if repeat == 0:
                previous = data
            else:
                assert data == previous
        report = json.loads(data)
        fact = next((a["facts"]["windows.msix"] for a in report["artifacts"] if "windows.msix" in a["facts"]), None)
        if status == "unread":
            assert fact is None and any(l["code"] == "windows.msix-manifest-unreadable" for l in report["limitations"])
        else:
            assert fact["identity_status"] == status, (case, fact)
            assert fact["source_sha256"] == hashlib.sha256(before).hexdigest()
            if status != "unique":
                assert fact["identity"] is None and not fact["identity_projection_established"]
            elif case in variants:
                assert fact["identity"]["name"] == "AnalyzeAnything.BlockMapFixture"
            else:
                for key, expected in observed["identity"].items():
                    assert (fact["identity"].get(key) or "") == expected, (key, fact["identity"], observed)
                for key in ["dependencies", "target_device_families"]:
                    projected = [{k: row["attributes"][k] for k in row["attributes"] if k != "MaxMajorVersionTested"} for row in fact[key]]
                    assert projected == observed[key], (case, key, projected, observed)
            assert not fact["schema_validated"] and not fact["references_resolved"]
            assert "MSIX package identity" in (destination / "report.md").read_text(encoding="utf-8") or status != "unique"
            assert "windows.msix" in (destination / "report.html").read_text(encoding="utf-8")
        assert path.read_bytes() == before
        results.append({"case": case, "projection_status": status, "native": observed, "repeated_json_identical": True, "input_unchanged": True})
    for path, before in preserved:
        assert path.read_bytes() == before
    chinese = output / "zh-report"
    done = subprocess.run([cli, str(output / "duplicate-identity/AppxManifest.xml"), "-o", str(chinese), "--format", "md", "--lang", "zh", *no_ai], capture_output=True, timeout=120, creationflags=flags)
    assert done.returncode in (0, 2)
    assert "MSIX 清单没有唯一身份声明" in (chinese / "report.md").read_text(encoding="utf-8")
    (output / "checks.json").write_text(json.dumps({"cases": results, "schema_validation_claimed": False, "installed_state_consulted": False}, indent=2) + "\n", encoding="utf-8")
    print("compared four native manifests and five namespace/cardinality/version variants")


if __name__ == "__main__":
    main()
