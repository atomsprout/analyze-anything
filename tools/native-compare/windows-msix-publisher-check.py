"""Check qualified subject spellings and literal publisher comparisons on Windows.

Reads repository fixtures and controlled variants only. No certificate store, trust
engine, package installation, executable loading or network access is used.
"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("native publisher references require Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh directory below this checkout's out directory")
    output.mkdir(parents=True)
    api = module("appx_reference", Path(__file__).with_name("windows-msix-blockmap.py"))
    manifest = module("manifest_reference", Path(__file__).with_name("windows-msix-manifest-check.py"))
    class Blob(c.Structure):
        _fields_ = [("size", w.DWORD), ("data", c.POINTER(c.c_ubyte))]
    crypt = c.WinDLL("crypt32", winmode=0x800)
    crypt.CertNameToStrW.argtypes = [w.DWORD, c.POINTER(Blob), w.DWORD, w.LPWSTR, w.DWORD]
    crypt.CertNameToStrW.restype = w.DWORD
    rows = json.loads((repository / "crates/aa-windows/tests/data/msix-publisher-subjects.ref.json").read_text(encoding="utf-8"))
    for row in rows:
        raw = bytes.fromhex(row["der"])
        memory = (c.c_ubyte * len(raw)).from_buffer_copy(raw)
        blob = Blob(len(raw), memory)
        count = crypt.CertNameToStrW(1, c.byref(blob), 0x02000003, None, 0)
        assert 0 < count <= 8193
        text = c.create_unicode_buffer(count)
        assert crypt.CertNameToStrW(1, c.byref(blob), 0x02000003, text, count) == count
        assert text.value == row["windows"], row
    source = repository / "crates/aa-windows/tests/data/upstream-TestAppxPackage_Win32.appx"
    original = source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(original)) as archive:
        entries = [(entry.filename, archive.read(entry)) for entry in archive.infolist()]
    xml = dict(entries)["AppxManifest.xml"].decode("utf-8")
    signatures = module("signature_reference", Path(__file__).with_name("windows-msix-signature-check.py"))
    certificate = signatures.native_verify(dict(entries)["AppxSignature.p7x"], include_subject=True)
    assert certificate["verified"]
    subject_der = bytes.fromhex(certificate["subject_der"])
    memory = (c.c_ubyte * len(subject_der)).from_buffer_copy(subject_der)
    subject_blob = Blob(len(subject_der), memory)
    count = crypt.CertNameToStrW(1, c.byref(subject_blob), 0x02000003, None, 0)
    assert 0 < count <= 8193
    subject_spelling = c.create_unicode_buffer(count)
    assert crypt.CertNameToStrW(1, c.byref(subject_blob), 0x02000003, subject_spelling, count) == count
    identity = re.search(r"<Identity\b[^>]*/>", xml).group()
    publisher = re.search(r'Publisher="([^"]+)"', identity).group(1)
    assert publisher == subject_spelling.value
    variants = [publisher, publisher.lower(), publisher.replace("S=", "ST="),
                publisher.replace(", ", ",  "), publisher.replace("CN=Microsoft Corporation", 'CN="Microsoft Corporation"'),
                "CN=Other Publisher"]
    manifest_path = output / "AppxManifest.xml"
    manifest_path.write_bytes(dict(entries)["AppxManifest.xml"])
    comparisons = manifest.native(manifest_path, api, variants)["publisher_comparisons"]
    assert [row["matches"] for row in comparisons] == [True] + [False] * (len(variants) - 1)
    assert all(row["hresult"] == "0x00000000" for row in comparisons)
    cases = {"original-wrapper": (xml, None, True, True),
             "changed-publisher": (xml.replace(identity, identity.replace(publisher, variants[-1])), None, False, False),
             "duplicate-identity": (xml.replace(identity, identity + identity), None, None, None),
             "bad-cms": (xml, "bad-cms", None, None)}
    cli = str(args.cli.resolve())
    flags = subprocess.CREATE_NO_WINDOW
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=flags)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    results = []
    for case, (text, change, matches, covered) in cases.items():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries:
                if name == "AppxManifest.xml":
                    content = text.encode("utf-8")
                elif name == "AppxSignature.p7x" and change:
                    content = content[:-1] + bytes([content[-1] ^ 1])
                archive.writestr(name, content)
        raw = buffer.getvalue()
        package = output / (case + ".appx")
        package.write_bytes(raw)
        destination = output / (case + "-report")
        previous = None
        for _ in range(2):
            done = subprocess.run([cli, str(package), "-o", str(destination), "--format", "json,md,html", *no_ai],
                                  capture_output=True, timeout=120, creationflags=flags)
            assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
            data = (destination / "report.json").read_bytes()
            assert previous is None or previous == data
            previous = data
        report = json.loads(data)
        checked = next(a["facts"]["windows.msix-publisher"] for a in report["artifacts"] if "windows.msix-publisher" in a["facts"])
        assert checked["publisher_checked"] == (matches is not None), (case, checked)
        if matches is not None:
            assert checked["matches"] == matches and checked["manifest_signed_coverage"]["established"] == covered, (case, checked)
            assert checked["signer_subject_sha256"] == hashlib.sha256(subject_der).hexdigest()
            assert checked["signer_subject_spelling"] == subject_spelling.value
        assert not checked["windows_trust_checked"]
        markdown = (destination / "report.md").read_text(encoding="utf-8")
        html = (destination / "report.html").read_text(encoding="utf-8")
        assert "windows.msix-publisher" in html
        if matches is not None:
            title = "MSIX publisher matches verified signer's subject spelling" if matches else "MSIX publisher differs from verified signer's subject spelling"
            assert title in markdown
        assert package.read_bytes() == raw
        results.append({"case": case, "publisher": checked, "input_unchanged": True, "repeated_json_identical": True})
    assert source.read_bytes() == original
    chinese = output / "chinese-report"
    done = subprocess.run([cli, str(output / "changed-publisher.appx"), "-o", str(chinese), "--format", "json,md", "--lang", "zh", *no_ai],
                          capture_output=True, timeout=120, creationflags=flags)
    assert done.returncode in (0, 2)
    assert "MSIX 发布者与已验证签名者的主题拼写不符" in (chinese / "report.md").read_text(encoding="utf-8")
    (output / "checks.json").write_text(json.dumps({"native_subject_count": len(rows), "native_comparisons": comparisons,
                                                   "package_cases": results}, indent=2) + "\n", encoding="utf-8")
    print("compared native subject spellings, literal publisher probes and four package cases")


if __name__ == "__main__":
    main()
