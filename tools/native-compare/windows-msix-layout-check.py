"""Compare original MSIX ZIP headers with SDK unpacking and an independent ZIP reader.

Uses only the four redistributable repository fixtures. No deployment or input execution.
The repacked LfhSize negative is a declaration test, not native package qualification.
"""

import argparse
import glob
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("SDK comparison requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh output directory below this checkout's out directory")
    candidates = list(map(Path, glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe")))
    if not candidates:
        parser.error("Windows SDK MakeAppx was not found")
    tool = max(candidates, key=lambda p: tuple(map(int, p.parent.parent.name.split("."))))
    cli = str(args.cli.resolve())
    flags = subprocess.CREATE_NO_WINDOW
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=flags)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True)
    results = []
    for name in ["native-msix-sha256.msix", "native-msix-sha384.msix", "native-msix-sha512.msix", "upstream-TestAppxPackage_Win32.appx"]:
        sample = repository / "crates/aa-windows/tests/data" / name
        original = sample.read_bytes()
        if len(original) > 16 * 1024 * 1024:
            raise ValueError("fixture exceeds controlled reference byte budget")
        native = subprocess.run([str(tool), "unpack", "/p", str(sample), "/d", str(output / (name + "-native"))],
                                capture_output=True, timeout=60, creationflags=flags)
        (output / (name + "-native.log")).write_bytes(native.stdout + native.stderr)
        assert native.returncode == 0, "SDK unpack without /nv failed"
        with zipfile.ZipFile(io.BytesIO(original)) as archive:
            entries = archive.infolist()
            assert len(entries) <= 4096 and sum(e.file_size for e in entries) <= 64 * 1024 * 1024
            content = {e.filename: archive.read(e) for e in entries}
        xml = content["AppxBlockMap.xml"].decode("utf-8")
        root = ET.fromstring(xml)
        first = list(root)[0]
        old = first.get("LfhSize")
        changed_xml = xml.replace('LfhSize="' + old + '"', 'LfhSize="' + str(int(old) + 1) + '"', 1)
        assert changed_xml != xml
        negative = output / (name + "-changed-header.msix")
        with zipfile.ZipFile(negative, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, data in content.items():
                archive.writestr(path, changed_xml.encode("utf-8") if path == "AppxBlockMap.xml" else data)
        cases = []
        for label, package in [("original", sample), ("changed-header", negative)]:
            before = package.read_bytes()
            destination = output / (name + "-" + label + "-report")
            for repeat in range(2):
                done = subprocess.run([cli, str(package), "-o", str(destination), "--format", "json,md,html", *no_ai],
                                      capture_output=True, timeout=120, creationflags=flags)
                assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
                report_bytes = (destination / "report.json").read_bytes()
                if repeat == 0:
                    previous = report_bytes
                else:
                    assert report_bytes == previous
            report = json.loads(report_bytes)
            container = next(a for a in report["artifacts"] if "windows.msix-zip-layout" in a["facts"])
            layout = container["facts"]["windows.msix-zip-layout"]
            assert layout["source_sha256"] == hashlib.sha256(before).hexdigest()
            assert layout["mapped_files_unresolved"] == 0
            expected_mismatches = 0 if label == "original" else 1
            assert layout["mapped_files_with_header_or_size_mismatch"] == expected_mismatches
            assert any(f["rule"] == "windows.msix-zip-map-mismatch" for f in report["findings"]) == bool(expected_mismatches)
            assert not layout["package_signature_checked"] and not layout["compressed_block_sizes_checked"]
            source = next(a for a in report["artifacts"] if "windows.msix-blockmap" in a["facts"])
            declarations = source["facts"]["windows.msix-blockmap"]["files"]
            with zipfile.ZipFile(io.BytesIO(before)) as archive:
                entries = {e.filename.lower(): e for e in archive.infolist()}
                assert layout["entries_checked"] == len(entries)
                for row in layout["mapped_files"]:
                    declaration = declarations[row["file"]]
                    entry = entries[declaration["path"].lower()]
                    name_length, extra_length = struct.unpack_from("<HH", before, entry.header_offset + 26)
                    header_length = 30 + name_length + extra_length
                    assert row["local_header_offset"] == entry.header_offset
                    assert row["local_header_size"] == header_length
                    assert row["data_offset"] == entry.header_offset + header_length
                    assert row["compressed_size"] == entry.compress_size
                    assert row["uncompressed_size"] == entry.file_size
                    assert row["header_and_size_agree"] == (declaration["local_file_header_size"] == header_length)
            assert package.read_bytes() == before
            cases.append({"case": label, "header_mismatches": expected_mismatches, "entries": layout["entries_checked"],
                          "repeated_json_identical": True, "input_unchanged": True})
        assert sample.read_bytes() == original
        chinese = output / (name + "-changed-header-zh")
        done = subprocess.run([cli, str(negative), "-o", str(chinese), "--format", "md", "--lang", "zh", *no_ai],
                              capture_output=True, timeout=120, creationflags=flags)
        assert done.returncode in (0, 2)
        text = (chinese / "report.md").read_text(encoding="utf-8")
        assert "MSIX 原始 ZIP 记录对应一致" in text and "MSIX 块映射与 ZIP 头或大小不符" in text
        results.append({"sample": name, "sha256": hashlib.sha256(original).hexdigest(), "native_unpack_return_code": native.returncode, "cases": cases})
    (output / "checks.json").write_text(json.dumps({"sdk": tool.parent.parent.name, "samples": results,
        "package_signatures_checked": False, "negative_cases_native_qualified": False}, indent=2) + "\n", encoding="utf-8")
    print("compared four native unpack results and eight original/header-declaration cases")


if __name__ == "__main__":
    main()
