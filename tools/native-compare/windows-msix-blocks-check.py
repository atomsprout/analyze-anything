"""Compare raw MSIX block extents with independent DEFLATE decoding and native declarations.

Only repository fixtures are used. The negative ZIPs preserve original payload streams;
they are declaration/profile tests, not Windows signature or installation qualification.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib

NS = "{http://schemas.microsoft.com/appx/2010/blockmap}"


def deflate(data):
    encoder = zlib.compressobj(wbits=-15)
    return encoder.compress(data) + encoder.flush()


def package(entries):
    """Build ZIP32 headers around supplied compressed streams without recompressing payloads."""
    local, central = bytearray(), bytearray()
    for name, method, plain, compressed in entries:
        name = name.encode("ascii")
        crc, offset = zlib.crc32(plain), len(local)
        header = bytearray(30)
        struct.pack_into("<IHHHHHIIIHH", header, 0, 0x04034B50, 20, 0, method, 0, 0,
                         crc, len(compressed), len(plain), len(name), 0)
        local.extend(header + name + compressed)
        header = bytearray(46)
        struct.pack_into("<IHHHHHHIIIHHHHHII", header, 0, 0x02014B50, 20, 20, 0, method, 0, 0,
                         crc, len(compressed), len(plain), len(name), 0, 0, 0, 0, 0, offset)
        central.extend(header + name)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), len(local), 0)
    return bytes(local + central + end)


def change_blocks(xml, filename, action):
    """Change only the selected File's block declaration, preserving namespace declarations."""
    pattern = r'<File\b[^>]*\bName="' + re.escape(filename) + r'"[^>]*>.*?</File>'
    match = re.search(pattern, xml, flags=re.S)
    if match is None:
        raise ValueError("controlled fixture File declaration absent")
    changed = action(match.group())
    assert changed != match.group()
    return xml[:match.start()] + changed + xml[match.end():]


def independent(entries, xml):
    """All lengths are bounded by the controlled fixture preflight and 64-KiB output cap."""
    by_name = {name: (method, plain, compressed) for name, method, plain, compressed in entries}
    records = []
    root = ET.fromstring(xml)
    algorithm = root.get("HashMethod").rsplit("#", 1)[1]
    for file in root:
        name = file.get("Name").replace("\\", "/")
        method, plain, compressed = by_name[name]
        blocks = file.findall(NS + "Block")
        cursor = 0
        for number, block in enumerate(blocks):
            length = int(block.get("Size")) if method == 8 else min(65536, len(plain) - 65536 * number)
            piece = compressed[cursor:cursor + length]
            if method == 8:
                decoder = zlib.decompressobj(-15)
                stream = piece if number + 1 == len(blocks) and cursor + length == len(compressed) else piece + b"\x03\x00"
                data = decoder.decompress(stream, 65537)
                assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            else:
                data = piece
            assert data == plain[number * 65536:(number + 1) * 65536]
            assert hashlib.new(algorithm, data).digest() == base64.b64decode(block.get("Hash"))
            cursor += length
        remainder = compressed[cursor:]
        if method == 8 and remainder:
            decoder = zlib.decompressobj(-15)
            assert decoder.decompress(remainder, 1) == b"" and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
        else:
            assert remainder == b""
        records.append({"file": name, "blocks": len(blocks), "compressed_bytes": len(compressed), "block_span_bytes": cursor})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("native AppxPackaging comparison requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh output directory below this checkout's out directory")
    spec = importlib.util.spec_from_file_location("msix_reference", Path(__file__).with_name("windows-msix-blockmap.py"))
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    cli, flags = str(args.cli.resolve()), subprocess.CREATE_NO_WINDOW
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=flags)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True)
    results = []
    for name in ["native-msix-sha256.msix", "native-msix-sha384.msix", "native-msix-sha512.msix", "upstream-TestAppxPackage_Win32.appx"]:
        source = repository / "crates/aa-windows/tests/data" / name
        original = source.read_bytes()
        assert len(original) <= 16 * 1024 * 1024
        entries = []
        with zipfile.ZipFile(io.BytesIO(original)) as archive:
            assert len(archive.infolist()) <= 4096 and sum(e.file_size for e in archive.infolist()) <= 64 * 1024 * 1024
            for entry in archive.infolist():
                assert entry.filename.isascii() and ".." not in Path(entry.filename).parts
                plain = archive.read(entry)
                nl, xl = struct.unpack_from("<HH", original, entry.header_offset + 26)
                start = entry.header_offset + 30 + nl + xl
                entries.append((entry.filename, entry.compress_type, plain, original[start:start + entry.compress_size]))
        content = {n: plain for n, _, plain, _ in entries}
        xml = content["AppxBlockMap.xml"].decode("utf-8")
        by_name = {n: (method, plain, compressed) for n, method, plain, compressed in entries}
        files = list(ET.fromstring(xml))
        selected = max((f for f in files if by_name[f.get("Name").replace("\\", "/")][0] == 8 and len(f.findall(NS + "Block")) > 0), key=lambda f: int(f.get("Size")))
        selected_name = selected.get("Name")
        selected_path = selected_name.replace("\\", "/")
        selected_compressed = by_name[selected_path][2]
        block = selected.find(NS + "Block")
        wrong_hash = base64.b64encode(bytes(len(base64.b64decode(block.get("Hash"))))).decode("ascii")
        def include_tail(text):
            last = list(re.finditer(r'<Block\b[^>]*\bSize="([0-9]+)', text))[-1]
            return text[:last.start(1)] + str(int(last.group(1)) + 2) + text[last.end(1):]
        variants = {"original": xml,
                    "wrong-block-hash": change_blocks(xml, selected_name, lambda text: text.replace('Hash="' + block.get("Hash") + '"', 'Hash="' + wrong_hash + '"', 1)),
                    "extent-overshoot": change_blocks(xml, selected_name, lambda text: re.sub(r'(<Block\b[^>]*\bSize=")[^"]+', lambda m: m.group(1) + str(len(selected_compressed) + 1), text, count=1)),
                    "missing-size": change_blocks(xml, selected_name, lambda text: re.sub(r'(<Block\b[^>]*) Size="[^"]+"', r'\1', text, count=1)),
                    "other-terminator": xml,
                    "terminator-in-last-block": change_blocks(xml, selected_name, include_tail)}
        multi = next((f for f in files if by_name[f.get("Name").replace("\\", "/")][0] == 8 and len(f.findall(NS + "Block")) > 1), None)
        if multi is not None:
            def shift(text):
                at = 0
                def size(match):
                    nonlocal at
                    at += 1
                    return match.group(1) + str(int(match.group(2)) + (1 if at == 1 else -1 if at == 2 else 0))
                return re.sub(r'(<Block\b[^>]*\bSize=")([0-9]+)', size, text)
            variants["shifted-boundary"] = change_blocks(xml, multi.get("Name"), shift)
        observed = independent(entries, xml)
        cases = []
        for case, current_xml in variants.items():
            folder = output / (name + "-" + case)
            folder.mkdir()
            current_entries = []
            for filename, method, plain, compressed in entries:
                if filename == "AppxBlockMap.xml":
                    plain = current_xml.encode("utf-8")
                    compressed = deflate(plain)
                if case == "other-terminator" and filename == selected_path:
                    assert compressed.endswith(b"\x03\x00")
                    compressed = compressed[:-2] + b"\x01\x00\x00\xff\xff"
                    assert zlib.decompress(compressed, -15) == plain
                current_entries.append((filename, method, plain, compressed))
                target = folder / "content" / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(plain)
            package_path = source if case == "original" else folder / "case.msix"
            independent_variant = independent(current_entries, current_xml) if case in ("other-terminator", "terminator-in-last-block") else None
            if case != "original":
                package_path.write_bytes(package(current_entries))
            try:
                native = reference.native(folder / "content/AppxBlockMap.xml", folder / "content")
                native = [{"name": n["name"], "content_matches": n["content_matches"], "validation_hresult": n.get("validation_hresult"), "blocks": n["blocks"]} for n in native]
            except OSError as error:
                native = {"reader_error": str(error)}
            before = package_path.read_bytes()
            destination = folder / "report"
            for repeat in range(2):
                done = subprocess.run([cli, str(package_path), "-o", str(destination), "--format", "json,md,html", *no_ai], capture_output=True, timeout=120, creationflags=flags)
                assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
                report_bytes = (destination / "report.json").read_bytes()
                if repeat == 0:
                    previous = report_bytes
                else:
                    assert report_bytes == previous
            report = json.loads(report_bytes)
            parent = next(a for a in report["artifacts"] if "windows.msix-zip-blocks" in a["facts"])
            checked = parent["facts"]["windows.msix-zip-blocks"]
            declaration_source = next(a for a in report["artifacts"] if "windows.msix-blockmap" in a["facts"])
            declared_files = declaration_source["facts"]["windows.msix-blockmap"]["files"]
            if isinstance(native, list):
                by_native_name = {n["name"].replace("\\", "/").lower(): n for n in native}
                for record in checked["files"]:
                    declared = declared_files[record["file"]]
                    native_file = by_native_name[declared["path"].lower()]
                    for witness in record.get("witnesses", []):
                        native_block = native_file["blocks"][witness["block"]]
                        assert witness["expected_hash"] == native_block["digest"]
                        if witness["declared_compressed_size"] is not None:
                            assert witness["declared_compressed_size"] == native_block["native_compressed_size"]
                if case == "original":
                    assert all(n["content_matches"] for n in native)
            else:
                assert case == "missing-size", native
            expected_mismatch = case in ("wrong-block-hash", "extent-overshoot")
            expected_unresolved = case in ("missing-size", "shifted-boundary")
            assert checked["files_with_mismatches"] == int(expected_mismatch), (name, case, checked)
            assert checked["files_unresolved"] == int(expected_unresolved), (name, case, checked)
            assert checked["files_with_matching_blocks"] == len(files) - int(expected_mismatch) - int(expected_unresolved)
            assert checked["files_with_verified_block_spans"] == len(files) - int(case == "extent-overshoot") - int(expected_unresolved)
            assert not checked["package_signature_checked"] and not checked["windows_trust_checked"]
            assert any(f["rule"] == "windows.msix-zip-block-mismatch" for f in report["findings"]) == expected_mismatch
            markdown = (destination / "report.md").read_text(encoding="utf-8")
            assert "MSIX original block extents and content correspond" in markdown
            if expected_mismatch:
                assert "MSIX original blocks differ from declarations" in markdown
            assert "windows.msix-zip-blocks" in (destination / "report.html").read_text(encoding="utf-8")
            assert package_path.read_bytes() == before
            cases.append({"case": case, "mismatches": checked["files_with_mismatches"], "unresolved": checked["files_unresolved"],
                          "native": native, "independent_variant_spans": independent_variant, "repeated_json_identical": True, "input_unchanged": True})
        assert source.read_bytes() == original
        chinese = output / (name + "-wrong-block-zh")
        done = subprocess.run([cli, str(output / (name + "-wrong-block-hash/case.msix")), "-o", str(chinese), "--format", "md", "--lang", "zh", *no_ai],
                              capture_output=True, timeout=120, creationflags=flags)
        assert done.returncode in (0, 2)
        assert "MSIX 原始分块与声明不符" in (chinese / "report.md").read_text(encoding="utf-8")
        results.append({"sample": name, "sha256": hashlib.sha256(original).hexdigest(), "original_independent_spans": observed, "cases": cases})
    (output / "checks.json").write_text(json.dumps({"samples": results, "negative_cases_native_qualified": False}, indent=2) + "\n", encoding="utf-8")
    print("compared", sum(len(r["cases"]) for r in results), "raw block/profile cases and native declarations")


if __name__ == "__main__":
    main()
