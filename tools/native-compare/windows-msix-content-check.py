"""Compare MSIX content checks with native declarations and independent byte hashing.

No package is deployed, no input is executed, and no signature/trust decision is inferred.
Repacked negative cases check uncompressed content, not validity of their ZIP layouts.
"""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import warnings
import xml.etree.ElementTree as ET
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("AppxPackaging comparison requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output, sample = args.output.resolve(), args.sample.resolve()
    if not output.is_relative_to(repository / "out") or sample.is_relative_to(output):
        parser.error("output must be below this checkout's out directory and must not contain the sample")
    if sample.stat().st_size > 16 * 1024 * 1024:
        parser.error("controlled package reference exceeds 16 MiB")
    before = sample.read_bytes()
    files = {}
    with zipfile.ZipFile(io.BytesIO(before)) as archive:
        if len(archive.infolist()) > 4096:
            parser.error("too many reference entries")
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = entry.filename
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name or name in files:
                parser.error("source reference must have unique ordinary relative ZIP names")
            if entry.file_size > 64 * 1024 * 1024 or sum(len(b) for b in files.values()) + entry.file_size > 512 * 1024 * 1024:
                parser.error("source reference exceeds the content byte budget")
            files[name] = archive.read(entry)
    xml = files["AppxBlockMap.xml"].decode("utf-8")
    root = ET.fromstring(xml)
    algorithm = {"http://www.w3.org/2001/04/xmlenc#sha256": "sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
                 "http://www.w3.org/2001/04/xmlenc#sha512": "sha512"}[root.get("HashMethod")]
    declarations = list(root)
    payload = max(declarations, key=lambda row: int(row.get("Size")))
    payload_name = payload.get("Name").replace("\\", "/")
    first_hash = payload.find("{http://schemas.microsoft.com/appx/2010/blockmap}Block").get("Hash")
    whole = payload.find("{http://schemas.microsoft.com/appx/2021/blockmap}FileHash")
    cases = ["original", "changed-payload", "changed-block-hash", "missing", "duplicate"]
    if whole is not None:
        cases.append("changed-file-hash")
    spec = importlib.util.spec_from_file_location("msix_reference", Path(__file__).with_name("windows-msix-blockmap.py"))
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    cli = str(args.cli.resolve())
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for case in cases:
        content = files.copy()
        if case == "changed-payload":
            data = bytearray(content[payload_name])
            data[-1] ^= 1
            content[payload_name] = bytes(data)
        elif case in ("changed-block-hash", "changed-file-hash"):
            old = first_hash if case == "changed-block-hash" else whole.get("Hash")
            wrong = base64.b64encode(bytes(len(base64.b64decode(old)))).decode("ascii")
            content["AppxBlockMap.xml"] = xml.replace(old, wrong, 1).encode("utf-8")
        elif case == "missing":
            del content[payload_name]
        folder = output / (case + "-content")
        if folder.is_symlink() or folder.is_junction():
            raise ValueError("reference folder redirects through a link or junction")
        folder.mkdir(exist_ok=True)
        if {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()} - content.keys():
            raise ValueError("unexpected existing reference files; choose a fresh output directory")
        for name, data in content.items():
            destination = folder / name
            if not destination.resolve().is_relative_to(folder.resolve()) or destination.is_symlink() or destination.is_junction():
                raise ValueError("reference file path redirects outside its controlled folder")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        package = output / (case + ".msix")
        if package.is_symlink() or package.is_junction() or not package.resolve().is_relative_to(output):
            raise ValueError("controlled package path redirects outside the output")
        if case == "original":
            package.write_bytes(before)
        else:
            with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in content.items():
                    archive.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data)
                if case == "duplicate":
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        archive.writestr(zipfile.ZipInfo(payload_name, (1980, 1, 1, 0, 0, 0)), content[payload_name])
        package_before = package.read_bytes()
        native = reference.native(folder / "AppxBlockMap.xml", folder)
        current_root = ET.fromstring(content["AppxBlockMap.xml"])
        for item in native:
            name = item["name"].replace("\\", "/")
            if name not in content:
                continue
            data = content[name]
            computed = [hashlib.new(algorithm, data[i:i + 65536]).hexdigest() for i in range(0, len(data), 65536)]
            item["block_hashes_match_bytes"] = computed == [block["digest"] for block in item["blocks"]]
            declaration = next(f for f in current_root if f.get("Name") == item["name"])
            whole_hash = declaration.find("{http://schemas.microsoft.com/appx/2021/blockmap}FileHash")
            item["file_hash_matches_bytes"] = None if whole_hash is None else base64.b64decode(whole_hash.get("Hash")) == hashlib.new(algorithm, data).digest()
            item["all_declarations_match_bytes"] = len(data) == item["size"] and item["block_hashes_match_bytes"] and item["file_hash_matches_bytes"] is not False
        destination = output / (case + "-report")
        command = [cli, str(package), "-o", str(destination), "--format", "json,md,html", *no_ai]
        for repeat in range(2):
            done = subprocess.run(command, capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
            if done.returncode not in (0, 2):
                raise RuntimeError(done.stderr.decode("utf-8", errors="replace"))
            raw = (destination / "report.json").read_bytes()
            if repeat == 0:
                first = raw
            else:
                assert first == raw, "repeated report differs"
        report = json.loads(raw)
        source = next(a for a in report["artifacts"] if a["path"].endswith("/AppxBlockMap.xml"))
        comparisons = source["facts"]["windows.msix-blockmap-checks"]
        assert not comparisons["package_signature_checked"] and not comparisons["zip_structure_checked"]
        assert not comparisons["compressed_block_sizes_checked"] and not comparisons["windows_trust_checked"]
        for expected in native:
            row = next(r for r in comparisons["files"] if r["name"] == expected["name"])
            if case == "duplicate":
                assert row["status"] == "unresolved"
            elif expected.get("reason") == "file-not-supplied":
                assert row["status"] == "unresolved"
            else:
                assert expected["validation_hresult"] == "0x00000000"
                assert row["status"] == ("hashes-agree" if expected["all_declarations_match_bytes"] else "size-or-content-hash-mismatch")
                assert row["target_sha256"] == expected["sha256"]
        assert any(f["rule"] == "windows.msix-content-hash-mismatch" for f in report["findings"]) == case.startswith("changed")
        if case == "duplicate":
            assert any(l["code"] == "zip.entry-names-duplicated" for l in report["limitations"])
        assert "windows.msix-blockmap-checks" in (destination / "report.html").read_text(encoding="utf-8")
        assert "MSIX block-map declarations" in (destination / "report.md").read_text(encoding="utf-8")
        assert package.read_bytes() == package_before
        for name, data in content.items():
            assert (folder / name).read_bytes() == data
        results.append({"case": case, "native": native, "repeated_json_identical": True, "inputs_unchanged": True,
                        "native_file_validation_differs_from_all_declarations": any(n.get("all_declarations_match_bytes") is not None and
                            n.get("content_matches") != n["all_declarations_match_bytes"] for n in native),
                        "matching_files": comparisons["files_with_matching_hashes"], "mismatching_files": comparisons["files_with_mismatches"],
                        "unresolved_files": comparisons["files_unresolved"]})
    chinese = output / "zh-report"
    done = subprocess.run([cli, str(output / "original.msix"), "-o", str(chinese), "--format", "md", "--lang", "zh", *no_ai],
                          capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
    assert done.returncode in (0, 2)
    assert "MSIX 分块摘要声明" in (chinese / "report.md").read_text(encoding="utf-8")
    assert sample.read_bytes() == before
    (output / "checks.json").write_text(json.dumps({"sample": sample.name, "sha256": hashlib.sha256(before).hexdigest(),
                                                    "cases": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("compared", len(cases), "content cases with native declarations and independent hashing for", sample.name)


if __name__ == "__main__":
    main()
