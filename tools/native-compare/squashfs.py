#!/usr/bin/env python3
"""Read-only SquashFS comparison using 7-Zip; nothing is mounted or executed."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def run(args):
    return subprocess.run([str(arg) for arg in args], check=True, capture_output=True).stdout


def reference(sample, sevenzip):
    data = sample.read_bytes()
    listing = run([sevenzip, "l", "-slt", "-sccUTF-8", sample]).decode("utf-8").replace("\r\n", "\n")
    header, separator, records = listing.partition("----------")
    if not separator or "Type = SquashFS" not in header:
        raise ValueError("7-Zip did not identify the input as SquashFS")
    entries = []
    for record in records.strip().split("\n\n"):
        values = dict(line.split(" = ", 1) for line in record.splitlines() if " = " in line)
        if "Path" not in values:
            continue
        name = values["Path"].replace("\\", "/")
        if name.startswith(("-", "@")):
            raise ValueError("native reference requires literal member arguments")
        entry = {"path": name, "type": "directory" if values["Folder"] == "+" else "file",
                 "mode": values.get("Mode"), "uid": int(values.get("User ID", 0)), "gid": int(values.get("Group ID", 0))}
        permissions = entry["mode"][1:]
        mode_bits = sum(1 << (8-index) for index, char in enumerate(permissions) if char in "rwxst")
        mode_bits |= 0o4000 if permissions[2] in "sS" else 0
        mode_bits |= 0o2000 if permissions[5] in "sS" else 0
        mode_bits |= 0o1000 if permissions[8] in "tT" else 0
        entry["mode_bits"] = mode_bits
        if entry["mode"].startswith("l"):
            entry["type"] = "symlink"
            entry["link_target"] = run([sevenzip, "x", "-so", "-y", sample, values["Path"]]).decode("utf-8")
        if entry["type"] == "file":
            contents = run([sevenzip, "x", "-so", "-y", sample, values["Path"]])
            entry.update(size=len(contents), sha256=hashlib.sha256(contents).hexdigest())
        entries.append(entry)
    return {"file": sample.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "tool": header.strip().splitlines()[0], "entries": sorted(entries, key=lambda entry: entry["path"])}


def compare(cli, sample, native):
    help_text = run([cli, "analyze", "--help"]).decode("utf-8")
    with tempfile.TemporaryDirectory(prefix="aa-squashfs-native-") as folder:
        args = [str(cli), str(sample), "-o", folder, "--format", "json"]
        if "--no-ai" in help_text:
            args.append("--no-ai")
        result = subprocess.run(args, capture_output=True, check=False)
        report_path = Path(folder) / "report.json"
        if result.returncode not in (0, 2) or not report_path.is_file():
            raise RuntimeError(result.stderr.decode(errors="replace"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    root = next(artifact for artifact in report["artifacts"] if artifact["parent"] is None)
    filesystem = next((artifact for artifact in report["artifacts"] if "squashfs.directory" in artifact["facts"]), None)
    if filesystem is None:
        raise AssertionError(f"no SquashFS directory: {report['limitations']!r}")
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{label}: {actual!r} != {expected!r}")

    check("input SHA-256", root["digests"]["sha256"], native["sha256"])
    actual = filesystem["facts"]["squashfs.directory"]["entries"]
    check("paths/types", [(entry["path"], entry["type"]) for entry in actual],
          [(entry["path"], entry["type"]) for entry in native["entries"]])
    for expected in native["entries"]:
        observed = next(entry for entry in actual if entry["path"] == expected["path"])
        check("owner: " + expected["path"], [observed["uid"], observed["gid"]], [expected["uid"], expected["gid"]])
        check("mode: " + expected["path"], observed["mode"], expected["mode_bits"])
        if expected["type"] == "symlink":
            check("link target: " + expected["path"], observed["link_target"], expected["link_target"])
        if expected["type"] == "file":
            artifact = next((artifact for artifact in report["artifacts"]
                             if artifact["path"] == filesystem["path"] + "/" + expected["path"]), None)
            check("size: " + expected["path"], observed["size"], expected["size"])
            check("SHA-256: " + expected["path"], None if artifact is None else artifact["digests"]["sha256"], expected["sha256"])
    native["checks"] = checks
    return len(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--sevenzip", default="7z")
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    if not args.native_only and args.cli is None:
        parser.error("--cli required unless --native-only is used")
    references = []
    checks = 0
    for sample in args.samples:
        record = reference(sample.resolve(), args.sevenzip)
        if not args.native_only:
            checks += compare(args.cli.resolve(), sample.resolve(), record)
        references.append(record)
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps({"records": references}, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(references)} native references; {checks} analyzer checks")


if __name__ == "__main__":
    main()
