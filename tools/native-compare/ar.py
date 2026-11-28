#!/usr/bin/env python3
"""Compare stored ar contents with ar/nm. Never extract, link or run input members.

Use --native-only to capture the independent reference before building the analyzer.
Thin archives are deliberately refused: a native tool could follow their host references.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args):
    environment = dict(os.environ, LC_ALL="C", TZ="UTC")
    return subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=environment).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def version(command):
    lines = run([command, "--version"]).decode("utf-8").splitlines()
    return next((line.strip() for line in lines if "version" in line.lower()), lines[0])


def reference(sample, ar, nm):
    data = sample.read_bytes()
    if data.startswith(b"!<thin>\n"):
        raise ValueError(f"{sample.name}: thin references are not passed to native tools")
    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"{sample.name}: not a normal ar archive")
    names = run([ar, "t", "--", sample]).decode("utf-8").splitlines()
    if len(names) != len(set(names)):
        raise ValueError(f"{sample.name}: this reference tool requires unique member names")
    if any(name.startswith(("-", "@")) for name in names):
        raise ValueError(f"{sample.name}: native reference arguments require literal member names")
    members = []
    symbol_index_members = []
    for name in names:
        contents = run([ar, "p", "--", sample, name])
        row = {"name": name, "size": len(contents), "sha256": digest(contents)}
        # GNU ar lists BSD indexes as members; LLVM hides them. Keep their bytes
        # separately so both tools describe the same ordinary member set.
        if name in {"__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"}:
            symbol_index_members.append(row)
        else:
            members.append(row)
    symbol_map = []
    in_map = False
    for line in run([nm, "--print-armap", sample]).decode("utf-8").splitlines():
        if line in ("Archive map", "Archive index:"):
            in_map = True
        elif in_map:
            if " in " not in line:
                break
            symbol, member = line.rsplit(" in ", 1)
            symbol_map.append({"name": symbol, "member": member})
    return {"file": sample.name, "sha256": digest(data), "size": len(data),
            "members": members, "symbol_index_members": symbol_index_members, "symbol_map": symbol_map}


def compare(cli, sample, native):
    with tempfile.TemporaryDirectory(prefix="aa-ar-reference-") as folder:
        help_text = subprocess.run([str(cli), "analyze", "--help"], capture_output=True, check=True).stdout
        offline = ["--no-ai"] if b"--no-ai" in help_text else []
        result = subprocess.run([str(cli), str(sample), "-o", folder, "--format", "json", *offline],
                                capture_output=True, check=False)
        if result.returncode not in (0, 2) or not (Path(folder) / "report.json").is_file():
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
        report = json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))
    root = next(artifact for artifact in report["artifacts"] if artifact["parent"] is None)
    archive = root["facts"].get("ar.directory")
    if archive is None:
        raise AssertionError(f"{sample.name}: no ar directory: {report['limitations']!r}")
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {expected!r}")

    check("archive SHA-256", root["digests"]["sha256"], native["sha256"])
    check("normal archive", archive["thin"], False)
    members = [member for member in archive["members"] if member["kind"] == "member"]
    check("member names and order", [member["name"] for member in members], [member["name"] for member in native["members"]])
    for actual, expected in zip(members, native["members"]):
        label = expected["name"]
        check("declared size: " + label, actual["size"], expected["size"])
        child = next((artifact for artifact in report["artifacts"]
                      if artifact["path"] == root["path"] + "/" + label and artifact["parent"] == root["path"]), None)
        check("member SHA-256: " + label, None if child is None else child["digests"]["sha256"], expected["sha256"])
    headers = {member["header_offset"]: member["name"] for member in members}
    if all(index["entries"] is not None for index in archive["symbol_indexes"]):
        symbols = [{"name": symbol["name"], "member": headers.get(symbol["member_header_offset"])}
                   for index in archive["symbol_indexes"] for symbol in index["entries"]["symbols"]]
        check("symbol-index names and member declarations", symbols, native["symbol_map"])
    else:
        check("unsupported index has an explicit limitation",
              any(limit["code"] == "ar.symbol-index-unread" for limit in report["limitations"]), True)
    native["checks"] = checks
    return len(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--ar", default="ar")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    if not args.native_only and args.cli is None:
        parser.error("--cli is required unless --native-only is given")
    records = []
    total = 0
    for sample in args.samples:
        native = reference(sample.resolve(), args.ar, args.nm)
        if not args.native_only:
            total += compare(args.cli.resolve(), sample.resolve(), native)
        records.append(native)
    result = {"tools": {"ar": version(args.ar), "nm": version(args.nm)}, "records": records}
    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(records)} archive references" if args.native_only else f"Passed {total} ar checks over {len(records)} archives")


if __name__ == "__main__":
    main()
