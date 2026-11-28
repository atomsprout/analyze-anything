#!/usr/bin/env python3
"""Read-only Arch package references using bsdtar, zstd and Python tarfile.

No package is installed and no package script is run. Optional pacman -Qip
reads a supplied package file without changing the package database.
"""

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


SELECTED_BUILD_FIELDS = {
    "format", "pkgname", "pkgbase", "pkgver", "pkgarch", "pkgbuild_sha256sum",
    "buildtool", "buildtoolver", "buildenv", "options", "installed",
}
RELATIONSHIPS = {
    "depend", "optdepend", "makedepend", "checkdepend", "provides", "conflict", "replaces",
}


def run(arguments):
    environment = dict(os.environ, LC_ALL="C", LANG="C")
    return subprocess.run([str(argument) for argument in arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=environment).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def logical(path):
    return path.removeprefix("./").rstrip("/")


def decompressed(sample):
    data = sample.read_bytes()
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return run(["zstd", "-dc", "--", sample])
    if data.startswith(b"\x1f\x8b\x08"):
        return gzip.decompress(data)
    if data.startswith(b"\xfd7zXZ\x00"):
        return lzma.decompress(data)
    if data.startswith(b"BZh"):
        return bz2.decompress(data)
    return data


def analyze(cli, sample):
    with tempfile.TemporaryDirectory(prefix="aa-arch-reference-") as folder:
        help_text = subprocess.run([str(cli), "analyze", "--help"], capture_output=True, check=True).stdout
        offline = ["--no-ai"] if b"--no-ai" in help_text else []
        result = subprocess.run([str(cli), str(sample), "-o", folder, "--format", "json", *offline],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode not in (0, 2) or not (Path(folder) / "report.json").is_file():
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return (Path(folder) / "report.json").read_bytes()


def fields(data, base):
    result = []
    offset = base
    for number, raw in enumerate(data.decode("utf-8").splitlines(keepends=True), 1):
        line = raw.rstrip("\r\n").lstrip(" \t")
        length = len(raw.encode("utf-8"))
        if line and not line.startswith("#"):
            name, value = line.split(" = ", 1)
            result.append({"name": name, "value": value, "line": number, "offset": offset, "length": length})
        offset += length
    return result


def verify(cli, sample, bsdtar, pacman):
    first = analyze(cli, sample)
    report = json.loads(first)
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {expected!r}")

    check("repeated report bytes", analyze(cli, sample), first)
    packages = [artifact for artifact in report["artifacts"] if "arch.package" in artifact["facts"]]
    check("one package identity", len(packages), 1)
    package = packages[0]
    metadata = package["facts"]["arch.package"]
    archive = next(artifact for artifact in report["artifacts"] if artifact["path"] == metadata["archive"])
    observed = archive["facts"]["arch.archive-entries"]
    check("complete original archive index", observed["complete"], True)
    payload = decompressed(sample)
    check("captured decompressed TAR SHA-256", archive["digests"]["sha256"], sha(payload))
    native = {"bsdtar": run([bsdtar, "--version"]).decode().strip(), "entries": []}
    names = run([bsdtar, "-tf", sample]).decode("utf-8").splitlines()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as reference:
        members = reference.getmembers()
        check("bsdtar names versus Python reader", [logical(name) for name in names], [logical(entry.name) for entry in members])
        check("TAR entry count", len(observed["entries"]), len(members))
        for actual, entry in zip(observed["entries"], members):
            expected = {"path": logical(entry.name), "offset": entry.offset_data,
                        "size": entry.size, "mode": entry.mode, "type": entry.type[0],
                        "link_target": entry.linkname or None}
            comparable = {key: actual[key] for key in expected}
            comparable["path"] = logical(comparable["path"])
            check("original TAR metadata: " + entry.name, comparable, expected)
            if entry.isfile():
                contents = reference.extractfile(entry).read()
                check("bsdtar member bytes: " + entry.name, run([bsdtar, "-xOf", sample, "--", entry.name]), contents)
                child_path = archive["path"] + "/" + logical(entry.name)
                child = next((artifact for artifact in report["artifacts"] if artifact["path"] == child_path), None)
                check("captured member SHA-256: " + entry.name, None if child is None else child["digests"]["sha256"], sha(contents))
                check("regular member capture status: " + entry.name, actual["captured"], True)
                expected["sha256"] = sha(contents)
            elif entry.issym() or entry.islnk():
                check("link remains declaration: " + entry.name, actual["captured"], False)
            native["entries"].append(expected)
        info = next(entry for entry in members if logical(entry.name) == ".PKGINFO")
        source = reference.extractfile(info).read()
        declared = fields(source, info.offset_data)
        check("PKGINFO ordered fields and source spans", metadata["fields"], declared)
        check("PKGINFO source artifact", metadata["source"], archive["path"])
        check("PKGINFO source member", metadata["member"], ".PKGINFO")
        for key, field in [("name", "pkgname"), ("version", "pkgver"), ("architecture", "arch")]:
            check("declared identity: " + key, metadata[key], next(row["value"] for row in declared if row["name"] == field))
        check("literal relationship declarations", metadata["dependencies"], [row for row in declared if row["name"] in RELATIONSHIPS])
        check("declared license provenance", metadata["declared_licenses"], [row["value"] for row in declared if row["name"] == "license"])
        for entry in members:
            name = logical(entry.name)
            if name == ".BUILDINFO":
                build = fields(reference.extractfile(entry).read(), entry.offset_data)
                check("selected BUILDINFO declarations", package["facts"]["arch.build-info"]["fields"],
                      [row for row in build if row["name"] in SELECTED_BUILD_FIELDS])
            elif name == ".MTREE":
                check("MTREE member digest only", package["facts"]["arch.mtree"]["sha256"], sha(reference.extractfile(entry).read()))
                check("MTREE checksums not verified", package["facts"]["arch.mtree"]["checksums_verified"], False)
            elif name == ".INSTALL":
                declaration = package["facts"]["arch.installation-declaration"]
                check("inert installation source text", declaration["text"], reference.extractfile(entry).read().decode("utf-8"))
                check("script semantics remain unresolved", any(row["code"] == "arch.script-semantics" for row in report["limitations"]), True)
    if pacman:
        native["pacman"] = run([pacman, "--version"]).decode().strip()
        query = run([pacman, "-Qip", "--", sample]).decode("utf-8")
        native["pacman_query"] = query
        for field, key in [("Name", "name"), ("Version", "version"), ("Architecture", "architecture")]:
            value = next(line.split(":", 1)[1].strip() for line in query.splitlines() if line.startswith(field) and ":" in line)
            check("pacman read-only identity: " + field, metadata[key], value)
    return {"sample": sample.name, "sha256": sha(sample.read_bytes()), "native": native, "checks": checks,
            "limitations": [{"code": row["code"], "artifact": row["artifact"]} for row in report["limitations"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--bsdtar", default=shutil.which("bsdtar") or shutil.which("tar"))
    parser.add_argument("--pacman", default=shutil.which("pacman"))
    args = parser.parse_args()
    if not args.bsdtar or "bsdtar" not in run([args.bsdtar, "--version"]).decode():
        parser.error("a libarchive bsdtar executable is required (use --bsdtar)")
    records = [verify(args.cli.resolve(), path.resolve(), args.bsdtar, args.pacman) for path in args.samples]
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{sum(len(record['checks']) for record in records)} native checks passed across {len(records)} Arch packages")


if __name__ == "__main__":
    main()
