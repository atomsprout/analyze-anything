#!/usr/bin/env python3
"""Read-only Alpine v2 references: exact zlib members, TAR, gzip and bsdtar."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zlib


def run(arguments):
    return subprocess.run([str(value) for value in arguments], check=True, capture_output=True, timeout=120).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def logical(name):
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def reference(path):
    source = path.read_bytes()
    layers = []
    at = 0
    seen_control = False
    while at < len(source):
        decoder = zlib.decompressobj(31)
        data = decoder.decompress(source[at:], 129 * 1024 * 1024)
        if not decoder.eof or decoder.unconsumed_tail:
            raise ValueError("reference gzip stream is truncated or exceeds its output bound")
        length = len(source) - at - len(decoder.unused_data)
        entries = []
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            for member in tar:
                entry = {"path": member.name, "type": member.type[0], "size": member.size, "mode": member.mode,
                         "uid": member.uid, "gid": member.gid, "link_target": member.linkname or None,
                         "pax": dict(member.pax_headers)}
                if member.isfile():
                    body = tar.extractfile(member).read()
                    entry["sha256"] = sha(body)
                    entry["sha1"] = hashlib.sha1(body).hexdigest()
                    if member.name == ".PKGINFO":
                        entry["control_text"] = body.decode("utf-8")
                entries.append(entry)
        if not seen_control and entries and all(entry["path"].startswith(".SIGN.") and "/" not in entry["path"] for entry in entries):
            role = "signature"
        elif not seen_control:
            role = "control"
            seen_control = True
        else:
            role = "payload"
        layers.append({"role": role, "offset": at, "compressed_size": length, "decoded_size": len(data),
                       "decoded_sha256": sha(data), "entries": entries})
        at += length
    return {"file": path.name, "sha256": sha(source), "size": len(source), "layers": layers}


def analyze(cli, sample, no_ai):
    with tempfile.TemporaryDirectory(prefix="aa-alpine-reference-") as folder:
        arguments = [str(cli), str(sample), "-o", folder, "--format", "json"]
        if no_ai:
            arguments.append("--no-ai")
        process = subprocess.run(arguments, capture_output=True, timeout=180)
        if process.returncode not in (0, 2):
            raise RuntimeError(process.stderr.decode(errors="replace"))
        return json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))


def verify(cli, sample, no_ai, native=False, apk_manifest=None, gzip_tool="gzip", tar_tool="bsdtar"):
    expected = reference(sample)
    report = analyze(cli, sample, no_ai)
    root = next(file for file in report["artifacts"] if file["parent"] is None)
    container = root["facts"]["alpine-apk.container"]
    checks = []

    def check(name, actual, value):
        matches = actual == value
        checks.append({"check": name, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {name}: {actual!r} != {value!r}")

    check("input SHA-256", root["digests"]["sha256"], expected["sha256"])
    check("exact gzip member count", len(container["layers"]), len(expected["layers"]))
    check("complete entry previews", container["entry_preview_complete"], True)
    check("no omitted entries", container["entries_omitted"], 0)
    check("shared output preview complete", root["facts"]["alpine-apk.output"]["preview_truncated"], False)
    for index, layer in enumerate(expected["layers"]):
        observed = container["layers"][index]
        for field in ("role", "offset", "compressed_size", "decoded_size", "decoded_sha256"):
            check(f"layer {index}: {field}", observed[field], layer[field])
        check(f"layer {index}: total entries", observed["entries_total"], len(layer["entries"]))
        check(f"layer {index}: retained entries", observed["entries_retained"], len(layer["entries"]))
        check(f"layer {index}: omitted entries", observed["entries_omitted"], 0)
        check(f"layer {index}: complete entry preview", observed["entry_preview_complete"], True)
        check(f"layer {index}: paths", [logical(entry["path"]) for entry in observed["entries"]], [logical(entry["path"]) for entry in layer["entries"]])
        for entry, found in zip(layer["entries"], observed["entries"]):
            for field in ("type", "size", "mode", "uid", "gid", "link_target"):
                check(f"layer {index}/{entry['path']}: {field}", found[field], entry[field])
            if "sha256" in entry:
                child = next((file for file in report["artifacts"] if file["path"] == found["captured_source"]), None)
                check(f"layer {index}/{entry['path']}: regular SHA-256", None if child is None else child["digests"]["sha256"], entry["sha256"])
            if layer["role"] == "control" and entry["path"] == ".PKGINFO":
                fields = [line.split(" = ", 1) for line in entry["control_text"].splitlines() if line and not line.startswith("#")]
                metadata = root["facts"]["alpine-apk.package"]
                check("total control fields", metadata["fields_total"], len(fields))
                check("omitted control fields", metadata["fields_omitted"], 0)
                check("complete control fields", metadata["fields_complete"], True)
                for field, key in [("pkgname", "name"), ("pkgver", "version"), ("arch", "architecture")]:
                    check("control identity: " + field, metadata[key], next(value for name, value in fields if name == field))
                relationships = [(name, value) for name, value in fields if name in ("depend", "provides", "replaces", "install_if", "triggers")]
                check("total relationship fields", metadata["dependency_fields_total"], len(relationships))
                check("omitted relationship fields", metadata["dependency_fields_omitted"], 0)
                check("literal dependency declarations", [(row["name"], row["value"]) for row in metadata["dependencies"]], relationships)
    native_results = {}
    if native:
        run([gzip_tool, "-t", sample])
        paths = run([tar_tool, "-tf", sample]).decode("utf-8").splitlines()
        check("bsdtar full concatenated TAR listing", [logical(path) for path in paths], [logical(entry["path"]) for layer in expected["layers"] for entry in layer["entries"]])
        native_results["gzip_version"] = run([gzip_tool, "--version"]).decode().splitlines()[0]
        native_results["bsdtar_version"] = run([tar_tool, "--version"]).decode().strip()
    if apk_manifest is not None:
        native_lines = apk_manifest.read_text(encoding="utf-8").splitlines()
        hashes = {}
        for line in native_lines:
            match = re.match(r"^(sha1|md5):([0-9a-f]+)\s+(.+)$", line.strip())
            if match:
                hashes[logical(match[3])] = (match[1], match[2])
        payload = next(layer for layer in expected["layers"] if layer["role"] == "payload")
        regular = [entry for entry in payload["entries"] if "sha1" in entry]
        if not regular:
            raise ValueError("no regular payload files for apk manifest comparison")
        for entry in regular:
            check("apk manifest SHA1: " + entry["path"], hashes.get(logical(entry["path"])), ("sha1", entry["sha1"]))
        native_results["apk_manifest_read_only"] = True
    expected.update(checks=checks, passed=len(checks), native=native_results,
                    scope="Exact gzip extents/CRC, TAR declarations, control identity/relationships and every ordinary-file digest; no signature/authentication conclusion")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--native", action="store_true", help="require independent gzip -t and bsdtar read-only inspection")
    parser.add_argument("--gzip", default="gzip", help="native gzip executable")
    parser.add_argument("--bsdtar", default="bsdtar", help="native bsdtar executable")
    parser.add_argument("--apk-manifest", type=Path, help="apk --no-network --allow-untrusted manifest output for the first sample")
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    cli = args.cli.resolve()
    no_ai = "--no-ai" in run([cli, "analyze", "--help"]).decode("utf-8")
    results = [verify(cli, sample.resolve(), no_ai, args.native, args.apk_manifest if index == 0 else None, args.gzip, args.bsdtar) for index, sample in enumerate(args.samples)]
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps({"reference": "Python zlib " + zlib.ZLIB_VERSION + ", tarfile; optional native gzip/bsdtar/apk manifest", "samples": results, "passed": sum(result["passed"] for result in results)}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"samples": len(results), "passed": sum(result["passed"] for result in results)}))


if __name__ == "__main__":
    main()
