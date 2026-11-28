#!/usr/bin/env python3
"""Generate inert native-writer LZ4 frames and compare their read-only reports."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def run(arguments):
    return subprocess.run([str(value) for value in arguments], capture_output=True, check=True, timeout=120).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cli = args.cli.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    offline = ["--no-ai"] if b"--no-ai" in run([cli, "analyze", "--help"]) else []
    contents = (b"Analyze Anything native LZ4 fixture. Project-authored Apache-2.0 data.\n" * 3000)
    checks = []
    records = []

    def check(name, actual, expected):
        matches = actual == expected
        checks.append({"check": name, "matches": matches})
        if not matches:
            raise AssertionError(f"{name}: {actual!r} != {expected!r}")

    profiles = [
        ("default", ["-B4"], contents),
        ("all-checksums", ["-B4", "-BX", "--content-size"], contents),
        ("no-content-checksum", ["-B5", "--no-frame-crc"], contents),
        ("short-stored", ["-B4", "-BX", "--content-size"], b"abc"),
    ]
    for name, flags, source in profiles:
        plain = output / f"{name}.txt"
        sample = output / f"{name}.txt.lz4"
        plain.write_bytes(source)
        run(["lz4", "-q", "-f", *flags, plain, sample])
        check(f"{name}: native decompression agrees with original data", run(["lz4", "-q", "-d", "-c", sample]), source)
        with tempfile.TemporaryDirectory(prefix="aa-native-lz4-") as temporary:
            result = subprocess.run([str(cli), str(sample), "-o", temporary, "--format", "json", *offline], capture_output=True, timeout=120)
            report_path = Path(temporary) / "report.json"
            if result.returncode not in (0, 2) or not report_path.is_file():
                raise RuntimeError(result.stderr.decode(errors="replace"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
        root = next(artifact for artifact in report["artifacts"] if artifact["parent"] is None)
        children = [artifact for artifact in report["artifacts"] if artifact["parent"] == root["path"]]
        check(f"{name}: LZ4 identity", root["kind"], "lz4")
        check(f"{name}: complete captured child count", len(children), 1)
        check(f"{name}: captured output size", children[0]["size"], len(source))
        check(f"{name}: captured output SHA-256", children[0]["digests"]["sha256"], sha(source))
        check(f"{name}: complete frame decoding", root["facts"]["lz4.frame"]["complete_decoding"], True)
        check(f"{name}: header checksum", root["facts"]["lz4.frame"]["header_checksum_matches"], True)
        check(f"{name}: declared checksums checked", root["facts"]["lz4.frame"]["declared_checksums_checked"], True)
        check(f"{name}: checksum agreement does not authenticate", root["facts"]["lz4.frame"]["authenticated"], False)
        check(f"{name}: original frame digest", root["digests"]["sha256"], sha(sample.read_bytes()))
        records.append({"file": sample.name, "sha256": sha(sample.read_bytes()), "source_sha256": sha(source),
                        "source_size": len(source), "writer_flags": flags, "header": root["facts"]["lz4.frame"]})
    reference = {"source_license": "Apache-2.0", "native_writer": run(["lz4", "--version"]).decode().strip(),
                 "checks": checks, "passed": len(checks), "samples": records}
    (output / "reference.json").write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": len(checks), "samples": len(records)}))


if __name__ == "__main__":
    main()
