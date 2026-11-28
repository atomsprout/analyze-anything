#!/usr/bin/env python3
"""Independent, read-only Linux declaration snapshots; no declared program is run."""

import argparse
import configparser
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def digest(data):
    return hashlib.sha256(data).hexdigest()


def report(cli, sample):
    with tempfile.TemporaryDirectory(prefix="aa-linux-declarations-") as folder:
        help_text = subprocess.run([str(cli), "analyze", "--help"], capture_output=True, check=True).stdout
        offline = ["--no-ai"] if b"--no-ai" in help_text else []
        process = subprocess.run(
            [str(cli), str(sample), "-o", folder, "--format", "json", *offline],
            capture_output=True,
        )
        if process.returncode not in (0, 2) or not (Path(folder) / "report.json").is_file():
            raise RuntimeError(process.stderr.decode(errors="replace"))
        data = json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))
        return next(artifact for artifact in data["artifacts"] if artifact["parent"] is None)


def verify(cli, directory, native=False):
    sources = json.loads((directory / "sources.json").read_text(encoding="utf-8"))
    checks = []
    records = []

    def check(name, actual, expected):
        matches = actual == expected
        checks.append({"check": name, "matches": matches})
        if not matches:
            raise AssertionError(f"{name}: {actual!r} != {expected!r}")

    for item in sources:
        path = directory / item["file"]
        body = path.read_bytes()
        check("pinned source SHA-256: " + path.name, digest(body), item["sha256"])
        if path.suffix not in (".service", ".desktop", ".xml"):
            continue
        artifact = report(cli, path)
        check("CLI input SHA-256: " + path.name, artifact["digests"]["sha256"], digest(body))
        record = {"file": path.name, "sha256": digest(body), "source": item["source"]}
        if path.suffix == ".xml":
            root = ET.fromstring(body)
            check("metainfo root", root.tag, "component")
            identity = root.findtext("id")
            launchables = [{"type": child.get("type"), "value": (child.text or "").strip()} for child in root.findall("launchable")]
            fact = artifact["facts"]["linux.appstream"]
            check("AppStream identity", fact["name"], identity)
            check("AppStream launchables", [{"type": row["attributes"].get("type"), "value": row["value"]} for row in fact["launchables"]], launchables)
            for tag in ("metadata_license", "project_license", "name", "summary"):
                children = [child for child in root.findall(tag) if "{http://www.w3.org/XML/1998/namespace}lang" not in child.attrib]
                actual = [row["value"] for row in fact["declarations"] if row["element"] == tag and row["direct_component_child"] and "xml:lang" not in row["attributes"]]
                check("AppStream " + tag, actual, [(child.text or "").strip() for child in children])
            record.update(reference="Python ElementTree", identity=identity, launchables=launchables)
            validator = ["appstreamcli", "validate", "--no-net", str(path)]
        else:
            parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",), comment_prefixes=("#", ";") if path.suffix == ".service" else ("#",))
            parser.optionxform = str
            parser.read_string(body.decode("utf-8"))
            key = "linux.systemd-unit" if path.suffix == ".service" else "linux.desktop-entry"
            fields = artifact["facts"][key]["fields"]
            # ConfigParser's repeated-key view is used only for the final literal occurrence,
            # never as a claim about systemd's append/reset or effective settings semantics.
            observed = {}
            for field in fields:
                observed[(field["group"], field["key"])] = field["value"]
            references = []
            for group in parser.sections():
                for name, value in parser.items(group, raw=True):
                    if name.startswith(("Exec", "Name")) or name in ("Type", "WantedBy", "Description", "Actions", "Categories"):
                        check(f"{path.name}: {group}/{name}", observed.get((group, name)), value.strip())
                        references.append({"group": group, "key": name, "value": value.strip()})
            record.update(reference="Python ConfigParser, last literal occurrence only", fields=references)
            validator = ["systemd-analyze", "verify", "--man=no", str(path)] if path.suffix == ".service" else ["desktop-file-validate", str(path)]
        if native:
            executable = shutil.which(validator[0])
            if executable is None:
                raise RuntimeError("native validator is required but unavailable: " + validator[0])
            process = subprocess.run(validator, capture_output=True, timeout=60)
            # Verification may reject an unavailable declared executable or an upstream
            # build placeholder. Preserve that result instead of relabelling it a pass.
            record["native_validation"] = {
                "tool": validator[0],
                "arguments": validator[1:-1] + [path.name],
                "exit_code": process.returncode,
                "stdout": process.stdout.decode(errors="replace"),
                "stderr": process.stderr.decode(errors="replace"),
                "input_executed": False,
            }
        records.append(record)
    return {"scope": "Literal selected fields, component identity and launchables; no effective unit, launcher or installation conclusion", "checks": checks, "passed": len(checks), "samples": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parents[2] / "crates/aa-linux/tests/data/declarations")
    parser.add_argument("--native", action="store_true", help="also record systemd-analyze, desktop-file-validate and appstreamcli validation")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    result = verify(args.cli.resolve(), args.fixtures.resolve(), args.native)
    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "samples": len(result["samples"])}))


if __name__ == "__main__":
    main()
