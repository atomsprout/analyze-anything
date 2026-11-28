#!/usr/bin/env python3
"""Static wheel/npm/JAR references: stdlib ZIP/TAR plus native jar/tar listings.

No package is installed, imported or added to a runtime classpath; scripts and
entry-point declarations are metadata only.
"""
import argparse
import configparser
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def run(args):
    return subprocess.run([str(arg) for arg in args], check=True, capture_output=True).stdout


def digest(body):
    return hashlib.sha256(body).hexdigest()


def reference(sample):
    body = sample.read_bytes()
    record = {"file": sample.name, "sha256": digest(body), "size": len(body)}
    members = []
    if sample.suffix in (".whl", ".jar"):
        with zipfile.ZipFile(sample) as archive:
            names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
            if len(names) != len(set(names)):
                raise ValueError("reference requires unique ZIP names")
            for name in names:
                data = archive.read(name)
                members.append({"path": name, "size": len(data), "sha256": digest(data)})
            if sample.suffix == ".whl":
                controls = [name for name in names if name.endswith(".dist-info/METADATA") and name.count("/") == 1]
                if len(controls) != 1:
                    raise ValueError("reference requires exactly one wheel METADATA")
                root = controls[0].rsplit("/", 1)[0]
                metadata = BytesParser().parsebytes(archive.read(controls[0]), headersonly=True)
                wheel = BytesParser().parsebytes(archive.read(root + "/WHEEL"), headersonly=True)
                unfold = lambda value: re.sub(r"\r?\n[ \t]+", " ", value).strip()
                points = []
                if root + "/entry_points.txt" in names:
                    parser = configparser.ConfigParser(interpolation=None)
                    parser.optionxform = str
                    parser.read_string(archive.read(root + "/entry_points.txt").decode("utf-8"))
                    points = [{"group": group, "name": name, "target": value}
                              for group in parser.sections() for name, value in parser.items(group)]
                record.update(kind="wheel", name=metadata["Name"], version=metadata["Version"],
                              dependencies=[unfold(value) for value in metadata.get_all("Requires-Dist", [])],
                              tags=wheel.get_all("Tag", []), entry_points=points)
            else:
                record["kind"] = "java"
        if jar := shutil.which("jar"):
            listing = run([jar, "--list", "--file", sample]).decode("utf-8").splitlines()
            if sorted(name for name in listing if not name.endswith("/")) != sorted(names):
                raise AssertionError("native jar tool disagrees with ZIP member enumeration")
            record["native_listing"] = "jar --list --file"
    else:
        with tarfile.open(sample, "r:gz") as archive:
            for entry in archive:
                if entry.isfile():
                    data = archive.extractfile(entry).read()
                    members.append({"path": entry.name, "size": len(data), "sha256": digest(data)})
                    if entry.name == "package/package.json":
                        metadata = json.loads(data)
            record.update(kind="npm", name=metadata["name"], version=metadata["version"], scripts=metadata.get("scripts", {}),
                          dependencies={group: metadata.get(group, {}) for group in
                                        ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")})
        if tar := shutil.which("tar"):
            listing = run([tar, "-tf", sample]).decode("utf-8").splitlines()
            if any(entry["path"] not in listing for entry in members):
                raise AssertionError("native tar tool omitted a regular member")
            record["native_listing"] = "tar -tf"
    record["members"] = sorted(members, key=lambda entry: entry["path"])
    return record


def compare(cli, sample, native):
    help_text = run([cli, "analyze", "--help"]).decode("utf-8")
    with tempfile.TemporaryDirectory(prefix="aa-language-package-reference-") as folder:
        args = [str(cli), str(sample), "-o", folder, "--format", "json"]
        if "--no-ai" in help_text:
            args.append("--no-ai")
        result = subprocess.run(args, capture_output=True, check=False)
        path = Path(folder) / "report.json"
        if result.returncode not in (0, 2) or not path.is_file():
            raise RuntimeError(result.stderr.decode(errors="replace"))
        report = json.loads(path.read_text(encoding="utf-8"))
    key = {"wheel": "wheel.package", "npm": "npm.package", "java": "java.jar"}[native["kind"]]
    package = next((artifact for artifact in report["artifacts"] if key in artifact["facts"]), None)
    if package is None:
        raise AssertionError(f"no {key} fact: {report['limitations']!r}")
    value = package["facts"][key]
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {expected!r}")

    root = next(artifact for artifact in report["artifacts"] if artifact["parent"] is None)
    check("input SHA-256", root["digests"]["sha256"], native["sha256"])
    inventory = [{key: member[key] for key in ("path", "size", "sha256")} for member in value["inventory"]["members"]]
    check("every captured member name/size/SHA-256", inventory, native["members"])
    if native["kind"] in ("wheel", "npm"):
        for field in ("name", "version"):
            check("declared " + field, value[field], native[field])
    if native["kind"] == "wheel":
        check("literal Requires-Dist", [row["declaration"] for row in value["dependencies"]], native["dependencies"])
        check("wheel tags", value["tags"], native["tags"])
        points = [{key: point[key] for key in ("group", "name", "target")} for point in value["entry_points"] or []]
        check("entry-point metadata", points, native["entry_points"])
    elif native["kind"] == "npm":
        dependencies = {group: {} for group in native["dependencies"]}
        for row in value["dependencies"]:
            dependencies[row["group"]][row["name"]] = row["declaration"]
        check("literal dependency groups", dependencies, native["dependencies"])
        check("literal script declarations", {row["name"]: row["declaration"] for row in value["scripts"]}, native["scripts"])
    native["checks"] = checks
    return len(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    if not args.native_only and args.cli is None:
        parser.error("--cli required unless --native-only is selected")
    records = []
    checks = 0
    for sample in args.samples:
        native = reference(sample.resolve())
        if not args.native_only:
            checks += compare(args.cli.resolve(), sample.resolve(), native)
        records.append(native)
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps({"records": records}, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(records)} package references; {checks} analyzer checks")


if __name__ == "__main__":
    main()
