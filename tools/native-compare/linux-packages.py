#!/usr/bin/env python3
"""Read-only Linux package references. Samples and package scripts are never installed/run."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import tarfile


def run(args, data=None):
    return subprocess.run([str(arg) for arg in args], input=data, check=True, stdout=subprocess.PIPE).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def logical(name):
    return name.removeprefix("./").lstrip("/")


def analyze(cli, sample):
    with tempfile.TemporaryDirectory(prefix="aa-linux-reference-") as folder:
        result = subprocess.run([str(cli), str(sample), "-o", folder, "--format", "json"], capture_output=True)
        if result.returncode not in (0, 2):
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return json.loads((Path(folder) / "report.json").read_text())


def verify(cli, sample):
    report = analyze(cli, sample)
    root = next(file for file in report["artifacts"] if file["parent"] is None)
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {expected!r}")

    def member(container, name, data):
        path = container["path"] + "/" + logical(name)
        found = next((file for file in report["artifacts"] if file["path"] == path), None)
        check("member SHA-256: " + path, None if found is None else found["digests"]["sha256"], sha(data))
        if found is not None and "deb.installation-declaration" in found["facts"]:
            check("installation declaration text: " + path, found["facts"]["deb.installation-declaration"]["text"], data.decode())

    native = {}
    if sample.suffix == ".deb":
        native["tool"] = run(["dpkg-deb", "--version"]).decode().splitlines()[0]
        for key, field in [("name", "Package"), ("version", "Version"), ("architecture", "Architecture")]:
            value = run(["dpkg-deb", "--field", sample, field]).decode().rstrip("\n")
            native[key] = value
            check("control identity: " + field, root["facts"]["deb.control"][key], value)
        native["archives"] = []
        for option, field in [("--ctrl-tarfile", "control_member"), ("--fsys-tarfile", "data_member")]:
            data = run(["dpkg-deb", option, sample])
            member_name = root["facts"]["deb.package"][field]
            original = root["path"] + "/" + member_name
            tar = next(file for file in report["artifacts"] if "deb.archive-entries" in file["facts"]
                       and (file["path"] == original or file["parent"] == original))
            rows = []
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for entry in archive:
                    row = {"path": entry.name, "size": entry.size, "mode": entry.mode, "type": entry.type[0],
                           "link_target": entry.linkname or None}
                    if entry.isfile():
                        contents = archive.extractfile(entry).read()
                        row["sha256"] = sha(contents)
                        member(tar, entry.name, contents)
                    rows.append(row)
            observed = [{key: row[key] for key in ("path", "size", "mode", "type", "link_target")}
                        for row in tar["facts"]["deb.archive-entries"]["entries"]]
            # Python's tarfile normalizes trailing directory slashes; compare logical paths.
            expected = [{key: row[key] for key in ("path", "size", "mode", "type", "link_target")} for row in rows]
            for row in observed + expected:
                row["path"] = row["path"].rstrip("/")
            check("native TAR metadata: " + member_name, observed, expected)
            native["archives"].append({"member": member_name, "entries": rows})
        scripts = [row["path"] for row in native["archives"][0]["entries"]
                   if logical(row["path"]) in ("preinst", "postinst", "prerm", "postrm", "config")]
        check("maintainer script declarations", sorted(finding["params"]["name"] for finding in report["findings"]
              if finding["rule"] == "deb.install-script"), sorted(logical(name) for name in scripts))
        check("trigger declarations", sum(finding["rule"] == "deb.triggers" for finding in report["findings"]),
              sum(logical(row["path"]) == "triggers" for row in native["archives"][0]["entries"]))
    else:
        import rpm
        native["tool"] = run(["rpm", "--version"]).decode().strip()
        transaction = rpm.TransactionSet()
        transaction.setVSFlags(rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS)
        with sample.open("rb") as stream:
            header = transaction.hdrFromFdno(stream.fileno())
        if "rpm.package" not in root["facts"]:
            raise AssertionError(f"{sample.name}: RPM metadata missing: {report['limitations']!r}")
        package = root["facts"]["rpm.package"]
        for key, tag in [("name", 1000), ("version", 1001), ("release", 1002), ("architecture", 1022)]:
            native[key] = header[tag]
            check("header identity: " + key, package[key], header[tag])
        native["tags"] = []
        for row in package["tags"]:
            if row["value"] is None or row["type"] == 9:
                continue
            value = header[row["tag"]]
            if row["type"] == 6 and isinstance(value, list) and len(value) == 1:
                value = value[0]
            if row["type"] != 6 and not isinstance(value, list):
                value = [value]
            check("native header tag: " + str(row["tag"]), row["value"], value)
            native["tags"].append({"tag": row["tag"], "value": value})
        cpio = run(["rpm2cpio", sample])
        archive = next(file for file in report["artifacts"] if "cpio.directory" in file["facts"])
        rows = []
        for name, mode, size, target in zip(header["filenames"], header["filemodes"], header["filesizes"], header["filelinktos"]):
            row = {"path": name, "mode": mode, "size": size, "link_target": target or None}
            if stat.S_ISREG(mode):
                data = run(["bsdtar", "-xOf", "-", "--", "./" + logical(name)], cpio)
                check("native file size: " + name, len(data), size)
                member(archive, name, data)
                row["sha256"] = sha(data)
            if stat.S_ISLNK(mode):
                observed = next(entry for entry in archive["facts"]["cpio.directory"]["entries"]
                                if logical(entry["path"]) == logical(name))
                check("symlink declaration: " + name, observed["link_target"], target)
            rows.append(row)
        native["entries"] = rows
        check("native CPIO paths", sorted(logical(entry["path"]) for entry in archive["facts"]["cpio.directory"]["entries"]),
              sorted(logical(row["path"]) for row in rows))
    return {"sample": sample.name, "sha256": sha(sample.read_bytes()), "native": native, "checks": checks,
            "limitations": [{"code": row["code"], "artifact": row["artifact"]} for row in report["limitations"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    records = [verify(args.cli.resolve(), path.resolve()) for path in args.samples]
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    print(f"{sum(len(record['checks']) for record in records)} native checks passed across {len(records)} packages")


if __name__ == "__main__":
    main()
