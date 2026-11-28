#!/usr/bin/env python3
"""Compare supplied OCI/Docker archives with read-only skopeo and raw TAR readers.

No image is run, loaded into a daemon, imported, merged or unpacked onto the host.
All image transports passed to skopeo are local oci/oci-archive/docker-archive.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def run(arguments):
    completed = subprocess.run([str(argument) for argument in arguments], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C", LANG="C"))
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace"))
    return completed.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(data):
    return "sha256:" + sha(data)


def logical(path):
    return path.removeprefix("./").rstrip("/")


def whiteout(path):
    path = logical(path)
    parent, _, name = path.rpartition("/")
    if name == ".wh..wh..opq":
        return {"kind": "opaque", "target": parent}
    if name.startswith(".wh."):
        return {"kind": "remove", "target": parent + "/" + name[4:] if parent else name[4:]}
    return None


class Supplied:
    """Only regular members of the supplied archive/layout, never host symlink targets."""
    def __init__(self, sample):
        self.sample = sample
        self.members = {}
        self.archive = None
        if sample.is_file():
            self.archive = tarfile.open(sample, mode="r:*")
            for member in self.archive:
                name = logical(member.name)
                if name in self.members:
                    raise ValueError("duplicate archive name: " + name)
                self.members[name] = member

    def has(self, name):
        if self.archive is not None:
            return name in self.members and self.members[name].isfile()
        path = self.sample / name
        return path.is_file() and not path.is_symlink()

    def read(self, name):
        if name.startswith("/") or "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
            raise ValueError("noncanonical supplied member path")
        if self.archive is not None:
            member = self.members[name]
            if not member.isfile():
                raise ValueError("expected a regular supplied archive member")
            return self.archive.extractfile(member).read()
        path = self.sample / name
        if path.is_symlink() or not path.resolve().is_relative_to(self.sample.resolve()):
            raise ValueError("layout reference would leave the supplied tree")
        return path.read_bytes()


def layer(bytes_):
    decoded = gzip.decompress(bytes_) if bytes_.startswith(b"\x1f\x8b\x08") else bytes_
    rows = []
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for entry in archive:
            header = decoded[entry.offset_data - 512:entry.offset_data]
            assert len(header) == 512
            declared_checksum = int(header[148:156].rstrip(b"\0 ") or b"0", 8)
            assert declared_checksum == sum(header[:148]) + 8 * 32 + sum(header[156:])
            header_type = header[156] or ord("0")
            assert header_type == entry.type[0]
            header_name = header[:100].split(b"\0", 1)[0]
            prefix = header[345:500].split(b"\0", 1)[0]
            if prefix:
                header_name = prefix + b"/" + header_name
            declared_path = header_name.decode("utf-8", errors="replace")
            assert logical(declared_path) == logical(entry.name) or entry.pax_headers.get("path") == entry.name
            row = {"path": entry.name, "type": entry.type[0], "link_target": entry.linkname or None,
                   "whiteout": whiteout(entry.name), "header_offset": entry.offset_data - 512,
                   "offset": entry.offset_data, "size": entry.size, "mode": entry.mode}
            if entry.isfile():
                contents = archive.extractfile(entry).read()
                row["sha256"] = sha(contents)
            rows.append(row)
    return {"size": len(bytes_), "digest": digest(bytes_), "diff_id": digest(decoded), "entries": rows}


def native(sample):
    supplied = Supplied(sample)
    is_oci = supplied.has("oci-layout") and supplied.has("index.json")
    transport = ("oci:" if sample.is_dir() else "oci-archive:") if is_oci else "docker-archive:"
    native_raw = run(["skopeo", "inspect", "--raw", transport + str(sample)])
    native_config = json.loads(run(["skopeo", "inspect", "--config", "--raw", transport + str(sample)]))
    result = {"format": "oci" if is_oci else "docker-save", "tool": run(["skopeo", "--version"]).decode().strip(),
              "skopeo_manifest": json.loads(native_raw),
              "skopeo_config": native_config, "manifests": []}

    def blob(descriptor):
        algorithm, checksum = descriptor["digest"].split(":", 1)
        assert algorithm == "sha256" and len(checksum) == 64
        name = "blobs/sha256/" + checksum
        data = supplied.read(name)
        assert digest(data) == descriptor["digest"] and len(data) == descriptor["size"]
        return name, data

    if is_oci:
        index = json.loads(supplied.read("index.json"))
        pending = list(index["manifests"])
        seen = set()
        while pending:
            descriptor = pending.pop(0)
            name, data = blob(descriptor)
            assert descriptor["digest"] not in seen
            seen.add(descriptor["digest"])
            document = json.loads(data)
            if descriptor["mediaType"] in ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"):
                pending.extend(document["manifests"])
                continue
            config_source, config_bytes = blob(document["config"])
            config = json.loads(config_bytes)
            rows = []
            for number, declared in enumerate(document["layers"]):
                source, content = blob(declared)
                measured = layer(content)
                measured.update({"order": number, "source": source, "declared_digest": declared["digest"],
                                 "state": "matched", "media_type": declared["mediaType"]})
                assert measured["diff_id"] == config["rootfs"]["diff_ids"][number]
                rows.append(measured)
            result["manifests"].append({"source": name, "digest": descriptor["digest"], "annotations": document.get("annotations"),
                                        "config_source": config_source, "config_digest": digest(config_bytes),
                                        "config": config, "layers": rows})
    else:
        for record in json.loads(supplied.read("manifest.json")):
            config_source = record["Config"]
            config_bytes = supplied.read(config_source)
            assert config_source.rsplit("/", 1)[-1] == sha(config_bytes) + ".json"
            config = json.loads(config_bytes)
            rows = []
            for number, source in enumerate(record["Layers"]):
                content = supplied.read(source)
                measured = layer(content)
                measured.update({"order": number, "source": source, "declared_digest": None, "state": "captured"})
                assert measured["diff_id"] == config["rootfs"]["diff_ids"][number]
                rows.append(measured)
            result["manifests"].append({"source": "manifest.json", "digest": None, "repo_tags": record.get("RepoTags"),
                                        "annotations": None, "config_source": config_source, "config_digest": digest(config_bytes),
                                        "config": config, "layers": rows})
    assert len(result["manifests"]) == 1
    assert result["manifests"][0]["config"] == native_config
    if is_oci:
        assert json.loads(supplied.read(result["manifests"][0]["source"])) == json.loads(native_raw)
    return result


def analyze(cli, sample):
    with tempfile.TemporaryDirectory(prefix="aa-image-reference-") as directory:
        help_text = run([cli, "analyze", "--help"])
        offline = ["--no-ai"] if b"--no-ai" in help_text else []
        completed = subprocess.run([str(cli), str(sample), "-o", directory, "--format", "json", *offline], capture_output=True)
        path = Path(directory) / "report.json"
        if completed.returncode not in (0, 2) or not path.is_file():
            raise RuntimeError(completed.stderr.decode(errors="replace"))
        return path.read_bytes()


def redacted_environment(values):
    if values is None:
        return None
    result = []
    for entry in values:
        name, separator, value = entry.partition("=")
        if name == "PASSWORD":
            value = "[redacted]"
        result.append(name + separator + value)
    return result


def verify(cli, sample, expected):
    first = analyze(cli, sample)
    report = json.loads(first)
    packages = [file for file in report["artifacts"] if "image.package" in file["facts"]]
    checks = []

    def check(label, actual, reference):
        matches = actual == reference
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {reference!r}")

    check("repeated report bytes", analyze(cli, sample), first)
    check("one image-package scope", len(packages), 1)
    package = packages[0]
    facts = package["facts"]["image.package"]
    check("native archive family profile", facts["format"], expected["format"])
    check("complete supported source graph", facts["complete"], True)
    check("layers never presented as merged filesystem", facts["merged_filesystem"], False)
    check("native manifest count", len(facts["manifests"]), len(expected["manifests"]))
    artifacts = {file["path"]: file for file in report["artifacts"]}

    def source(label, path, relative):
        check(label + " exists as captured artifact", path in artifacts, True)
        check(label + " original member path", path.endswith("/" + relative) or path == relative, True)

    for actual, reference in zip(facts["manifests"], expected["manifests"]):
        source("manifest source", actual["source"], reference["source"])
        source("config source", actual["config_source"], reference["config_source"])
        if expected["format"] == "oci":
            check("original manifest descriptor digest", actual["digest"], reference["digest"])
            check("literal manifest annotations", actual["annotations"], reference["annotations"])
        check("config source digest", actual["config_digest"], reference["config_digest"])
        config = reference["config"]
        declaration = config.get("config") or {}
        for key in ("architecture", "os"):
            check("native config identity: " + key, actual[key], config.get(key))
        for key, original in [("entrypoint", "Entrypoint"), ("cmd", "Cmd")]:
            check("literal config argv: " + key, actual[key], declaration.get(original))
        check("recognizable secret in environment redacted", actual["env"], redacted_environment(declaration.get("Env")))
        check("literal exposed ports", actual["ports"], sorted((declaration.get("ExposedPorts") or {}).keys()))
        check("literal volumes", actual["volumes"], sorted((declaration.get("Volumes") or {}).keys()))
        check("rootfs declaration type", actual["rootfs_type"], config["rootfs"].get("type"))
        check("native ordered layer count", len(actual["layers"]), len(reference["layers"]))
        for row, layer_reference in zip(actual["layers"], reference["layers"]):
            number = layer_reference["order"]
            source(f"layer {number} source", row["source"], layer_reference["source"])
            for key in ("order", "digest", "declared_digest", "size", "state", "diff_id"):
                check(f"layer {number}: {key}", row[key], layer_reference[key])
            check(f"layer {number}: diff_id agrees with captured uncompressed TAR", row["diff_id_state"], "matched")
            check(f"layer {number}: complete metadata index", row["complete"], True)
            check(f"layer {number}: decoded TAR source retained", row["tar_source"] in artifacts, True)
            check(f"layer {number}: decoded TAR SHA-256", artifacts[row["tar_source"]]["digests"]["sha256"], layer_reference["diff_id"].split(":", 1)[1])
            check(f"layer {number}: entry count", len(row["entries"]), len(layer_reference["entries"]))
            for entry, original in zip(row["entries"], layer_reference["entries"]):
                for key in ("path", "type", "link_target", "whiteout", "header_offset", "offset", "size", "mode"):
                    actual_value, expected_value = entry[key], original[key]
                    if key == "path":
                        actual_value, expected_value = logical(actual_value), logical(expected_value)
                    check(f"layer {number}: {original['path']}: {key}", actual_value, expected_value)
                if "sha256" in original:
                    path = row["tar_source"] + "/" + logical(original["path"])
                    check(f"layer {number}: {original['path']}: payload captured", path in artifacts, True)
                    check(f"layer {number}: {original['path']}: payload SHA-256", artifacts[path]["digests"]["sha256"], original["sha256"])
    check("synthetic credential absent from image facts", "synthetic-redaction-probe" in json.dumps(facts), False)
    return {"sample": sample.name, "sha256": sha(sample.read_bytes()) if sample.is_file() else None,
            "native": expected, "checks": checks,
            "limitations": [{"code": row["code"], "artifact": row["artifact"]} for row in report["limitations"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    args.record.parent.mkdir(parents=True, exist_ok=True)
    references = [{"sample": sample.name, "sha256": sha(sample.read_bytes()) if sample.is_file() else None,
                   "native": native(sample.resolve())} for sample in args.samples]
    (args.record.parent / "native-observations.json").write_text(json.dumps(references, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    records = [verify(args.cli.resolve(), sample.resolve(), reference["native"])
               for sample, reference in zip(args.samples, references)]
    args.record.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{sum(len(record['checks']) for record in records)} static native image checks passed")


if __name__ == "__main__":
    main()
