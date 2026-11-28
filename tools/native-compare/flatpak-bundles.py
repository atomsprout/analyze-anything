#!/usr/bin/env python3
"""Read Flatpak bundles through native Flatpak/GLib; never install, import or apply them."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import tempfile

import gi
gi.require_version("Flatpak", "1.0")
from gi.repository import Flatpak, Gio, GLib

SUPER = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))"
PAYLOAD = "(a(uuu)aa(ayay)ayay)"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def raw(value):
    return bytes(value.get_data_as_bytes().get_data())


def read_variant(signature, data):
    value = GLib.Variant.new_from_bytes(GLib.VariantType.new(signature), GLib.Bytes.new(data), False)
    if not value.is_normal_form():
        raise ValueError("native GLib rejected non-normal GVariant: " + signature)
    return value


def children(value):
    return [value.get_child_value(index) for index in range(value.n_children())]


def number(value, byteorder):
    return int.from_bytes(raw(value), byteorder)


def varuint(data, at):
    value = 0
    shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, at
        shift += 7
        if shift >= 70:
            raise ValueError("oversized delta integer")


def metadata_fields(text):
    group = ""
    fields = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1]
        else:
            key, value = line.split("=", 1)
            fields.append({"group": group, "name": key.strip(), "value": value.strip(), "line": number,
                           "interpreted": group in ("Application", "Runtime", "Context", "Session Bus Policy", "System Bus Policy")})
    return fields


def native(sample):
    source = sample.read_bytes()
    root = read_variant(SUPER, source)
    columns = children(root)
    metadata = {}
    for row in children(columns[0]):
        key, value = children(row)
        name = key.get_string()
        if name in metadata:
            raise ValueError("duplicate native metadata key")
        metadata[name] = value.get_variant()
    byteorder = "little" if metadata["ostree.endianness"].get_byte() == ord("l") else "big"
    bundle = Flatpak.BundleRef.new(Gio.File.new_for_path(str(sample)))
    declared = bytes(bundle.get_metadata().get_data())
    result = {"name": bundle.get_name(), "architecture": bundle.get_arch(), "branch": bundle.get_branch(),
              "reference": bundle.format_ref(), "commit": bundle.get_commit(), "metadata": declared.decode("utf-8"),
              "parts": [], "objects": {}, "paths": []}
    assert not raw(columns[2]) and not raw(columns[5]) and not children(columns[7])
    assert sha(raw(columns[4])) == raw(columns[3]).hex()
    inline = [value for key, value in metadata.items() if key.startswith("deltas/")]
    for index, descriptor in enumerate(children(columns[6])):
        version, checksum, size, usize, object_list = children(descriptor)
        assert number(version, byteorder) == 0
        part = next(value for key, value in metadata.items() if key.startswith("deltas/") and key.endswith("/" + str(index)))
        compression, compressed = children(part)
        stored = raw(part)
        assert len(stored) == number(size, byteorder) and sha(stored) == raw(checksum).hex()
        payload = lzma.decompress(raw(compressed)) if compression.get_byte() == ord("x") else raw(compressed)
        modes, xattrs, blob, operations = children(read_variant(PAYLOAD, payload))
        data, ops = raw(blob), raw(operations)
        descriptors = raw(object_list)
        at = 0
        result["parts"].append({"index": index, "sha256": sha(stored), "decoded_sha256": sha(payload),
                                "decoded_size": len(payload), "objects": len(descriptors) // 33})
        for offset in range(0, len(descriptors), 33):
            kind = descriptors[offset]
            expected = descriptors[offset + 1:offset + 33].hex()
            assert ops[at] == ord("S")
            at += 1
            mode_value = None
            attrs = None
            if kind == 1:
                mode_index, at = varuint(ops, at)
                xattr_index, at = varuint(ops, at)
                mode_value = modes.get_child_value(mode_index)
                attrs = xattrs.get_child_value(xattr_index)
            length, at = varuint(ops, at)
            position, at = varuint(ops, at)
            content = data[position:position + length]
            assert len(content) == length
            record = {"kind": kind, "checksum": expected, "part": index, "size": length, "sha256": sha(content), "data": content}
            if kind != 1:
                assert sha(content) == expected
            else:
                uid, gid, mode = children(mode_value)
                record["mode"] = number(mode, "big")
                symlink = record["mode"] & 0o170000 == 0o120000
                target = content.decode("utf-8") if symlink else ""
                attr_rows = sorted(children(attrs), key=lambda row: raw(row.get_child_value(0)))
                canonical_attrs = GLib.Variant.new_array(GLib.VariantType.new("(ayay)"), attr_rows)
                header = GLib.Variant.new_tuple(uid, gid, mode, GLib.Variant("u", 0), GLib.Variant("s", target), canonical_attrs)
                header_data = raw(header)
                checksum_input = len(header_data).to_bytes(4, "big") + bytes(4) + header_data
                if not symlink:
                    checksum_input += content
                assert sha(checksum_input) == expected
                record["link_target"] = target if symlink else None
            key = (kind, expected)
            assert key not in result["objects"]
            result["objects"][key] = record
        assert at == len(ops)
    commit = children(columns[4])
    pending = [("", raw(commit[6]).hex(), raw(commit[7]).hex())]
    while pending:
        prefix, tree_hash, meta_hash = pending.pop()
        assert (3, meta_hash) in result["objects"]
        tree = read_variant("(a(say)a(sayay))", result["objects"][(2, tree_hash)]["data"])
        files, directories = children(tree)
        for row in children(files):
            name, checksum = children(row)
            name = name.get_string()
            path = prefix + "/" + name if prefix else name
            record = dict(result["objects"][(1, raw(checksum).hex())])
            record["path"] = path
            result["paths"].append(record)
        for row in children(directories):
            name, tree, meta = children(row)
            name = name.get_string()
            path = prefix + "/" + name if prefix else name
            pending.append((path, raw(tree).hex(), raw(meta).hex()))
    result["paths"].sort(key=lambda row: row["path"])
    result["object_count"] = len(result.pop("objects"))
    for row in result["paths"]:
        row.pop("data")
    return result


def analyze(cli, sample):
    with tempfile.TemporaryDirectory(prefix="aa-flatpak-reference-") as directory:
        completed = subprocess.run([str(cli), str(sample), "-o", directory, "--format", "json", "--no-ai"], capture_output=True)
        if completed.returncode not in (0, 2):
            raise RuntimeError(completed.stderr.decode(errors="replace"))
        return (Path(directory) / "report.json").read_bytes()


def verify(cli, sample):
    reference = native(sample)
    first = analyze(cli, sample)
    report = json.loads(first)
    root = next(file for file in report["artifacts"] if file["parent"] is None)
    facts = root["facts"]["flatpak.bundle"]
    checks = []

    def check(label, actual, expected):
        matches = actual == expected
        checks.append({"check": label, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {label}: {actual!r} != {expected!r}")

    check("repeated report bytes", analyze(cli, sample), first)
    check("complete captured profile", facts["complete"], True)
    for key in ("name", "architecture", "branch", "reference", "commit"):
        check("native Flatpak identity: " + key, facts[key], reference[key])
    check("native application declarations", root["facts"]["flatpak.application"]["fields"], metadata_fields(reference["metadata"]))
    check("native object/path names", [row["path"] for row in facts["entries"]], [row["path"] for row in reference["paths"]])
    for actual, expected in zip(facts["parts"], reference["parts"]):
        for key in ("index", "sha256", "decoded_sha256", "decoded_size", "objects"):
            check("native part " + str(expected["index"]) + ": " + key, actual[key], expected[key])
        decoded = next(file for file in report["artifacts"] if file["path"] == actual["decoded_artifact"])
        check("retained decoded part digest", decoded["digests"]["sha256"], expected["decoded_sha256"])
    for actual, expected in zip(facts["entries"], reference["paths"]):
        for key in ("size", "mode", "link_target"):
            check(expected["path"] + ": " + key, actual[key], expected.get(key))
        check(expected["path"] + ": verified object checksum", actual["object_checksum"], expected["checksum"])
        check(expected["path"] + ": label checked", actual["object_label_verified"], True)
        if expected.get("link_target") is None:
            artifact = next(file for file in report["artifacts"] if file["path"] == actual["captured_path"])
            check(expected["path"] + ": captured payload SHA-256", artifact["digests"]["sha256"], expected["sha256"])
    return {"sample": sample.name, "sha256": sha(sample.read_bytes()), "native": reference, "checks": checks,
            "limitations": [{"code": row["code"], "artifact": row["artifact"]} for row in report["limitations"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--record", required=True, type=Path)
    args = parser.parse_args()
    records = [verify(args.cli.resolve(), sample.resolve()) for sample in args.samples]
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{sum(len(record['checks']) for record in records)} native Flatpak/GLib checks passed")


if __name__ == "__main__":
    main()
