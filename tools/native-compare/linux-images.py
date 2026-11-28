#!/usr/bin/env python3
"""Read-only SquashFS/AppImage/snap references. No image is mounted or executed."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def run(arguments):
    return subprocess.run([str(argument) for argument in arguments], check=True, capture_output=True, timeout=120).stdout


def sha(body):
    return hashlib.sha256(body).hexdigest()


def appimage_offset(body):
    """Independent snapshot of the upstream Type 2 runtime's ELF-size calculation."""
    if body[:4] != b"\x7fELF" or body[8:11] != b"AI\x02":
        return 0
    endian = "<" if body[5] == 1 else ">"
    if body[4] == 2:
        start = struct.unpack_from(endian + "Q", body, 40)[0]
        size, count = struct.unpack_from(endian + "HH", body, 58)
        section = start + size * (count - 1)
        offset, length = struct.unpack_from(endian + "QQ", body, section + 24)
    elif body[4] == 1:
        start = struct.unpack_from(endian + "I", body, 32)[0]
        size, count = struct.unpack_from(endian + "HH", body, 46)
        section = start + size * (count - 1)
        offset, length = struct.unpack_from(endian + "II", body, section + 16)
    else:
        raise ValueError("unsupported ELF class")
    return max(start + size * count, offset + length)


def analyze(cli, sample, no_ai):
    with tempfile.TemporaryDirectory(prefix="aa-linux-image-reference-") as folder:
        arguments = [str(cli), str(sample), "-o", folder, "--format", "json"]
        if no_ai:
            arguments.append("--no-ai")
        process = subprocess.run(arguments, capture_output=True, timeout=180)
        if process.returncode not in (0, 2):
            raise RuntimeError(process.stderr.decode(errors="replace"))
        return json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))


def verify(cli, sample, no_ai):
    body = sample.read_bytes()
    offset = appimage_offset(body)
    report = analyze(cli, sample, no_ai)
    checks = []

    def check(name, actual, expected):
        matches = actual == expected
        checks.append({"check": name, "matches": matches})
        if not matches:
            raise AssertionError(f"{sample.name}: {name}: {actual!r} != {expected!r}")

    root = next(artifact for artifact in report["artifacts"] if artifact["parent"] is None)
    check("source SHA-256", root["digests"]["sha256"], sha(body))
    if offset:
        check("AppImage ELF-proven filesystem offset", root["facts"]["appimage.container"]["filesystem_offset"], offset)
        image = next(artifact for artifact in report["artifacts"] if artifact["parent"] == root["path"] and "squashfs.directory" in artifact["facts"])
    else:
        image = root
    header = body[offset:offset + 96]
    check("native image magic", header[:4].hex(), "68737173")
    bytes_used = struct.unpack_from("<Q", header, 40)[0]
    superblock = image["facts"]["squashfs.directory"]["superblock"]
    check("SquashFS bytes_used", superblock["bytes_used"], bytes_used)
    check("SquashFS block size", superblock["block_size"], struct.unpack_from("<I", header, 12)[0])
    check("SquashFS inode count", superblock["inodes"], struct.unpack_from("<I", header, 4)[0])
    # -lln only lists; -cat writes member bytes to stdout. Neither creates links,
    # device nodes, executable files, mountpoints or an installed package.
    listing = run(["unsquashfs", "-o", offset, "-lln", sample]).decode("utf-8")
    native_entries = []
    for line in listing.splitlines():
        match = re.match(r"^([dl\-bcps][rwxstST-]{9})\s+(\d+)/(\d+)\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(squashfs-root(?:/.*)?)$", line)
        if not match:
            continue
        mode, uid, gid, size, path = match.groups()
        if path == "squashfs-root":
            continue
        path = path.removeprefix("squashfs-root/")
        target = None
        if mode.startswith("l"):
            path, separator, target = path.partition(" -> ")
            if not separator:
                raise ValueError("native symlink listing has no literal target")
        entry = {"path": path, "mode": mode, "uid": int(uid), "gid": int(gid), "size": int(size), "link_target": target}
        native_entries.append(entry)
    if not native_entries:
        raise ValueError("no native listing entries were parsed; qualification cannot pass silently")
    captured = {entry["path"].lstrip("/"): entry for entry in image["facts"]["squashfs.directory"]["entries"] if entry["path"].lstrip("/")}
    check("native directory paths", sorted(captured), sorted(entry["path"] for entry in native_entries))
    for entry in native_entries:
        observed = captured[entry["path"]]
        if entry["mode"].startswith("l"):
            check("link target: " + entry["path"], observed["link_target"], entry["link_target"])
        elif entry["mode"].startswith("-"):
            data = run(["unsquashfs", "-o", offset, "-cat", sample, entry["path"]])
            artifact = next((artifact for artifact in report["artifacts"] if artifact["path"] == image["path"] + "/" + entry["path"] and artifact["parent"] == image["path"]), None)
            check("regular-file size: " + entry["path"], observed["size"], len(data))
            check("regular-file SHA-256: " + entry["path"], None if artifact is None else artifact["digests"]["sha256"], sha(data))
            entry["sha256"] = sha(data)
    snap = image["facts"].get("snap.package")
    if snap is not None:
        import yaml
        metadata = run(["unsquashfs", "-o", offset, "-cat", sample, "meta/snap.yaml"])
        reference = yaml.safe_load(metadata)
        check("snap name", snap["name"], reference["name"])
        check("snap version", snap["version"], str(reference["version"]))
        check("snap metadata SHA-256", snap["source_sha256"], sha(metadata))
        check("snap application names", sorted(app["name"] for app in snap["applications"]), sorted(reference.get("apps", {})))
    return {"file": sample.name, "sha256": sha(body), "filesystem_offset": offset, "bytes_used": bytes_used,
            "scope": "Native header, complete directory paths, link targets and every captured regular-file digest; selected snap declarations", "checks": checks, "passed": len(checks), "native_entries": native_entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    version = subprocess.run(["unsquashfs", "-version"], capture_output=True, timeout=10)
    cli = args.cli.resolve()
    no_ai = "--no-ai" in run([cli, "analyze", "--help"]).decode("utf-8")
    records = [verify(cli, sample.resolve(), no_ai) for sample in args.samples]
    result = {"tool": "unsquashfs", "tool_version": (version.stdout + version.stderr).decode(errors="replace").splitlines(), "samples": records, "passed": sum(record["passed"] for record in records)}
    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"samples": len(records), "passed": result["passed"]}))


if __name__ == "__main__":
    main()
