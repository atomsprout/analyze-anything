#!/usr/bin/env python3
"""Verify this repository's eleven GitHub release assets without publishing anything.

Full verification runs only the Windows x64 CLI from the verified CLI ZIP. It never
runs a desktop program, installer or supplied analysis input. Python 3.11+ and an
authenticated gh are required; full CLI verification also requires Windows x64.

    python tools/release/verify-published.py v0.2.3 --version 0.2.3 --count 30
    python tools/release/verify-published.py v0.2.3 --version 0.2.3 --count 30 --check-workflow

Historical releases without `formats --json` can exercise download, hashes and
archive checks without executing a program. This explicitly incomplete mode has
full_verified=false and cannot qualify a release's CLI or advertised format count:

    python tools/release/verify-published.py v0.2.2 --version 0.2.2 --count 28 --archives-only

Output lives in a fresh directory under out/verify-published/. --assets-dir can
reuse an earlier download under out/; all bytes are checked again against current
GitHub metadata and checksum files. --out chooses a new directory under out/.
The JSON record is written on success or failure. No GitHub state is changed.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote
import zipfile


REPOSITORY = Path(__file__).resolve().parents[2]
# .github/workflows/release.yml's four CLI targets, plus windows.ps1's two
# desktop packages and their shared manifest. Signed macOS packages are separate.
TARGETS = {
    "aarch64-apple-darwin": "tar.gz",
    "aarch64-unknown-linux-gnu": "tar.gz",
    "x86_64-unknown-linux-gnu": "tar.gz",
    "x86_64-pc-windows-msvc": "zip",
}
MAX_ASSET = 1024 * 1024 * 1024
MAX_ALL_ASSETS = 3 * MAX_ASSET
MAX_EXPANDED = 512 * 1024 * 1024
MAX_MEMBERS = 128
BLOCK = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(arguments, timeout=120, cwd=None):
    result = subprocess.run(list(map(str, arguments)), cwd=cwd, capture_output=True, timeout=timeout)
    require(result.returncode == 0, f"{Path(arguments[0]).name} exited {result.returncode}: "
            + result.stderr.decode("utf-8", errors="replace")[:4000])
    return result.stdout


def gh_json(endpoint, missing_ok=False, pages=False):
    arguments = ["gh", "api", endpoint]
    if pages:
        arguments += ["--paginate", "--slurp"]
    result = subprocess.run(arguments, capture_output=True, timeout=120)
    if missing_ok and result.returncode != 0 and b"HTTP 404" in result.stderr:
        return None
    require(result.returncode == 0, "gh api failed: " + result.stderr.decode("utf-8", errors="replace")[:4000])
    require(len(result.stdout) <= 16 * 1024 * 1024, "GitHub metadata exceeds 16 MiB")
    return json.loads(result.stdout)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def expected_assets(tag, version):
    archives = {f"analyze-anything-{tag}-{target}.{suffix}" for target, suffix in TARGETS.items()}
    desktop = {
        f"analyze-anything-desktop-{version}-windows-x64-portable.zip",
        f"analyze-anything-desktop-{version}-windows-x64-offline-setup.exe",
    }
    names = archives | {name + ".sha256" for name in archives} | desktop | {"SHA256SUMS"}
    require(len(names) == 11, "release asset contract must contain exactly eleven names")
    return names, archives, desktop


def release_metadata(repo, tag):
    # Listing includes authenticated draft releases, even before their tag exists.
    pages = gh_json(f"repos/{repo}/releases?per_page=100", pages=True)
    matches = [release for page in pages for release in page if release.get("tag_name") == tag]
    require(len(matches) == 1, f"expected exactly one accessible release for {tag}, found {len(matches)}")
    return matches[0]


def source_commit(repo, release):
    ref = gh_json(f"repos/{repo}/git/ref/tags/{quote(release['tag_name'], safe='')}", missing_ok=True)
    if ref is None:
        target = release.get("target_commitish", "")
        require(release.get("draft") and SHA1.fullmatch(target), "an untagged draft must name an immutable commit SHA")
        commit = gh_json(f"repos/{repo}/git/commits/{target}")
        require(commit["sha"] == target, "draft commit resolution disagrees")
        return {"commit": target, "resolved_from": "untagged-draft-target", "tag_object": None}
    obj = ref["object"]
    tag_object = dict(obj)
    seen = set()
    while obj.get("type") == "tag":
        require(obj.get("sha") not in seen and len(seen) < 8, "annotated tag chain is cyclic or too deep")
        seen.add(obj["sha"])
        obj = gh_json(f"repos/{repo}/git/tags/{obj['sha']}")["object"]
    require(obj.get("type") == "commit" and SHA1.fullmatch(obj.get("sha", "")), "release tag does not resolve to a commit")
    target = release.get("target_commitish", "")
    if SHA1.fullmatch(target):
        require(target == obj["sha"], "release target commit and tag commit disagree")
    return {"commit": obj["sha"], "resolved_from": "tag-ref", "tag_object": tag_object}


def metadata_assets(release, expected):
    assets = release.get("assets", [])
    names = [asset.get("name") for asset in assets]
    require(len(names) == 11 and set(names) == expected and len(set(names)) == len(names),
            f"release assets differ: missing={sorted(expected - set(names))}, extra={sorted(set(names) - expected)}")
    total = 0
    for asset in assets:
        size = asset.get("size")
        require(type(size) is int and 0 < size <= MAX_ASSET, f"invalid or over-budget size for {asset['name']}")
        require(asset.get("state") == "uploaded", f"incomplete GitHub upload: {asset['name']}")
        total += size
    require(total <= MAX_ALL_ASSETS, "release assets exceed the 3 GiB download profile")
    return {asset["name"]: asset for asset in assets}


def fingerprint(release):
    return {
        "id": release["id"], "tag": release["tag_name"], "draft": release["draft"],
        "prerelease": release["prerelease"], "target_commitish": release["target_commitish"],
        "assets": sorted((a["id"], a["name"], a["size"], a.get("digest"), a.get("updated_at"), a.get("state"))
                         for a in release["assets"]),
    }


def path_under_out(path, must_exist=False):
    path = path.resolve(strict=must_exist)
    require(path.is_relative_to((REPOSITORY / "out").resolve()), "verification paths must remain under this checkout's out/")
    return path


def download(repo, tag, assets, directory):
    directory.mkdir(parents=True, exist_ok=True)
    require(not directory.is_symlink(), "asset directory must not be a symlink")
    present = list(directory.iterdir())
    require(all(path.is_file() and not path.is_symlink() and path.name in assets for path in present),
            "asset directory contains unexpected entries or links")
    missing = sorted(set(assets) - {path.name for path in present})
    if missing:
        arguments = ["gh", "release", "download", tag, "--repo", repo, "--dir", directory]
        for name in missing:
            arguments += ["--pattern", name]
        run(arguments, timeout=600)
    require({path.name for path in directory.iterdir()} == set(assets), "downloaded asset names differ from the metadata snapshot")
    return {"downloaded": missing, "reused": sorted(set(assets) - set(missing))}


def check_asset_bytes(directory, assets):
    checked = []
    for name in sorted(assets):
        asset, path = assets[name], directory / name
        require(path.is_file() and not path.is_symlink(), f"not an ordinary downloaded asset: {name}")
        require(path.stat().st_size == asset["size"], f"GitHub size mismatch: {name}")
        actual = sha_file(path)
        supplied = asset.get("digest")
        if supplied:
            require(supplied.startswith("sha256:") and SHA256.fullmatch(supplied[7:]), f"unsupported GitHub digest: {name}")
            require(actual == supplied[7:], f"GitHub API digest mismatch: {name}")
        checked.append({"name": name, "asset_id": asset["id"], "size": asset["size"], "sha256": actual,
                        "github_digest": supplied, "github_digest_verified": bool(supplied)})
    return checked


def checksum_entries(path, expected):
    require(path.stat().st_size <= 32 * 1024, f"checksum manifest too large: {path.name}")
    values = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) ([ *])([^\r\n]+)", line)
        require(match is not None, f"malformed checksum line: {path.name}")
        name = match[3]
        require(name in expected and name not in values, f"unexpected or duplicate checksum target: {name}")
        values[name] = match[1].lower()
    require(set(values) == expected, f"missing checksum targets: {path.name}")
    return values


def check_checksums(directory, archives, desktop, assets):
    sums = {}
    for name in sorted(archives):
        sums[name + ".sha256"] = checksum_entries(directory / (name + ".sha256"), {name})
    sums["SHA256SUMS"] = checksum_entries(directory / "SHA256SUMS", desktop)
    hashes = {asset["name"]: asset["sha256"] for asset in assets}
    for manifest, entries in sums.items():
        for name, expected in entries.items():
            require(hashes[name] == expected, f"checksum mismatch in {manifest}: {name}")
    return sums


def sane_name(name, directory=False):
    require(isinstance(name, str) and 0 < len(name.encode("utf-8")) <= 8192, "empty or overlong archive path")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in name), "control character in archive path")
    require("\\" not in name and ":" not in name and not name.startswith("/"), "absolute or Windows-special archive path")
    if directory and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    require(all(part and part not in (".", "..") and not part.endswith((".", " ")) for part in parts), "ambiguous archive path")
    for part in parts:
        base = part.split(".")[0].upper()
        require(base not in {"CON", "PRN", "AUX", "NUL"} and not re.fullmatch(r"(?:COM|LPT)[1-9]", base), "Windows device archive path")
    return name


def archive_layout(name):
    if name.endswith(".tar.gz"):
        root = name[:-7]
    else:
        require(name.endswith(".zip"), "unsupported release archive")
        root = name[:-4]
    desktop = name.startswith("analyze-anything-desktop-")
    program = "analyze-anything-desktop.exe" if desktop else "analyze-anything.exe" if name.endswith(".zip") else "analyze-anything"
    readme = "README.txt" if desktop else "README.md"
    return root, {f"{root}/{entry}" for entry in (program, readme, "LICENSE", "NOTICE")}


def member_record(name, size, digest, mode=None):
    return {"path": name, "size": size, "sha256": digest, "mode": mode}


def check_layout(records, root, expected):
    names = [record["path"] for record in records]
    require(len(names) == len(set(name.casefold() for name in names)), "duplicate or case-colliding archive entries")
    files = {record["path"] for record in records if record["sha256"] is not None}
    require(files == expected, f"archive payload differs: missing={sorted(expected - files)}, extra={sorted(files - expected)}")
    require(all(record["sha256"] is not None or record["path"] == root for record in records), "unexpected archive directory")


def check_zip(path):
    root, expected = archive_layout(path.name)
    records, expanded = [], 0
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) <= MAX_MEMBERS, "ZIP member count exceeds its bound")
        for member in members:
            name = sane_name(member.filename, member.is_dir())
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            require(kind in (0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG), "link or special ZIP entry")
            require(not member.flag_bits & 1, "encrypted release ZIP")
            require(member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsupported release ZIP compression")
            expanded += member.file_size
            require(0 <= member.file_size <= MAX_EXPANDED and expanded <= MAX_EXPANDED, "ZIP expanded-byte budget exceeded")
            digest, size = hashlib.sha256(), 0
            with archive.open(member) as stream:
                for block in iter(lambda: stream.read(BLOCK), b""):
                    size += len(block)
                    require(size <= member.file_size, "ZIP body exceeds its declared length")
                    digest.update(block)
            require(size == member.file_size, "ZIP body is truncated")
            require(not member.is_dir() or size == 0, "ZIP directory has data")
            records.append(member_record(name, size, None if member.is_dir() else digest.hexdigest(), mode))
    check_layout(records, root, expected)
    return {"kind": "zip", "crc_checked": True, "expanded_bytes": expanded, "members": records}


def pax_path(data):
    at, fields = 0, {}
    while at < len(data):
        space = data.find(b" ", at, at + 13)
        require(space > at and data[at:space].isdigit(), "invalid PAX record length")
        length = int(data[at:space])
        require(space - at + 2 < length <= 16 * 1024 and at + length <= len(data), "PAX record exceeds its bound")
        record = data[space + 1:at + length]
        require(record.endswith(b"\n") and b"=" in record, "invalid PAX record")
        name, value = record[:-1].decode("utf-8").split("=", 1)
        require(name not in fields and name not in ("size", "linkpath") and not name.startswith("GNU.sparse"), "unsupported PAX override")
        fields[name] = value
        at += length
    return fields.get("path")


def check_tar_gzip(path):
    root, expected = archive_layout(path.name)
    records, expanded, decoded, pax_bytes, pending = [], 0, 0, 0, None
    headers = 0
    with gzip.open(path, "rb") as stream:
        def read(size):
            nonlocal decoded
            data = stream.read(size)
            decoded += len(data)
            require(decoded <= MAX_EXPANDED, "gzip decoded-byte budget exceeded")
            require(len(data) == size, "TAR stream is truncated")
            return data

        while True:
            raw = read(512)
            if not any(raw):
                require(pending is None and not any(read(512)), "incomplete TAR terminator")
                # Reading through gzip EOF verifies its CRC and ISIZE, including
                # bytes after TAR's terminator; no hidden second TAR is accepted.
                for block in iter(lambda: stream.read(BLOCK), b""):
                    decoded += len(block)
                    require(decoded <= MAX_EXPANDED and not any(block), "unread data or over-budget bytes after TAR terminator")
                break
            headers += 1
            require(headers <= 2 * MAX_MEMBERS, "TAR header count exceeds its bound")
            header = tarfile.TarInfo.frombuf(raw, "utf-8", "strict")
            require(0 <= header.size <= MAX_EXPANDED, "TAR member size exceeds its bound")
            if header.type == tarfile.XHDTYPE:
                pax_bytes += header.size
                require(pending is None and header.size <= 64 * 1024 and pax_bytes <= 1024 * 1024, "PAX metadata budget exceeded")
                pending = pax_path(read(header.size))
                read((-header.size) % 512)
                # A PAX header without a path still applies to exactly one entry.
                pending = pending if pending is not None else ""
                continue
            require(header.isfile() or header.isdir(), "link, special or unsupported release TAR entry")
            name = sane_name(pending or header.name, header.isdir())
            pending = None
            digest, size = hashlib.sha256(), 0
            while size < header.size:
                block = read(min(BLOCK, header.size - size))
                size += len(block)
                digest.update(block)
            read((-size) % 512)
            expanded += size
            require(not header.isdir() or size == 0, "TAR directory has data")
            records.append(member_record(name, size, None if header.isdir() else digest.hexdigest(), header.mode))
            require(len(records) <= MAX_MEMBERS, "TAR member count exceeds its bound")
    check_layout(records, root, expected)
    return {"kind": "tar.gz", "gzip_crc_and_size_checked": True, "decoded_bytes": decoded,
            "expanded_bytes": expanded, "members": records}


def extract_windows_cli(path, inspection, output):
    member = next(record for record in inspection["members"] if record["path"].endswith("/analyze-anything.exe"))
    output.mkdir()
    program = output / "analyze-anything.exe"
    with zipfile.ZipFile(path) as archive, archive.open(member["path"]) as source, program.open("xb") as target:
        shutil.copyfileobj(source, target, BLOCK)
    require(program.stat().st_size == member["size"] and sha_file(program) == member["sha256"], "extracted CLI differs from the inspected ZIP entry")
    return program


def check_catalogue(catalogue, expected):
    require(catalogue.get("schema_version") == 1, "unsupported format catalogue schema")
    formats = catalogue.get("formats")
    require(isinstance(formats, list) and len(formats) <= 10000, "invalid format catalogue length")
    ids, counts = set(), Counter()
    for entry in formats:
        identifier, group, state = entry.get("id"), entry.get("group"), entry.get("state")
        require(isinstance(identifier, str) and identifier and identifier not in ids, "duplicate or missing format family ID")
        ids.add(identifier)
        require(group in ("primary", "compression", "declaration") and state in ("implemented", "planned"), "unknown format count category")
        if state == "implemented":
            counts[group] += 1
    require(catalogue.get("counts") == dict(counts), "reported group counts differ from implemented family rows")
    total = counts["primary"] + counts["compression"]
    require(catalogue.get("primary_total_including_compression") == total == expected, "advertised format count differs from the expected implemented count")
    return {"schema_version": 1, "counts": dict(counts), "primary_total_including_compression": total,
            "implemented_ids": [entry["id"] for entry in formats if entry["state"] == "implemented"]}


def check_cli(program, version, count, output):
    require(os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64"), "full CLI verification requires Windows x64; use --archives-only elsewhere")
    actual = run([program, "--version"], cwd=program.parent).decode("utf-8").strip()
    require(actual == f"analyze-anything {version}", f"release CLI version differs: {actual!r}")
    data = run([program, "formats", "--json"], cwd=program.parent)
    require(len(data) <= 4 * 1024 * 1024, "CLI catalogue exceeds its output bound")
    catalogue = json.loads(data)
    (output / "formats.json").write_bytes(data)
    return {"version": actual, "sha256": sha_file(program), "formats": check_catalogue(catalogue, count)}


def check_workflow(program, source, version, catalogue, output):
    head = run(["git", "rev-parse", "HEAD"], cwd=REPOSITORY).decode().strip()
    require(head == source["commit"], "--check-workflow requires this checkout's HEAD to equal the release source commit")
    run(["git", "diff", "--quiet", "HEAD", "--"], cwd=REPOSITORY)
    import tomllib
    local_version = tomllib.loads((REPOSITORY / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    require(local_version == version, "local workflow source version differs")
    local = json.loads((REPOSITORY / "crates/aa-core/src/formats.json").read_text(encoding="utf-8"))
    require(local["formats"] == catalogue["formats"], "local workflow catalogue differs from the release binary")
    script = REPOSITORY / "tools/release/check-workflow.py"
    workflow_record = output / "workflow.json"
    data = run([sys.executable, script, program, "--record", workflow_record], timeout=600, cwd=REPOSITORY)
    (output / "workflow.stdout.txt").write_bytes(data)
    result = json.loads(workflow_record.read_text(encoding="utf-8"))
    require(result["program_sha256"] == sha_file(program), "workflow checked different program bytes")
    return {"passed": True, "script_sha256": sha_file(script), "record": "workflow.json", "record_sha256": sha_file(workflow_record)}


def verify(args, output, record):
    expected, archives, desktop = expected_assets(args.tag, args.version)
    record["expected_assets"] = sorted(expected)
    record["gh_version"] = run(["gh", "--version"]).decode("utf-8").splitlines()[0]
    release = release_metadata(args.repo, args.tag)
    assets = metadata_assets(release, expected)
    source = source_commit(args.repo, release)
    if args.source:
        require(source["commit"] == args.source, "release source differs from --source")
    record["release"] = {key: release.get(key) for key in ("id", "html_url", "tag_name", "target_commitish", "draft", "prerelease", "published_at")}
    record["source"] = source
    (output / "release-before.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    directory = path_under_out(args.assets_dir, must_exist=True) if args.assets_dir else output / "assets"
    record["retrieval"] = download(args.repo, args.tag, assets, directory)
    record["assets"] = check_asset_bytes(directory, assets)
    record["checksums"] = check_checksums(directory, archives, desktop, record["assets"])
    record["archives"] = {}
    for name in sorted(archives | {name for name in desktop if name.endswith(".zip")}):
        record["archives"][name] = check_zip(directory / name) if name.endswith(".zip") else check_tar_gzip(directory / name)
    if not args.archives_only:
        name = f"analyze-anything-{args.tag}-x86_64-pc-windows-msvc.zip"
        program = extract_windows_cli(directory / name, record["archives"][name], output / "windows-cli")
        record["cli"] = check_cli(program, args.version, args.count, output)
        if args.check_workflow:
            catalogue = json.loads((output / "formats.json").read_text(encoding="utf-8"))
            record["workflow"] = check_workflow(program, source, args.version, catalogue, output)
    after = gh_json(f"repos/{args.repo}/releases/{release['id']}")
    (output / "release-after.json").write_text(json.dumps(after, indent=2) + "\n", encoding="utf-8")
    require(fingerprint(release) == fingerprint(after), "release metadata or assets changed during verification")
    require(source == source_commit(args.repo, after), "release tag moved during verification")
    record["metadata_unchanged"] = True
    record["full_verified"] = not args.archives_only
    record["status"] = "verified" if record["full_verified"] else "archives-verified-cli-not-run"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag")
    parser.add_argument("--version", required=True, help="exact expected CLI/desktop version, without leading v")
    parser.add_argument("--count", required=True, type=int, help="expected implemented primary + compression family count")
    parser.add_argument("--repo", default="atomsprout/analyze-anything")
    parser.add_argument("--source", help="optional exact expected release source commit SHA")
    parser.add_argument("--out", type=Path, help="new output directory under this checkout's out/")
    parser.add_argument("--assets-dir", type=Path, help="reuse/download asset files in an existing directory under out/")
    parser.add_argument("--archives-only", action="store_true", help="incomplete dry validation; do not execute a CLI or verify its format count")
    parser.add_argument("--check-workflow", action="store_true", help="also run current check-workflow.py; requires matching, unmodified tracked source")
    args = parser.parse_args()
    parser.error("--tag must equal v<version>") if not VERSION.fullmatch(args.version) or args.tag != "v" + args.version else None
    parser.error("--count must be between 1 and 10000") if not 1 <= args.count <= 10000 else None
    parser.error("invalid --repo") if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) else None
    parser.error("--source must be a full lowercase commit SHA") if args.source and not SHA1.fullmatch(args.source) else None
    parser.error("--archives-only and --check-workflow cannot be combined") if args.archives_only and args.check_workflow else None
    if args.out:
        output = path_under_out(args.out)
        output.mkdir(parents=True)
    else:
        base = REPOSITORY / "out/verify-published"
        base.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix=args.tag + "-", dir=path_under_out(base)))
    record = {"schema_version": 1, "repository": args.repo, "expected_version": args.version,
              "expected_format_count": args.count, "mode": "archives-only" if args.archives_only else "full",
              "full_verified": False, "status": "failed", "verifier_sha256": sha_file(Path(__file__)),
              "execution_scope": "Only the release Windows CLI; installers and analyzed samples are never executed.",
              "workflow_contract_sha256": sha_file(REPOSITORY / ".github/workflows/release.yml")}
    try:
        verify(args, output, record)
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    record_path = output / "verification.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": record["status"], "full_verified": record["full_verified"],
                      "record": str(record_path.relative_to(REPOSITORY)), "error": record.get("error")}))
    return 0 if record["status"] != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
