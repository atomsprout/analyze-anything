"""Compare CArchive members with PyInstaller's own read-only archive-viewer reader.

Run with a development Python environment containing PyInstaller. This imports no
module from the sample and never opens the embedded marshal/PYZ object directory.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

import PyInstaller
from PyInstaller.archive.readers import CArchiveReader

from common import analyze, check, finish, sha256_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analyzer", help="CLI built without AI features")
    parser.add_argument("sample")
    parser.add_argument("--record", required=True)
    args = parser.parse_args()
    native = CArchiveReader(str(Path(args.sample).resolve()))
    files = []
    for name, (offset, stored, size, compressed, kind) in native.toc.items():
        if size > 512 * 1024 * 1024 or len(files) >= 10000:
            raise ValueError("sample exceeds reference profile")
        if kind in ("n", "d"):
            raise ValueError("reference sample has unresolved links/dependencies")
        data = native.extract(name)
        check(f"{name}: native member size matches declaration", len(data) == size)
        files.append({"name": name, "offset": native._start_offset + offset, "stored_size": stored,
                      "size": size, "compression_flag": compressed, "type": kind,
                      "sha256": hashlib.sha256(data).hexdigest()})
    report = analyze(str(Path(args.analyzer).resolve()), str(Path(args.sample).resolve()))
    root = next(a for a in report["artifacts"] if a["parent"] is None)
    directory = root["facts"].get("pyinstaller.directory", {})
    check("archive start agrees", directory.get("archive_start") == native._start_offset)
    with open(args.sample, "rb") as handle:
        handle.seek(native._end_offset - native._COOKIE_LENGTH)
        cookie = struct.unpack(native._COOKIE_FORMAT, handle.read(native._COOKIE_LENGTH))
    check("cookie declarations agree with archive reader layout",
          directory.get("cookie_offset") == native._end_offset - native._COOKIE_LENGTH
          and directory.get("python_version") == cookie[4]
          and directory.get("python_library") == cookie[5].rstrip(b"\0").decode("utf-8"))
    entries = directory.get("entries", [])
    observed = [{key: row[key] for key in ("name", "offset", "stored_size", "size", "compression_flag", "type")}
                for row in entries if row["type"] != "o"]
    declared = [{key: value for key, value in row.items() if key != "sha256"} for row in files]
    check("all member declarations agree with CArchiveReader", observed == declared)
    check("runtime options are retained as declarations", [row["name"] for row in entries if row["type"] == "o"] == native.options)
    children = {a["path"][len(root["path"]) + 1:]: (a.get("digests") or {}).get("sha256")
                for a in report["artifacts"] if a["parent"] == root["path"]}
    expected = {row["name"].replace("\\", "/"): row["sha256"] for row in files}
    check("native member names have unique logical paths", len(expected) == len(files))
    check("all captured member digests agree", children == expected,
          {"missing": sorted(set(expected) - set(children))[:10], "different": [p for p in expected if children.get(p) != expected[p]][:10]})
    codes = dict(Counter(item["code"] for item in report["limitations"]))
    if any(row["type"] in "zmMs" for row in files):
        check("opaque Python code is explicitly reported", "pyinstaller.python-code" in codes)
    record = {"sample": Path(args.sample).name, "sha256": sha256_file(args.sample), "reference_version": PyInstaller.__version__,
              "archive_start": native._start_offset, "files": files, "options": native.options,
              "declarations_agree": observed == declared, "contents_agree": children == expected, "limitations": codes}
    Path(args.record).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finish()


if __name__ == "__main__":
    main()
