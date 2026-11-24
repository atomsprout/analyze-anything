"""Compare embedded members with read-only .NET BinaryReader/DeflateStream results."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from common import analyze, check, finish, sha256_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analyzer", help="CLI built without AI features")
    parser.add_argument("sample")
    parser.add_argument("--record", required=True)
    parser.add_argument("--reference", help="Reuse a native comparison record bound to this sample's SHA-256")
    args = parser.parse_args()
    if args.reference:
        previous = json.loads(Path(args.reference).read_text(encoding="utf-8-sig"))
        if previous["sha256"] != sha256_file(args.sample):
            raise ValueError("native reference belongs to different sample bytes")
        native = previous["reference"]
    else:
        with tempfile.TemporaryDirectory(prefix="aa-dotnet-reference-") as work:
            native_path = Path(work, "reference.json")
            subprocess.run(["pwsh", "-NoProfile", "-File", str(Path(__file__).with_suffix(".ps1")),
                            "-Sample", str(Path(args.sample).resolve()), "-Record", str(native_path)], check=True, timeout=180)
            native = json.loads(native_path.read_text(encoding="utf-8-sig"))
    report = analyze(str(Path(args.analyzer).resolve()), str(Path(args.sample).resolve()))
    root = next(a for a in report["artifacts"] if a["parent"] is None)
    metadata = root["facts"].get("dotnet-bundle.manifest", {})
    check("bundle version agrees", metadata.get("version") == native["version"])
    check("bundle header offset agrees", metadata.get("header_offset") == native["header_offset"])
    check("bundle identifier agrees", metadata.get("bundle_id") == native["bundle_id"])
    declared = [{key: row[key] for key in ("path", "offset", "size", "compressed_size", "type", "manifest_offset")}
                for row in native["files"]]
    check("all manifest fields agree with BinaryReader", metadata.get("entries") == declared)
    children = {a["path"][len(root["path"]) + 1:]: (a.get("digests") or {}).get("sha256")
                for a in report["artifacts"] if a["parent"] == root["path"]}
    expected = {row["path"]: row["sha256"] for row in native["files"]}
    check("all embedded contents agree with native DeflateStream and SHA-256", children == expected,
          {"missing": sorted(set(expected) - set(children))[:10], "different": [p for p in expected if children.get(p) != expected[p]][:10]})
    record = {"sample": Path(args.sample).name, "sha256": sha256_file(args.sample), "reference": native,
              "manifest_agrees": metadata.get("entries") == declared, "contents_agree": children == expected,
              "limitations": report["limitations"]}
    Path(args.record).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finish()


if __name__ == "__main__":
    main()
