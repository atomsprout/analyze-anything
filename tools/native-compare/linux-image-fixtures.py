#!/usr/bin/env python3
"""Fetch a pinned external AppImage for read-only qualification; never execute it."""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


APPIMAGE = {
    "file": "appimagetool-12-x86_64.AppImage",
    "source": "https://github.com/AppImage/AppImageKit/releases/download/12/appimagetool-x86_64.AppImage",
    "sha256": "d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13",
    "size": 1974248,
    "source_project": "https://github.com/AppImage/AppImageKit/tree/12",
    "source_license": "MIT, Copyright (c) 2004-18 Simon Peter; bundled dependencies retain their own licences",
    "license_source": "https://github.com/AppImage/AppImageKit/blob/12/LICENSE",
    "redistributed_in_repository": False,
    "filesystem_offset": 188392,
    "compression_id": 1,
    "input_executed": False,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="external sample directory, normally under ignored out/")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(APPIMAGE["source"], timeout=60) as response:
        data = response.read(APPIMAGE["size"] + 1)
    if len(data) != APPIMAGE["size"] or hashlib.sha256(data).hexdigest() != APPIMAGE["sha256"]:
        raise ValueError("external AppImage size or SHA-256 differs from the pinned qualification input")
    (args.output / APPIMAGE["file"]).write_bytes(data)
    (args.output / "appimage-source.json").write_text(json.dumps(APPIMAGE, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"file": APPIMAGE["file"], "sha256": APPIMAGE["sha256"], "size": len(data)}))


if __name__ == "__main__":
    main()
