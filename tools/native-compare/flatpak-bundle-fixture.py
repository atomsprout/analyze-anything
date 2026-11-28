#!/usr/bin/env python3
"""Create an inert project-owned bundle with the native Flatpak writer, without installing it."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def run(*arguments):
    subprocess.run([str(argument) for argument in arguments], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    tree = output / "source"
    (tree / "files/share/fixture").mkdir(parents=True, exist_ok=True)
    (tree / "export").mkdir(exist_ok=True)
    (tree / "metadata").write_text(
        "[Application]\nname=org.example.AnalyzeAnythingFixture\n"
        "runtime=org.example.InertRuntime/x86_64/1\ncommand=never-run\n"
        "[Context]\nshared=network;\nsockets=wayland;\nfilesystems=home:ro;\n",
        encoding="utf-8")
    (tree / "files/share/fixture/message.txt").write_text("Inert Apache-2.0 fixture payload.\n", encoding="utf-8")
    (tree / "files/share/fixture/empty").write_bytes(b"")
    (tree / "files/share/fixture/中文.txt").write_text("静态数据\n", encoding="utf-8")
    link = tree / "files/share/fixture/alias"
    if not link.is_symlink():
        link.symlink_to("message.txt")
    repo = output / "repo"
    run("ostree", "--repo=" + str(repo), "init", "--mode=archive-z2")
    run("ostree", "--repo=" + str(repo), "commit", "--branch=app/org.example.AnalyzeAnythingFixture/x86_64/stable",
        "--tree=dir=" + str(tree), "--subject=Inert project-authored fixture",
        "--timestamp=2020-01-01T00:00:00Z")
    bundle = output / "native-inert.flatpak"
    run("flatpak", "build-bundle", "--arch=x86_64", "--repo-url=https://example.invalid/repository",
        repo, bundle, "org.example.AnalyzeAnythingFixture", "stable")
    rows = []
    for path in sorted(tree.rglob("*")):
        name = path.relative_to(tree).as_posix()
        if path.is_symlink():
            rows.append({"path": name, "link_target": str(path.readlink())})
        elif path.is_file():
            data = path.read_bytes()
            rows.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    (output / "source-reference.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Created only repository data and a bundle; no application or package script was run.")


if __name__ == "__main__":
    main()
