#!/usr/bin/env python3
"""Write inert OCI and Docker-save images with umoci/skopeo, never run or unpack them.

Only project-authored Apache-2.0 data is inserted into a new, empty image. This
is the native writer equivalent of FROM scratch plus COPY/config declarations;
there is no RUN, image import, daemon load, container launch or registry access.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile


STAMP = 1577836800


def run(*arguments):
    completed = subprocess.run([str(argument) for argument in arguments],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=dict(os.environ, LC_ALL="C", LANG="C"))
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace"))
    return completed.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def freeze(tree):
    # Only the project-owned source tree is changed. Symlink targets are not followed.
    for path in sorted(tree.rglob("*"), key=lambda path: len(path.parts), reverse=True):
        os.utime(path, (STAMP, STAMP), follow_symlinks=False)
    os.utime(tree, (STAMP, STAMP), follow_symlinks=False)


def layer_member(archive, name, body=b"", kind=tarfile.REGTYPE, target="", mode=0o644, pax=None):
    header = tarfile.TarInfo(name)
    header.type = kind
    header.mode = mode
    header.mtime = STAMP
    header.uid = header.gid = 0
    header.linkname = target
    header.pax_headers = dict(pax or {})
    header.size = len(body) if kind == tarfile.REGTYPE else 0
    archive.addfile(header, io.BytesIO(body) if header.size else None)


def write_layers(output, base, replacement):
    """Finalize ordinary PAX TARs before handing them to the native image writer."""
    first = output / "source-layer.tar"
    with tarfile.open(first, "w", format=tarfile.PAX_FORMAT) as archive:
        layer_member(archive, "fixture/", kind=tarfile.DIRTYPE, mode=0o755)
        layer_member(archive, "fixture/message.txt", (base / "message.txt").read_bytes())
        # These conflicting base headers remain inert TAR data. The effective
        # values exist in local PAX records and must not be attributed to the
        # following 512-byte base header alone.
        layer_member(archive, "fixture/pax-link", kind=tarfile.SYMTYPE, target="benign", mode=0o777,
                     pax={"linkpath": "../outside"})
        layer_member(archive, "fixture/alias", kind=tarfile.SYMTYPE, target="message.txt", mode=0o777)
        layer_member(archive, "fixture/hardlink", kind=tarfile.LNKTYPE, target="fixture/message.txt")
        for name in ("empty", "obsolete.txt", "中文.txt"):
            layer_member(archive, "fixture/" + name, (base / name).read_bytes())
        layer_member(archive, "fixture/pax-base-name.txt", b"PAX metadata source provenance.\n",
                     pax={"path": "fixture/pax-effective-name.txt"})
    second = output / "whiteout-layer.tar"
    with tarfile.open(second, "w", format=tarfile.PAX_FORMAT) as archive:
        layer_member(archive, "fixture/.wh.obsolete.txt", mode=0)
    third = output / "opaque-layer.tar"
    with tarfile.open(third, "w", format=tarfile.PAX_FORMAT) as archive:
        layer_member(archive, "opaque/.wh..wh..opq", mode=0)
        layer_member(archive, "opaque/", kind=tarfile.DIRTYPE, mode=0o755)
        layer_member(archive, "opaque/replacement.txt", (replacement / "replacement.txt").read_bytes())
    return [first, second, third]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    base = output / "source"
    base.mkdir(exist_ok=True)
    (base / "message.txt").write_text("Inert Apache-2.0 image fixture payload.\n", encoding="utf-8")
    (base / "empty").write_bytes(b"")
    (base / "obsolete.txt").write_text("A later layer declares a whiteout for this name.\n", encoding="utf-8")
    (base / "中文.txt").write_text("静态图像数据\n", encoding="utf-8")
    alias = base / "alias"
    if not alias.is_symlink():
        alias.symlink_to("message.txt")
    hardlink = base / "hardlink"
    if not hardlink.exists():
        os.link(base / "message.txt", hardlink)
    replacement = output / "replacement"
    replacement.mkdir(exist_ok=True)
    (replacement / "replacement.txt").write_text("Literal opaque-directory layer data.\n", encoding="utf-8")
    freeze(base)
    freeze(replacement)
    layout = output / "layout"
    run("umoci", "init", "--layout", layout)
    run("umoci", "new", "--image", str(layout) + ":fixture")
    image = str(layout) + ":fixture"
    run("umoci", "config", "--image", image, "--no-history", "--created", "2020-01-01T00:00:00Z",
        "--architecture", "amd64", "--os", "linux", "--config.user", "123:456", "--config.workingdir", "/fixture",
        "--config.entrypoint", "/never-run", "--config.cmd", "literal-argument", "--config.cmd=--literal-option",
        "--config.env", "FIXTURE_LITERAL=present", "--config.env", "PASSWORD=synthetic-redaction-probe",
        "--config.exposedports", "8080/tcp", "--config.volume", "/state",
        "--manifest.annotation", "org.opencontainers.image.title=Inert native image fixture")
    # Ubuntu's umoci 0.4.7 insert path can omit final TAR padding/trailers. Keep
    # that boundary explicit rather than silently repairing bytes in a reader.
    # raw add-layer consumes these finalized, project-authored TARs verbatim and
    # natively writes gzip blobs, diff_ids, config and manifest descriptors.
    layers = write_layers(output, base, replacement)
    for layer in layers:
        run("umoci", "raw", "add-layer", "--image", image, "--no-history", layer)
    oci = output / "native-inert.oci.tar"
    docker = output / "native-inert.docker.tar"
    run("skopeo", "--insecure-policy", "copy", "oci:" + image, "oci-archive:" + str(oci) + ":fixture")
    run("skopeo", "--insecure-policy", "copy", "oci:" + image,
        "docker-archive:" + str(docker) + ":example.invalid/inert:fixture")
    originals = []
    for tree, prefix in [(base, "fixture"), (replacement, "opaque")]:
        for path in sorted(tree.rglob("*")):
            name = prefix + "/" + path.relative_to(tree).as_posix()
            if path.is_symlink():
                originals.append({"path": name, "link_target": str(path.readlink())})
            elif path.is_file():
                data = path.read_bytes()
                originals.append({"path": name, "size": len(data), "sha256": sha(data)})
    native = {"tools": {"umoci": run("umoci", "--version").decode().strip(),
                         "skopeo": run("skopeo", "--version").decode().strip()},
              "source_entries": originals,
              "layer_only_declarations": [
                  {"path": "fixture/pax-link", "raw_header_link_target": "benign", "pax_linkpath": "../outside"},
                  {"raw_header_path": "fixture/pax-base-name.txt", "pax_path": "fixture/pax-effective-name.txt"}],
              "source_layers": [{"sample": path.name, "sha256": sha(path.read_bytes()), "size": path.stat().st_size}
                                for path in layers],
              "umoci_stat": json.loads(run("umoci", "stat", "--image", image, "--json")),
              "archives": []}
    for path, transport in [(oci, "oci-archive"), (docker, "docker-archive")]:
        native["archives"].append({"sample": path.name, "sha256": sha(path.read_bytes()), "size": path.stat().st_size,
                                    "manifest": json.loads(run("skopeo", "inspect", "--raw", transport + ":" + str(path))),
                                    "config": json.loads(run("skopeo", "inspect", "--config", "--raw", transport + ":" + str(path)))})
    (output / "source-reference.json").write_text(json.dumps(native, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Created local OCI and Docker-save archives from inert source; no image was run, loaded or unpacked.")


if __name__ == "__main__":
    main()
