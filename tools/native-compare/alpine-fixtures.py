#!/usr/bin/env python3
"""Build inert project-authored APK v2 declarations; never run their scripts."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import tarfile


def archive(files, cut):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data, mode in files:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.uid = entry.gid = entry.mtime = 0
            if not name.startswith("."):
                entry.pax_headers["APK-TOOLS.checksum.SHA1"] = hashlib.sha1(data).hexdigest()
            tar.addfile(entry, io.BytesIO(data))
    data = output.getvalue()
    if cut:
        while data.endswith(bytes(512)):
            data = data[:-512]
    return gzip.compress(data, mtime=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    payload = archive([("usr/share/aa-fixture/data.txt", b"Project-authored inert payload.\n", 0o644)], False)
    info = ("pkgname = aa-native-fixture\npkgver = 1.2-r0\narch = noarch\nlicense = Apache-2.0\n"
            "pkgdesc = Inert native inspection fixture\nsize = 32\ndepend = so:libc.musl.so.1\n"
            "triggers = /usr/share/aa-fixture\ndatahash = " + hashlib.sha256(payload).hexdigest() + "\n").encode()
    control = archive([(".PKGINFO", info, 0o644), (".post-install", b"#!/bin/sh\n# Inert source, never run by these checks.\n", 0o755),
                       (".trigger", b"#!/bin/sh\n# Trigger source retained only as bytes.\n", 0o755)], True)
    unsigned = control + payload
    # Deliberately inert signature bytes; the reader must never call this verified.
    signature = archive([(".SIGN.RSA.aa-fixture.rsa.pub", b"inert signature bytes, no key or certificate\n", 0o644)], True)
    for name, data in [("native-unsigned.apk", unsigned), ("native-signature-declaration.apk", signature + unsigned)]:
        (args.output / name).write_bytes(data)
        print(name + " " + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    main()
