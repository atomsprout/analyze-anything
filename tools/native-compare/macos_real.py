"""Compares the analyzer with codesign on real applications already on this Mac.

    python3 tools/native-compare/macos_real.py path/to/aa /Applications/Some.app [more.app ...]

For each application, and each application, extension or XPC service nested inside it, the main
executable's signature as this program reads it must match what `codesign` reports: code
directory hash, identifier, team, flags, certificate chain, entitlement keys, and whether the
seal verifies. Nothing is downloaded and nothing is run.
"""
import os
import sys

from common import check, finish
from macos import compare_signature

NESTED = (".app", ".appex", ".xpc")


def bundles(app):
    yield app
    for base, dirs, _files in os.walk(app):
        for name in list(dirs):
            path = os.path.join(base, name)
            if os.path.islink(path):
                dirs.remove(name)
            elif name.endswith(NESTED):
                yield path


def main():
    apps = sys.argv[2:]
    if not apps:
        raise SystemExit(__doc__)
    for app in apps:
        for bundle in bundles(app.rstrip("/")):
            label = os.path.relpath(bundle, os.path.dirname(app.rstrip("/")))
            try:
                compare_signature(label, bundle)
            except Exception as error:  # one unreadable bundle must not hide the others
                check(f"{label}: compared", False, error)
    finish()


if __name__ == "__main__":
    main()
