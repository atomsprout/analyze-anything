#!/usr/bin/env python3
"""Build project-authored Linux packages; declared installation scripts are never run."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aa-package-build-") as folder:
        folder = Path(folder)
        deb = folder / "deb"
        (deb / "DEBIAN").mkdir(parents=True)
        (deb / "usr/share/aa-fixture").mkdir(parents=True)
        (deb / "usr/share/aa-fixture/data.txt").write_text("https://example.invalid/native-fixture\n")
        (deb / "DEBIAN/control").write_text("Package: aa-native-fixture\nVersion: 1.2-3\nArchitecture: all\n"
            "Maintainer: Fixture <fixture@example.invalid>\nDescription: Project-authored static analysis fixture\n"
            "Depends: alternative-a (>= 1) | alternative-b\n")
        (deb / "DEBIAN/postinst").write_text("#!/bin/sh\nprintf 'not executed by these checks\\n'\n")
        (deb / "DEBIAN/postinst").chmod(0o755)
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(deb), str(args.out.resolve() / "native-script.deb")], check=True)
        rpm = folder / "rpm"
        for name in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (rpm / name).mkdir(parents=True)
        spec = rpm / "SPECS/fixture.spec"
        spec.write_text("""Name: aa-native-fixture
Version: 1.2
Release: 3
Summary: Project-authored static analysis fixture
License: Apache-2.0
BuildArch: noarch
Requires: /bin/sh
%description
Only project-authored text and declared scripts. No fixture payload is executed.
%install
mkdir -p %{buildroot}/usr/share/aa-fixture
printf 'https://example.invalid/native-fixture\\n' > %{buildroot}/usr/share/aa-fixture/data.txt
%post
printf 'not executed by these checks\\n'
%preun
printf 'not executed by these checks\\n'
%files
/usr/share/aa-fixture/data.txt
""")
        subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {rpm}", "--define", "_binary_payload w9.gzdio", str(spec)], check=True)
        shutil.copyfile(next((rpm / "RPMS/noarch").glob("*.rpm")), args.out / "native-script.rpm")


if __name__ == "__main__":
    main()
