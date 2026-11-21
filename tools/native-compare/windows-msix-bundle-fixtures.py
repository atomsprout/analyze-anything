"""Build an owned application/resource bundle with MakeAppx, without installing it."""

import argparse
import glob
from pathlib import Path
import subprocess
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if sys.platform != "win32" or output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh directory below this Windows checkout's out directory")
    candidates = [Path(p) for p in glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe")]
    if not candidates:
        parser.error("Windows SDK MakeAppx was not found")
    makeappx = max(candidates, key=lambda p: tuple(int(n) for n in p.parent.parent.name.split(".")))
    output.mkdir(parents=True)
    packages = output / "packages"
    packages.mkdir()
    with zipfile.ZipFile(repository / "crates/aa-windows/tests/data/native-msix-sha256.msix") as archive:
        files = {name: archive.read(name) for name in ["AppxManifest.xml", "hello.exe", "Assets/Logo150.png", "Assets/Logo44.png"]}
    app_xml = files["AppxManifest.xml"].decode("utf-8").replace("AnalyzeAnything.BlockMapFixture", "AnalyzeAnything.BundleFixture")
    resource_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
 <Identity Name="AnalyzeAnything.BundleFixture" Publisher="CN=Analyze Anything Fixture"
  Version="1.0.0.0" ResourceId="language-zh"/>
 <Properties><DisplayName>Bundle resource fixture</DisplayName><PublisherDisplayName>Fixture</PublisherDisplayName>
  <Logo>Assets/Logo150.png</Logo><ResourcePackage>true</ResourcePackage></Properties>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
 <Resources><Resource Language="zh-CN"/></Resources>
</Package>'''
    def run(arguments):
        done = subprocess.run([str(makeappx), *arguments], capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
        if done.returncode:
            raise RuntimeError(done.stdout.decode("utf-8", errors="replace") + done.stderr.decode("utf-8", errors="replace"))
    for name, xml, names in [("app", app_xml, ["hello.exe", "Assets/Logo150.png", "Assets/Logo44.png"]),
                              ("resource", resource_xml, ["Assets/Logo150.png"])]:
        source = output / (name + "-input")
        source.mkdir()
        (source / "AppxManifest.xml").write_text(xml, encoding="utf-8")
        for path in names:
            destination = source / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(files[path])
        run(["pack", "/d", str(source), "/p", str(packages / (name + ".appx")), "/o"])
    run(["bundle", "/d", str(packages), "/p", str(output / "native-msix-bundle.appxbundle"), "/bv", "2.0.0.0", "/o"])
    print("built application/resource bundle with SDK", makeappx.parent.parent.name)


if __name__ == "__main__":
    main()
