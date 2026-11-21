"""Build project-owned MSIX inputs with MakeAppx; never install or run them."""

import argparse
import binascii
import glob
from pathlib import Path
import struct
import subprocess
import sys
import zlib


def png(size):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data))
    pixels = (b"\0" + bytes([40, 110, 170, 255]) * size) * size
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("MakeAppx fixture generation requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if not output.is_relative_to(repository / "out"):
        parser.error("fixture output must stay below this checkout's out directory")
    candidates = [Path(p) for p in glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe")]
    if not candidates:
        parser.error("Windows SDK MakeAppx was not found")
    makeappx = max(candidates, key=lambda p: tuple(int(n) for n in p.parent.parent.name.split(".")))
    output.mkdir(parents=True, exist_ok=True)
    source = output / "input"
    if source.is_symlink() or source.is_junction():
        parser.error("fixture input must not redirect through a link or junction")
    source.mkdir(exist_ok=True)
    manifest = '''<?xml version="1.0" encoding="UTF-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
 IgnorableNamespaces="uap rescap">
 <Identity Name="AnalyzeAnything.BlockMapFixture" Publisher="CN=Analyze Anything Fixture" Version="1.0.0.0" ProcessorArchitecture="x86"/>
 <Properties><DisplayName>Block Map Fixture</DisplayName><PublisherDisplayName>Fixture</PublisherDisplayName><Logo>Assets/Logo150.png</Logo></Properties>
 <Resources><Resource Language="en-us"/></Resources>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
 <Applications><Application Id="App" Executable="hello.exe" EntryPoint="Windows.FullTrustApplication">
 <uap:VisualElements DisplayName="Block Map Fixture" Description="Static analysis fixture"
  Square150x150Logo="Assets/Logo150.png" Square44x44Logo="Assets/Logo44.png" BackgroundColor="transparent"/>
 </Application></Applications>
 <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>'''
    files = {"AppxManifest.xml": manifest.encode("utf-8"), "hello.exe": (repository / "crates/aa-windows/tests/data/hello.exe").read_bytes(),
             "payload.bin": bytes((i * 37 + 19) % 256 for i in range(65543)), "empty.dat": b"",
             "Assets/Logo150.png": png(150), "Assets/Logo44.png": png(44)}
    existing = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    if existing - set(files):
        parser.error("unexpected old fixture files; choose a fresh output directory")
    for name, data in files.items():
        path = source / name
        if not path.resolve().is_relative_to(source.resolve()) or path.is_symlink() or path.is_junction():
            parser.error("fixture file path redirects outside the controlled input")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for algorithm, stored in (("SHA256", False), ("SHA384", False), ("SHA512", True)):
        package = output / ("native-msix-" + algorithm.lower() + ".msix")
        command = [str(makeappx), "pack", "/d", str(source), "/p", str(package), "/h", algorithm, "/o"]
        if stored:
            command.append("/nc")
        result = subprocess.run(command, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(result.stdout.decode("utf-8", errors="replace"))
        print("built", package.name, "with SDK", makeappx.parent.parent.name)


if __name__ == "__main__":
    main()
