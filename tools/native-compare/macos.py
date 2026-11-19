"""Compares the analyzer with macOS's own codesign, hdiutil and pkgbuild."""
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zlib

from common import analyze, check, children_digests, compare_files, finish, folder_digests, limitation_codes, rules

AA = os.path.abspath(sys.argv[1])
WORK = tempfile.mkdtemp(prefix="aa-native-")
# Files macOS itself adds to a volume; they are not part of what was put on the image.
VOLUME_NOISE = (".fseventsd", ".Trashes", ".DS_Store", ".HFS+ Private", ".journal", ".Spotlight", ".TemporaryItems", ".VolumeIcon", ".DocumentRevisions")
BROKEN = {"apple.code-modified", "apple.seal-broken", "apple.resources-modified", "apple.resources-missing", "apple.cms-invalid", "apple.nested-code-replaced"}


def run(*command, **options):
    return subprocess.run(command, capture_output=True, text=True, **options)


def codesign(path):
    """What `codesign -dvvv` says about the code at `path`, for every architecture it holds."""
    slices = []
    archs = re.findall(r"\b(arm64e?|x86_64)\b", run("lipo", "-archs", path).stdout) or [None]
    for arch in archs:
        command = ["codesign", "-dvvv"] + (["-a", arch] if arch else []) + [path]
        text = run(*command).stderr
        field = lambda key: (re.search(rf"^{key}=(.*)$", text, re.M) or [None, None])[1]
        flags = re.search(r"flags=0x([0-9a-f]+)", text)
        slices.append({
            "arch": arch,
            "identifier": field("Identifier"),
            "team": None if field("TeamIdentifier") in (None, "not set") else field("TeamIdentifier"),
            "cdhash": field("CDHash"),
            "flags": int(flags.group(1), 16) if flags else None,
            "authorities": re.findall(r"^Authority=(.*)$", text, re.M),
            "signed": "code object is not signed" not in text,
        })
    entitlements = run("codesign", "-d", "--entitlements", "-", "--xml", path).stdout.strip()
    keys = sorted(plistlib.loads(entitlements.encode()).keys()) if entitlements.startswith("<?xml") else []
    return slices, keys, run("codesign", "--verify", "--strict", path).returncode == 0


def main_executable(app):
    for candidate in ("Contents/Info.plist", "Info.plist"):
        info = os.path.join(app, candidate)
        if os.path.exists(info):
            with open(info, "rb") as handle:
                name = plistlib.load(handle).get("CFBundleExecutable")
            relative = ("Contents/MacOS/" if candidate.startswith("Contents") else "") + name
            return relative
    raise RuntimeError("no Info.plist in " + app)


def compare_signature(label, app):
    relative = main_executable(app)
    native, native_keys, native_valid = codesign(os.path.join(app, relative))
    report = analyze(AA, app)
    artifact = next((a for a in report["artifacts"] if a["path"] == relative), None)
    fact = (artifact or {}).get("facts", {}).get("apple.macho")
    if not fact:
        check(f"{label}: main executable {relative} was analyzed", False, [a["path"] for a in report["artifacts"]][:5])
        return report
    ours = {s["signature"]["cdhash"]: s["signature"] for s in fact["slices"] if s.get("signature")}
    for native_slice in native:
        if not native_slice["signed"]:
            check(f"{label} [{native_slice['arch']}]: both say unsigned", not ours)
            continue
        mine = ours.get(native_slice["cdhash"])
        # codesign prints the first 20 bytes of the code directory hash; ours is the same value.
        check(f"{label} [{native_slice['arch']}]: cdhash {native_slice['cdhash']}", mine is not None, sorted(ours))
        if mine is None:
            continue
        check(f"{label} [{native_slice['arch']}]: identifier", mine["identifier"] == native_slice["identifier"], (mine["identifier"], native_slice["identifier"]))
        check(f"{label} [{native_slice['arch']}]: team", mine.get("team_id") == native_slice["team"], (mine.get("team_id"), native_slice["team"]))
        check(f"{label} [{native_slice['arch']}]: flags", mine["flags"] == native_slice["flags"], (mine["flags"], native_slice["flags"]))
        certificates = [c.get("common_name") for c in ((mine.get("cms") or {}).get("chain") or {}).get("certificates", [])]
        check(f"{label} [{native_slice['arch']}]: certificate chain", certificates == native_slice["authorities"], (certificates, native_slice["authorities"]))
        our_keys = sorted((mine.get("entitlements") or {}).keys())
        check(f"{label} [{native_slice['arch']}]: entitlement keys ({len(native_keys)})", our_keys == native_keys, (our_keys[:12], native_keys[:12]))
    broken = sorted(rules(report) & BROKEN)
    check(f"{label}: codesign --verify {'passes' if native_valid else 'fails'}, and we agree", native_valid == (not broken), broken)
    return report


def download(url, name):
    path = os.path.join(WORK, name)
    urllib.request.urlretrieve(url, path)
    return path


def attach(image):
    mount = tempfile.mkdtemp(prefix="aa-mount-")
    done = run("hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mount, image)
    if done.returncode != 0:
        raise RuntimeError("hdiutil attach failed: " + done.stderr)
    return mount


def detach(mount):
    run("hdiutil", "detach", mount, "-force")


def make_source():
    """A small folder with the kinds of content a volume holds."""
    source = os.path.join(WORK, "source")
    os.makedirs(os.path.join(source, "nested", "deeper"))
    with open(os.path.join(source, "readme.txt"), "w") as handle:
        handle.write("hello from the native comparison\n" * 50)
    with open(os.path.join(source, "nested", "random.bin"), "wb") as handle:
        handle.write(os.urandom(3 * 1024 * 1024))
    with open(os.path.join(source, "nested", "zeros.bin"), "wb") as handle:
        handle.write(bytes(2 * 1024 * 1024))
    with open(os.path.join(source, "nested", "deeper", "名字 with spaces.txt"), "w") as handle:
        handle.write("unicode name\n")
    with open(os.path.join(source, "text.log"), "w") as handle:
        handle.write("".join(f"line {i} of a compressible file\n" for i in range(40000)))
    with open(os.path.join(source, "empty"), "w"):
        pass
    return source


def payload_magics(package):
    """The first bytes of each Payload entry in a xar archive, read independently."""
    with open(package, "rb") as handle:
        data = handle.read()
    header, _version, toc_length, _toc_unpacked = struct.unpack(">HHQQ", data[4:24])
    toc = zlib.decompress(data[header:header + toc_length]).decode("utf-8", "replace")
    heap = header + toc_length
    found = []
    for block in re.findall(r'<file id="\d+">(.*?)</file>', toc, re.S):
        if re.search(r"<name>Payload</name>", block):
            offset = re.search(r"<data>.*?<offset>(\d+)</offset>", block, re.S)
            if offset:
                found.append(data[heap + int(offset.group(1)):heap + int(offset.group(1)) + 4])
    return found


def main():
    print(run("sw_vers").stdout, flush=True)

    # 1. Code signatures of apps that ship with macOS.
    for app in ("/System/Applications/Calculator.app", "/System/Applications/TextEdit.app", "/System/Applications/Utilities/Terminal.app", "/Applications/Safari.app"):
        if os.path.isdir(app):
            compare_signature(os.path.basename(app), app)

    # 2. A real third-party image: the volume's files and the app's signature.
    image = download("https://github.com/rxhanson/Rectangle/releases/download/v0.93/Rectangle0.93.dmg", "Rectangle0.93.dmg")
    mount = attach(image)
    try:
        report = analyze(AA, image)
        compare_files("Rectangle0.93.dmg against the mounted volume", folder_digests(mount), children_digests(report, "Rectangle0.93.dmg"), VOLUME_NOISE)
        app = os.path.join(WORK, "Rectangle.app")
        shutil.copytree(os.path.join(mount, "Rectangle.app"), app, symlinks=True)
    finally:
        detach(mount)
    compare_signature("Rectangle.app (Developer ID)", app)

    # 3. The same app after tampering: both tools must object.
    resource_app = os.path.join(WORK, "Rectangle-resource.app")
    shutil.copytree(app, resource_app, symlinks=True)
    resources = os.path.join(resource_app, "Contents", "Resources")
    victim = next(os.path.join(resources, n) for n in sorted(os.listdir(resources)) if os.path.isfile(os.path.join(resources, n)) and not os.path.islink(os.path.join(resources, n)))
    with open(victim, "ab") as handle:
        handle.write(b"tampered")
    native_ok = run("codesign", "--verify", "--deep", "--strict", resource_app).returncode == 0
    broken = sorted(rules(analyze(AA, resource_app)) & BROKEN)
    check("changed resource: codesign rejects it and so do we", (not native_ok) and bool(broken), (native_ok, broken))

    code_app = os.path.join(WORK, "Rectangle-code.app")
    shutil.copytree(app, code_app, symlinks=True)
    binary = os.path.join(code_app, main_executable(code_app))
    with open(binary, "r+b") as handle:
        size = os.path.getsize(binary)
        for position in (size // 3, size // 2):
            handle.seek(position)
            byte = handle.read(1)
            handle.seek(position)
            handle.write(bytes([byte[0] ^ 0xFF]))
    native_ok = run("codesign", "--verify", "--strict", binary).returncode == 0
    broken = sorted(rules(analyze(AA, code_app)) & BROKEN)
    check("changed code: codesign rejects it and so do we", (not native_ok) and "apple.code-modified" in broken, (native_ok, broken))

    # 4. Images made here by hdiutil in every compression and both file systems.
    source = make_source()
    expected = folder_digests(source)
    for filesystem in ("HFS+", "APFS"):
        for image_format in ("UDZO", "UDBZ", "ULFO", "ULMO", "UDCO", "UDRO"):
            name = f"made-{filesystem.replace('+', 'plus')}-{image_format}.dmg"
            path = os.path.join(WORK, name)
            made = run("hdiutil", "create", "-srcfolder", source, "-fs", filesystem, "-format", image_format, "-volname", "Compare", path)
            if made.returncode != 0:
                print(f"skip {name}: hdiutil cannot make it here: {made.stderr.strip()[:200]}", flush=True)
                continue
            report = analyze(AA, path)
            compare_files(f"{name} ({filesystem}, {image_format})", expected, children_digests(report, name), VOLUME_NOISE)
            check(f"{name}: nothing reported unreadable", report["coverage"]["content_lost"] == 0, dict(limitation_codes(report)))

    # 5. Files stored compressed inside the file system (decmpfs).
    compressed = os.path.join(WORK, "source-compressed")
    run("ditto", "--hfsCompression", source, compressed)
    for filesystem in ("HFS+", "APFS"):
        name = f"made-compressed-{filesystem.replace('+', 'plus')}.dmg"
        path = os.path.join(WORK, name)
        if run("hdiutil", "create", "-srcfolder", compressed, "-fs", filesystem, "-format", "UDZO", "-volname", "Compare", path).returncode == 0:
            report = analyze(AA, path)
            compare_files(f"{name} (files compressed in the file system)", expected, children_digests(report, name), VOLUME_NOISE)

    # 6. An encrypted image: recognised, and nothing claimed about its content.
    name = "made-encrypted.dmg"
    path = os.path.join(WORK, name)
    made = run("hdiutil", "create", "-srcfolder", source, "-fs", "HFS+", "-format", "UDZO", "-encryption", "AES-256", "-stdinpass", "-volname", "Compare", path, input="correct horse")
    if made.returncode == 0:
        report = analyze(AA, path)
        check("encrypted image: reported as encrypted", "dmg.encrypted" in limitation_codes(report), dict(limitation_codes(report)))
        check("encrypted image: no files claimed", not children_digests(report, name), list(children_digests(report, name))[:5])
    else:
        check("encrypted image could be made", False, made.stderr)

    # 7. Installer packages made here by pkgbuild, in the old and the current payload format.
    for label, extra in (("default", []), ("latest", ["--compression", "latest"])):
        name = f"made-{label}.pkg"
        path = os.path.join(WORK, name)
        made = run("pkgbuild", "--root", source, "--identifier", "test.native.compare", "--version", "1.0", "--install-location", "/opt/compare", *extra, path)
        if made.returncode != 0:
            print(f"skip {name}: {made.stderr.strip()[:200]}", flush=True)
            continue
        magics = payload_magics(path)
        print(f"{name}: payload begins with {magics}", flush=True)
        report = analyze(AA, path)
        ours = {a["path"].split("/Payload/", 1)[1]: a["digests"]["sha256"] for a in report["artifacts"] if "/Payload/" in a["path"] and a["digests"] and a["parent"] and a["parent"].endswith("/Payload")}
        # pkgbuild adds nothing to the payload, but AppleDouble files may accompany extended attributes.
        compare_files(f"{name} payload ({'pbzx' if b'pbzx' in magics else 'gzip'})", expected, ours, ("._",))

    finish()


main()
