"""Check a licensed APPX's P7X mathematics with CryptoAPI and independent package hashes.

No certificate is installed, no trust provider or revocation lookup is used, and no
package is installed or executed. Uses the pinned Microsoft repository fixture only.
"""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import zipfile
import zlib


def native_verify(p7x, include_subject=False):
    dll = c.WinDLL("crypt32", use_last_error=True, winmode=0x800)
    dll.CryptMsgOpenToDecode.argtypes = [w.DWORD, w.DWORD, w.DWORD, c.c_void_p, c.c_void_p, c.c_void_p]
    dll.CryptMsgOpenToDecode.restype = c.c_void_p
    dll.CryptMsgUpdate.argtypes = [c.c_void_p, c.c_void_p, w.DWORD, w.BOOL]
    dll.CryptMsgUpdate.restype = w.BOOL
    dll.CryptMsgGetParam.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.c_void_p, c.POINTER(w.DWORD)]
    dll.CryptMsgGetParam.restype = w.BOOL
    dll.CryptMsgControl.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.c_void_p]
    dll.CryptMsgControl.restype = w.BOOL
    dll.CryptMsgClose.argtypes = [c.c_void_p]
    dll.CryptMsgClose.restype = w.BOOL
    class Context(c.Structure):
        _fields_ = [("encoding", w.DWORD), ("encoded", c.c_void_p), ("size", w.DWORD), ("info", c.c_void_p), ("store", c.c_void_p)]
    dll.CertCreateCertificateContext.argtypes = [w.DWORD, c.c_void_p, w.DWORD]
    dll.CertCreateCertificateContext.restype = c.POINTER(Context)
    dll.CertFreeCertificateContext.argtypes = [c.POINTER(Context)]
    dll.CertFreeCertificateContext.restype = w.BOOL
    assert p7x[:4] == b"PKCX" and len(p7x) <= 4 * 1024 * 1024
    cms = c.create_string_buffer(p7x[4:])
    handle = dll.CryptMsgOpenToDecode(0x10001, 0, 0, None, None, None)
    if not handle:
        raise c.WinError(c.get_last_error())
    certificate = None
    try:
        if not dll.CryptMsgUpdate(handle, cms, len(p7x) - 4, True):
            return {"decoded": False, "verified": False, "error": hex(c.get_last_error())}
        size = w.DWORD()
        if not dll.CryptMsgGetParam(handle, 12, 0, None, c.byref(size)) or not 0 < size.value <= 65536:
            raise c.WinError(c.get_last_error())
        encoded = c.create_string_buffer(size.value)
        if not dll.CryptMsgGetParam(handle, 12, 0, encoded, c.byref(size)):
            raise c.WinError(c.get_last_error())
        certificate = dll.CertCreateCertificateContext(0x10001, encoded, size.value)
        if not certificate:
            raise c.WinError(c.get_last_error())
        passed = bool(dll.CryptMsgControl(handle, 0, 1, certificate.contents.info))
        result = {"decoded": True, "verified": passed, "error": None if passed else hex(c.get_last_error()), "trust_checked": False}
        if include_subject:
            class Blob(c.Structure):
                _fields_ = [("size", w.DWORD), ("data", c.c_void_p)]
            class Algorithm(c.Structure):
                _fields_ = [("oid", c.c_char_p), ("parameters", Blob)]
            class InfoPrefix(c.Structure):
                _fields_ = [("version", w.DWORD), ("serial", Blob), ("algorithm", Algorithm), ("issuer", Blob),
                            ("not_before", w.FILETIME), ("not_after", w.FILETIME), ("subject", Blob)]
            info = c.cast(certificate.contents.info, c.POINTER(InfoPrefix)).contents
            assert 0 < info.subject.size <= 16384
            result["subject_der"] = c.string_at(info.subject.data, info.subject.size).hex()
        return result
    finally:
        if certificate:
            dll.CertFreeCertificateContext(certificate)
        dll.CryptMsgClose(handle)


def layout(raw):
    archive = zipfile.ZipFile(io.BytesIO(raw))
    entries = {}
    footer = raw.rfind(b"PK\x06\x06")
    assert footer >= 0 and len(raw) < 16 * 1024 * 1024
    pos = archive.start_dir
    while pos < footer:
        assert raw[pos:pos + 4] == b"PK\x01\x02"
        nl, xl, cl = struct.unpack_from("<HHH", raw, pos + 28)
        name = raw[pos + 46:pos + 46 + nl].decode("ascii")
        entries[name] = (pos, 46 + nl + xl + cl)
        pos += 46 + nl + xl + cl
    assert pos == footer
    return archive, entries, footer


def replace_signature(raw, signature):
    archive, entries, footer = layout(raw)
    entry = archive.getinfo("AppxSignature.p7x")
    assert entry.flag_bits == 0 and entry.compress_type == 8
    nl, xl = struct.unpack_from("<HH", raw, entry.header_offset + 26)
    header = bytearray(raw[entry.header_offset:entry.header_offset + 30 + nl + xl])
    encoder = zlib.compressobj(wbits=-15)
    compressed = encoder.compress(signature) + encoder.flush()
    crc = zlib.crc32(signature)
    struct.pack_into("<III", header, 14, crc, len(compressed), len(signature))
    central = bytearray(raw[archive.start_dir:footer])
    at = entries["AppxSignature.p7x"][0] - archive.start_dir
    struct.pack_into("<III", central, at + 16, crc, len(compressed), len(signature))
    directory_start = entry.header_offset + len(header) + len(compressed)
    end = bytearray(raw[footer:])
    struct.pack_into("<Q", end, 48, directory_start)
    struct.pack_into("<Q", end, 64, directory_start + len(central))
    return raw[:entry.header_offset] + header + compressed + central + end


def independent(raw):
    archive, entries, footer = layout(raw)
    signature = archive.read("AppxSignature.p7x")
    sig = archive.getinfo("AppxSignature.p7x")
    start, length = entries["AppxSignature.p7x"]
    assert start + length == footer
    central = raw[archive.start_dir:start]
    end = bytearray(raw[footer:])
    for at, value in [(24, len(entries) - 1), (32, len(entries) - 1), (40, len(central)), (48, sig.header_offset), (64, sig.header_offset + len(central))]:
        struct.pack_into("<Q", end, at, value)
    computed = {"AXPC": hashlib.sha256(raw[:sig.header_offset]).hexdigest(), "AXCD": hashlib.sha256(central + end).hexdigest()}
    for label, name in [("AXCT", "[Content_Types].xml"), ("AXBM", "AppxBlockMap.xml"), ("AXCI", "AppxMetadata/CodeIntegrity.cat")]:
        if name in archive.namelist():
            computed[label] = hashlib.sha256(archive.read(name)).hexdigest()
    at = signature.index(b"APPX")
    size = 4 + len(computed) * 36
    assert size in (148, 184)
    capsule = signature[at:at + size]
    assert len(capsule) == size and capsule[:4] == b"APPX"
    declared = {capsule[p:p + 4].decode("ascii"): capsule[p + 4:p + 36].hex() for p in range(4, size, 36)}
    return signature, [{"label": label, "expected": declared[label], "computed": digest, "matches": declared[label] == digest} for label, digest in computed.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("CryptoAPI comparison requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh output directory below this checkout's out directory")
    source = repository / "crates/aa-windows/tests/data/upstream-TestAppxPackage_Win32.appx"
    original = source.read_bytes()
    signature, _ = independent(original)
    archive, entries, _ = layout(original)
    first = archive.infolist()[0]
    central_only = bytearray(original)
    central_only[entries[first.filename][0] + 12] ^= 1
    local_and_central = bytearray(central_only)
    local_and_central[first.header_offset + 10] ^= 1
    bad_signature = bytearray(signature)
    bad_signature[-1] ^= 1
    bad_capsule = bytearray(signature)
    bad_capsule[signature.index(b"AXBM") + 4] ^= 1
    cases = {"original": original, "central-only": central_only, "local-and-central": local_and_central,
             "bad-signature": replace_signature(original, bad_signature), "bad-capsule": replace_signature(original, bad_capsule)}
    cli, flags = str(args.cli.resolve()), subprocess.CREATE_NO_WINDOW
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=flags)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True)
    results = []
    for case, raw in cases.items():
        package = output / (case + ".appx")
        package.write_bytes(raw)
        p7x, comparisons = independent(raw)
        native = native_verify(p7x)
        assert native["verified"] == (case not in ("bad-signature", "bad-capsule")), (case, native)
        destination = output / (case + "-report")
        for repeat in range(2):
            done = subprocess.run([cli, str(package), "-o", str(destination), "--format", "json,md,html", *no_ai], capture_output=True, timeout=120, creationflags=flags)
            assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
            data = (destination / "report.json").read_bytes()
            if repeat == 0:
                previous = data
            else:
                assert previous == data
        report = json.loads(data)
        binding = next(a["facts"]["windows.msix-signature-binding"] for a in report["artifacts"] if "windows.msix-signature-binding" in a["facts"])
        assert binding["cms_signature_verified"] == native["verified"]
        assert binding["matching_digests"] == sum(r["matches"] for r in comparisons)
        assert binding["unresolved_digests"] == 0
        for expected, checked in zip(comparisons, binding["checks"]):
            assert expected["label"] == checked["label"] and expected["expected"] == checked["expected"] and expected["computed"] == checked["computed"]
        assert binding["publisher_checked"] == native["verified"]
        if native["verified"]:
            assert binding["publisher_matches"] and binding["publisher_manifest_signed_coverage"]
        assert not binding["windows_trust_checked"]
        assert package.read_bytes() == raw
        assert "Declared MSIX package digests match original bytes" in (destination / "report.md").read_text(encoding="utf-8")
        assert "windows.msix-signature-binding" in (destination / "report.html").read_text(encoding="utf-8")
        results.append({"case": case, "native_cms": native, "comparisons": comparisons, "input_unchanged": True, "repeated_json_identical": True})
    standalone = output / "standalone.p7x"
    standalone.write_bytes(signature)
    done = subprocess.run([cli, str(standalone), "-o", str(output / "standalone-report"), "--format", "json,md", "--lang", "zh", *no_ai], capture_output=True, timeout=120, creationflags=flags)
    assert done.returncode in (0, 2)
    assert "MSIX CMS 签名数学检查通过" in (output / "standalone-report/report.md").read_text(encoding="utf-8")
    assert standalone.read_bytes() == signature and source.read_bytes() == original
    (output / "checks.json").write_text(json.dumps({"sample_sha256": hashlib.sha256(original).hexdigest(), "cases": results, "trust_checked": False}, indent=2) + "\n", encoding="utf-8")
    print("compared five package cases with CryptoAPI and independent region/footprint hashes, plus standalone P7X")


if __name__ == "__main__":
    main()
