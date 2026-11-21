"""Read a controlled catalog with Windows CryptCAT APIs; never add it to a catalog store."""

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid


class Blob(c.Structure):
    _fields_ = [("size", w.DWORD), ("data", c.POINTER(c.c_ubyte))]


class Guid(c.Structure):
    _fields_ = [("data", c.c_ubyte * 16)]


class Algorithm(c.Structure):
    _fields_ = [("oid", c.c_char_p), ("parameters", Blob)]


class AttributeValue(c.Structure):
    _fields_ = [("oid", c.c_char_p), ("value", Blob)]


class Indirect(c.Structure):
    _fields_ = [("data", AttributeValue), ("algorithm", Algorithm), ("digest", Blob)]


class Member(c.Structure):
    _fields_ = [("size", w.DWORD), ("tag", w.LPWSTR), ("filename", w.LPWSTR),
                ("subject", Guid), ("flags", w.DWORD), ("indirect", c.POINTER(Indirect)),
                ("cert_version", w.DWORD), ("reserved", w.DWORD), ("reserved_handle", w.HANDLE),
                ("encoded_indirect", Blob), ("encoded_member", Blob)]


def native_catalog(path, version):
    api = c.WinDLL("wintrust", use_last_error=True, winmode=0x800)
    api.CryptCATOpen.argtypes = [w.LPWSTR, w.DWORD, c.c_void_p, w.DWORD, w.DWORD]
    api.CryptCATOpen.restype = w.HANDLE
    api.CryptCATClose.argtypes = [w.HANDLE]
    api.CryptCATClose.restype = w.BOOL
    api.CryptCATEnumerateMember.argtypes = [w.HANDLE, c.POINTER(Member)]
    api.CryptCATEnumerateMember.restype = c.POINTER(Member)
    handle = api.CryptCATOpen(str(path.resolve()), 0, None, version * 0x100, 0)
    if handle == c.c_void_p(-1).value or not handle:
        raise c.WinError(c.get_last_error())
    records = []
    try:
        previous = None
        for _ in range(16384):
            previous = api.CryptCATEnumerateMember(handle, previous)
            if not previous:
                break
            member = previous.contents
            record = {"reference_tag": member.tag, "sip_guid": "{" + str(uuid.UUID(bytes_le=bytes(member.subject.data))).upper() + "}"}
            if member.indirect:
                indirect = member.indirect.contents
                if indirect.digest.size > 64:
                    raise ValueError("native catalog digest exceeded the reference budget")
                record.update(data_oid=indirect.data.oid.decode("ascii"),
                              digest_algorithm=indirect.algorithm.oid.decode("ascii"),
                              digest=c.string_at(indirect.digest.data, indirect.digest.size).hex())
            records.append(record)
        else:
            raise ValueError("native catalog member count exceeded the reference budget")
    finally:
        api.CryptCATClose(handle)
    return records


def native_signature(path):
    result = subprocess.run(["pwsh", "-NoProfile", "-File",
                             str(Path(__file__).with_name("windows-catalog-signature.ps1")),
                             "-CatalogFile", str(path.resolve())], capture_output=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return json.loads(result.stdout)


def run(command):
    result = subprocess.run(command, capture_output=True, timeout=120,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def compare_cli(cli, sample, output, native, before, version):
    cli = str(cli.resolve())
    no_ai = ["--no-ai"] if b"--no-ai" in run([cli, "analyze", "--help"]) else []
    output.mkdir(parents=True, exist_ok=True)
    cases = [("original", before)]
    if native_signature(sample)["signatures"]:
        damaged = bytearray(before)
        # The controlled MakeCat/SignTool fixture has one signer and no unsigned attributes.
        # Its final octet belongs to the signature value, as also checked by the Rust tests.
        damaged[-1] ^= 1
        cases.append(("changed-signature", bytes(damaged)))
        declaration = next(m for m in native if len(m.get("digest", "")) == (64 if version == 2 else 40))
        digest = bytes.fromhex(declaration["digest"])
        offset = before.rfind(digest)
        if offset < 0:
            raise ValueError("controlled fixture digest was not present")
        damaged = bytearray(before)
        damaged[offset] ^= 1
        cases.append(("changed-content", bytes(damaged)))
    results = []
    for name, content in cases:
        path = output / (name + ".cat")
        path.write_bytes(content)
        destination = output / (name + "-report")
        command = [cli, str(path.resolve()), "-o", str(destination.resolve()),
                   "--format", "json,md,html", *no_ai]
        run(command)
        raw = (destination / "report.json").read_bytes()
        report = json.loads(raw)
        fact = next(a["facts"]["windows.catalog"] for a in report["artifacts"] if "windows.catalog" in a["facts"])
        assert not fact["payloads_checked"] and not fact["windows_trust_checked"]
        if name == "original":
            assert len(fact["entries"]) == len(native)
            for entry in fact["entries"]:
                tag = entry["reference_tag"] or entry["subject_identifier"]
                expected = next(m for m in native if m["reference_tag"].lower() == tag.lower())
                assert entry["sip_guid"] == expected["sip_guid"]
                if entry["digest"] is not None:
                    for key in ("digest", "digest_algorithm", "data_oid"):
                        assert entry[key] == expected[key]
        if fact["signatures"]:
            checks = fact["signatures"][0]["checks"]
            assert checks["signature"] == ("failed" if name == "changed-signature" else "passed")
            assert checks["content_digest"] == ("failed" if name == "changed-content" else "passed")
            combined = native_signature(path)["signatures"][0]["combined_content_and_signature"]
            assert combined == ("passed" if name == "original" else "failed")
            assert any(f["rule"] == "windows.catalog-integrity-failed" for f in report["findings"]) == (name != "original")
        run(command)
        assert raw == (destination / "report.json").read_bytes()
        assert "Windows catalog declarations" in (destination / "report.md").read_text(encoding="utf-8")
        assert "windows.catalog" in (destination / "report.html").read_text(encoding="utf-8")
        assert path.read_bytes() == content
        results.append({"case": name, "repeated_json_identical": True})
    chinese = output / "zh-report"
    run([cli, str(sample.resolve()), "-o", str(chinese.resolve()), "--format", "md", "--lang", "zh", *no_ai])
    assert "Windows 目录声明与签名检查" in (chinese / "report.md").read_text(encoding="utf-8")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--version", required=True, type=int, choices=(1, 2))
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("the native catalog reference requires Windows")
    if bool(args.cli) != bool(args.output):
        parser.error("--cli and --output must be supplied together")
    before = args.sample.read_bytes()
    members = native_catalog(args.sample, args.version)
    assert args.sample.read_bytes() == before, "catalog input changed"
    record = {"sample": args.sample.name, "sha256": hashlib.sha256(before).hexdigest(),
              "reference": "CryptCATOpen/CryptCATEnumerateMember", "public_version": args.version,
              "members": members, "cms_signature_only": native_signature(args.sample)}
    if args.cli:
        record["cli_cases"] = compare_cli(args.cli, args.sample, args.output, members, before, args.version)
    assert args.sample.read_bytes() == before, "original catalog changed"
    args.reference.parent.mkdir(parents=True, exist_ok=True)
    args.reference.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"read {len(members)} native catalog records")


if __name__ == "__main__":
    main()
