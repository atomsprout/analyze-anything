"""Create controlled PE layout variants and record the Windows catalog SIP hash oracle."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def variants(fixtures):
    base = (fixtures / "hello.exe").read_bytes()
    signed = (fixtures / "hello-signed.exe").read_bytes()
    pe = struct.unpack_from("<I", base, 60)[0]
    optional = pe + 24
    table = optional + struct.unpack_from("<H", base, pe + 20)[0]
    count = struct.unpack_from("<H", base, pe + 6)[0]
    yield "plain", "hello.exe", "copy", base
    yield "signed", "hello-signed.exe", "copy", signed
    for size in (1, 2, 7, 8, 9):
        yield f"append-{size}", "hello.exe", f"append:{size}", base + b"Z" * size
    for size in (1, 8):
        yield f"signed-append-{size}", "hello-signed.exe", f"append:{size}", signed + b"Z" * size
    headers = struct.unpack_from("<I", base, optional + 60)[0]
    gap = bytearray(base[:headers] + bytes(512) + base[headers:])
    for section in range(count):
        at = table + 40 * section + 20
        offset = struct.unpack_from("<I", gap, at)[0]
        if offset:
            struct.pack_into("<I", gap, at, offset + 512)
    yield "section-gap", "hello.exe", "section-gap:512", bytes(gap)
    changes = [("section-overlap", table + 60, struct.unpack_from("<I", base, table + 20)[0]),
               ("section-outside", table + 20, len(base) + 512),
               ("header-outside", optional + 60, len(base) + 512),
               ("no-directories", optional + 108, 0),
               ("zero-cert-offset", optional + 112 + 36, 16)]
    for name, offset, value in changes:
        data = bytearray(base)
        struct.pack_into("<I", data, offset, value)
        yield name, "hello.exe", f"u32:{offset}:{value}", bytes(data)
    yield "truncated", "hello.exe", "truncate:1024", base[:1024]
    yield "pe32", "dotnet.exe", "copy", (fixtures / "dotnet.exe").read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    fixtures = repository / "crates/aa-windows/tests/data"
    destination = args.output.resolve()
    if not destination.is_relative_to(repository / "out"):
        parser.error("generated variants must remain below this checkout's out directory")
    destination.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("sip_reference", Path(__file__).with_name("windows-sip-hash.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records = []
    for name, base, operation, content in variants(fixtures):
        path = destination / (name + ".exe")
        path.write_bytes(content)
        record = {"case": name, "base": base, "operation": operation,
                  "size": len(content), "input_sha256": hashlib.sha256(content).hexdigest()}
        for algorithm in ("SHA1", "SHA256"):
            try:
                record[algorithm.lower()] = module.sip_hash(path, algorithm)
            except OSError as error:
                record[algorithm.lower()] = {"native_error": error.winerror & 0xFFFFFFFF}
        assert path.read_bytes() == content
        records.append(record)
    args.reference.parent.mkdir(parents=True, exist_ok=True)
    args.reference.write_text(json.dumps({"reference": "CryptCATAdminCalcHashFromFileHandle2", "cases": records}, indent=2) + "\n", encoding="utf-8")
    print(f"recorded {len(records)} native SIP cases")


if __name__ == "__main__":
    main()
