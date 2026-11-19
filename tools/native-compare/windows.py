"""Compares the analyzer with Windows's own Authenticode check and cabinet maker."""
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

from common import analyze, check, finish, limitation_codes

AA = os.path.abspath(sys.argv[1])
WORK = tempfile.mkdtemp(prefix="aa-native-")
CHECKS = ("content_digest", "file_digest", "signature", "chain")


def native_signature(path):
    """What Get-AuthenticodeSignature reports for `path`."""
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
        "@{ Status = $s.Status.ToString(); Type = $s.SignatureType.ToString(); "
        "Thumbprint = $s.SignerCertificate.Thumbprint; Subject = $s.SignerCertificate.Subject } | ConvertTo-Json -Compress"
    )
    done = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True)
    return json.loads(done.stdout.strip().splitlines()[-1])


def our_signature(path):
    report = analyze(AA, path)
    root = next(a for a in report["artifacts"] if a["parent"] is None)
    return root["facts"].get("windows.authenticode"), report


def compare(path):
    name = os.path.basename(path)
    native = native_signature(path)
    fact, _report = our_signature(path)
    if fact is None:
        check(f"{name}: recognised as a Windows program", False)
        return None
    signatures = fact.get("signatures") or []
    if native["Type"] == "None":
        check(f"{name}: no signature of either kind, and none found in the file", not signatures, len(signatures))
        return native
    if native["Type"] == "Catalog":
        # Windows names the catalog first even when the file also carries its own signature
        # (system files often have both), so an embedded one is not a disagreement. If there
        # is one, Windows vouching for the file means ours must verify too.
        if signatures and native["Status"] == "Valid":
            passed = all(signatures[0]["checks"].get(key) == "passed" for key in CHECKS)
            check(f"{name}: catalog-signed and also signed inside; the embedded signature verifies", passed, signatures[0]["checks"])
        else:
            check(f"{name}: catalog-signed, nothing embedded", not signatures, len(signatures))
        return native
    check(f"{name}: embedded signature found", bool(signatures))
    if not signatures:
        return native
    ours = signatures[0]
    check(f"{name}: signer certificate {native['Thumbprint']}", (ours["signer"].get("sha1") or "").upper() == native["Thumbprint"], ours["signer"].get("sha1"))
    passed = all(ours["checks"].get(key) == "passed" for key in CHECKS)
    if native["Status"] == "Valid":
        check(f"{name}: Windows says Valid; our checks all pass", passed, ours["checks"])
    elif native["Status"] == "HashMismatch":
        check(f"{name}: Windows says HashMismatch; our file digest check fails", ours["checks"].get("file_digest") != "passed", ours["checks"])
    else:
        print(f"note {name}: Windows status {native['Status']} is about trust, which this program does not judge", flush=True)
    return native


def candidates():
    patterns = [
        r"C:\Program Files\PowerShell\7\*.exe",
        r"C:\Program Files\PowerShell\7\System.*.dll",
        r"C:\Program Files\PowerShell\7\Microsoft.*.dll",
        r"C:\Program Files\dotnet\dotnet.exe",
        r"C:\Program Files\Git\cmd\*.exe",
        r"C:\Program Files\Git\bin\*.exe",
        r"C:\Program Files\nodejs\node.exe",
        r"C:\Program Files\7-Zip\*.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\drivers\ntfs.sys",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\explorer.exe",
    ]
    found = []
    for pattern in patterns:
        found.extend(sorted(glob.glob(pattern))[:12])
    return found


def main():
    embedded = None
    for path in candidates():
        native = compare(path)
        if native and native["Type"] == "Authenticode" and native["Status"] == "Valid" and embedded is None:
            embedded = path
    check("at least one file with a valid embedded signature was compared", embedded is not None)

    # The same file with one byte changed: both must report the mismatch.
    if embedded:
        tampered = os.path.join(WORK, "tampered-" + os.path.basename(embedded))
        shutil.copyfile(embedded, tampered)
        with open(tampered, "r+b") as handle:
            handle.seek(0x600)
            byte = handle.read(1)
            handle.seek(0x600)
            handle.write(bytes([byte[0] ^ 0xFF]))
        native = native_signature(tampered)
        fact, _report = our_signature(tampered)
        ours = (fact.get("signatures") or [{}])[0].get("checks", {})
        check("changed byte: Windows reports HashMismatch", native["Status"] == "HashMismatch", native)
        check("changed byte: our file digest check fails", ours.get("file_digest") not in (None, "passed"), ours)

    # Cabinets made here by makecab, in both compression methods it offers.
    content = os.path.join(WORK, "content.txt")
    with open(content, "w") as handle:
        for index in range(60000):
            handle.write(f"line {index} of the cabinet test file, {index * 7919 % 1000}\n")
    with open(content, "rb") as handle:
        expected = hashlib.sha256(handle.read()).hexdigest()
    for label, options in (("MSZIP", []), ("LZX", ["/D", "CompressionType=LZX", "/D", "CompressionMemory=21"])):
        cabinet = os.path.join(WORK, f"made-{label}.cab")
        made = subprocess.run(["makecab", *options, content, cabinet], capture_output=True, text=True)
        if not os.path.exists(cabinet):
            check(f"makecab made a {label} cabinet", False, made.stdout[-300:])
            continue
        report = analyze(AA, cabinet)
        ours = [a["digests"]["sha256"] for a in report["artifacts"] if a["parent"] and a["digests"]]
        check(f"{label} cabinet: the file inside is byte-identical", ours == [expected], (ours, dict(limitation_codes(report))))

    finish()


main()
