"""Development-only Windows reference tool discovery and signature inspection."""
import glob
import json
import os
import re
import shutil
import subprocess


def find_signtool(sdk_root=None):
    """Prefer PATH, then the newest x64 SDK tool; never run an ARM tool on x64."""
    installed = shutil.which("signtool")
    if installed:
        return installed
    if sdk_root is None:
        sdk_root = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Windows Kits", "10", "bin")
    candidates = glob.glob(os.path.join(sdk_root, "*", "x64", "signtool.exe"))
    def version(path):
        folder = os.path.basename(os.path.dirname(os.path.dirname(path)))
        return tuple(int(part) for part in folder.split(".")) if re.fullmatch(r"\d+(?:\.\d+)*", folder) else ()
    return max(candidates, key=lambda path: (version(path), path), default=None)


def native_signature(path):
    """Pass the literal path as data, including quotes and PowerShell metacharacters."""
    environment = dict(os.environ, AA_COMPARE_INPUT=os.path.abspath(path))
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "$s = Get-AuthenticodeSignature -LiteralPath $env:AA_COMPARE_INPUT; "
        "@{ Status = $s.Status.ToString(); Type = $s.SignatureType.ToString(); "
        "Thumbprint = $s.SignerCertificate.Thumbprint; Subject = $s.SignerCertificate.Subject } | ConvertTo-Json -Compress"
    )
    done = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
                          env=environment, capture_output=True, text=True, encoding="utf-8", timeout=120, check=True)
    return json.loads(done.stdout.strip().splitlines()[-1])
