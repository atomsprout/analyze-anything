"""Shared helpers: run the analyzer, hash files, record checks."""
import collections
import hashlib
import json
import os
import subprocess
import tempfile

FAILURES = []
PASSED = [0]


def check(name, held, detail=""):
    """Records one comparison and prints it."""
    print(("ok   " if held else "FAIL ") + name + ("" if held or not detail else "\n       " + str(detail)[:1500]), flush=True)
    if held:
        PASSED[0] += 1
    else:
        FAILURES.append(name)


def finish():
    print(f"\n{PASSED[0]} checks passed, {len(FAILURES)} failed", flush=True)
    for name in FAILURES:
        print("  failed: " + name)
    raise SystemExit(1 if FAILURES else 0)


def analyze(aa, path, extra=()):
    """Runs the analyzer on `path` and returns the report."""
    out = tempfile.mkdtemp(prefix="aa-out-")
    done = subprocess.run([aa, "analyze", path, "-o", out, "--format", "json", *extra], capture_output=True, text=True)
    report = os.path.join(out, "report.json")
    if not os.path.exists(report):
        raise RuntimeError(f"no report for {path}: exit {done.returncode}: {done.stderr[-800:]}")
    with open(report, encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def folder_digests(root):
    """SHA-256 of every regular file under `root` (links not followed), by relative path."""
    found = {}
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            found[os.path.relpath(path, root).replace(os.sep, "/")] = sha256_file(path)
    return found


def children_digests(report, container):
    """SHA-256 of the artifacts unpacked directly from `container`, by path inside it."""
    prefix = container + "/"
    return {
        a["path"][len(prefix):]: a["digests"]["sha256"]
        for a in report["artifacts"]
        if a["parent"] == container and a["digests"] and a["path"].startswith(prefix)
    }


def compare_files(name, expected, ours, ignorable=()):
    """Every expected file must be present with the same digest; extras must be ignorable."""
    missing = sorted(p for p in expected if p not in ours)
    different = sorted(p for p in expected if p in ours and ours[p] != expected[p])
    extra = sorted(p for p in ours if p not in expected and not any(p.startswith(i) or ("/" + i) in ("/" + p) for i in ignorable))
    detail = {"missing": missing[:10], "different": different[:10], "unexpected": extra[:10]}
    check(f"{name}: {len(expected)} files identical", not missing and not different and not extra, detail)


def limitation_codes(report):
    return collections.Counter(item["code"] for item in report["limitations"])


def rules(report):
    return {finding["rule"] for finding in report["findings"]}
