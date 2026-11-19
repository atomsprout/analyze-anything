"""Runs the desktop app's self-check and compares its exports with the command line's."""
import argparse
import filecmp
import json
import os
import subprocess
import sys
import tempfile

FAILURES = []
PASSED = [0]


def check(name, held, detail=""):
    print(("ok   " if held else "FAIL ") + name + ("" if held or not detail else "\n       " + str(detail)[:1500]), flush=True)
    if held:
        PASSED[0] += 1
    else:
        FAILURES.append(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", help="the app's executable")
    parser.add_argument("aa", help="the aa command")
    parser.add_argument("inputs", nargs=2, help="two files to analyze, the earlier version first")
    parser.add_argument("--slow", help="a large file, for checking that an analysis can be cancelled")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    work = tempfile.mkdtemp(prefix="aa-desktop-check-")
    out = os.path.join(work, "out")
    plan = {"inputs": [os.path.abspath(p) for p in args.inputs], "slow_input": os.path.abspath(args.slow) if args.slow else None, "out": out}
    plan_path = os.path.join(work, "plan.json")
    with open(plan_path, "w", encoding="utf-8") as handle:
        json.dump(plan, handle)
    environment = dict(os.environ, AA_DESKTOP_SELFTEST=plan_path, AA_DESKTOP_DATA_DIR=os.path.join(work, "data"))
    print(f"running the app's self-check (its window will appear); working in {work}", flush=True)
    try:
        done = subprocess.run([os.path.abspath(args.app)], env=environment, timeout=args.timeout, capture_output=True, text=True)
        check("the app ran its self-check and quit", done.returncode == 0, f"exit {done.returncode}: {done.stderr[-800:]}")
    except subprocess.TimeoutExpired:
        check("the app ran its self-check and quit", False, f"still running after {args.timeout} seconds")

    result_path = os.path.join(out, "result.json")
    if not os.path.exists(result_path):
        check("the app wrote its result", False, result_path)
        return finish()
    with open(result_path, encoding="utf-8") as handle:
        result = json.load(handle)
    for item in result["checks"]:
        check("app: " + item["name"], item["ok"], item["detail"])

    # Nothing of the runs may be left behind: workers are gone and their scratch folders removed.
    scratch = os.path.join(work, "data", "scratch")
    left = os.listdir(scratch) if os.path.isdir(scratch) else []
    check("no scratch files are left after the app quit", not left, left)
    workers = subprocess.run(["pgrep", "-f", os.path.abspath(args.app) + " --worker"], capture_output=True, text=True).stdout.split()
    check("no worker process is left after the app quit", not workers, workers)

    # The exports of the first input against the command line's, byte for byte.
    lang = result.get("notes", {}).get("export_lang", "zh")
    reference = os.path.join(work, "cli")
    made = subprocess.run([os.path.abspath(args.aa), "analyze", plan["inputs"][0], "-o", reference, "--lang", lang, "--format", "json,html,pdf,md,txt,sarif,sbom"], capture_output=True, text=True)
    check("the command line analyzed the same input", os.path.exists(os.path.join(reference, "report.json")), made.stderr[-500:])
    exports = os.path.join(out, "exports")
    stem = os.path.basename(plan["inputs"][0])
    singles = {"json": "report.json", "html": "report.html", "pdf": "report.pdf", "md": "report.md", "txt": "report.txt", "sarif": "report.sarif"}
    for kind, name in singles.items():
        exported = os.path.join(exports, f"{stem}.report.{kind}")
        same = os.path.exists(exported) and filecmp.cmp(exported, os.path.join(reference, name), shallow=False)
        check(f"exported {kind} is byte for byte what `aa` writes", same, exported)
    sbom = os.path.join(exports, f"{stem}.sbom.cdx.json")
    check("exported sbom is byte for byte what `aa` writes", os.path.exists(sbom) and filecmp.cmp(sbom, os.path.join(reference, "sbom.cdx.json"), shallow=False), sbom)
    folder = os.path.join(exports, f"{stem} report")
    names = sorted(os.listdir(reference))
    check("the exported folder holds the same files as `aa` writes", os.path.isdir(folder) and sorted(os.listdir(folder)) == names, folder)
    if os.path.isdir(folder):
        _, different, errors = filecmp.cmpfiles(folder, reference, names, shallow=False)
        check("every file in the exported folder is byte for byte what `aa` writes", not different and not errors, different + errors)
        verified = subprocess.run([os.path.abspath(args.aa), "verify", folder], capture_output=True, text=True)
        check("`aa verify` accepts the exported folder", verified.returncode == 0, verified.stdout[-500:])
    finish()


def finish():
    print(f"\n{PASSED[0]} checks passed, {len(FAILURES)} failed", flush=True)
    for name in FAILURES:
        print("  failed: " + name)
    raise SystemExit(1 if FAILURES else 0)


main()
