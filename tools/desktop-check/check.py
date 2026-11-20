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
    parser.add_argument("aa", help="the analyze-anything command")
    parser.add_argument("inputs", nargs=2, help="two files to analyze, the earlier version first")
    parser.add_argument("--slow", help="a large file, for checking that an analysis can be cancelled")
    parser.add_argument("--ai-config", help="settings for the AI interpretation to use instead of the stand-in: this really asks the model they name")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    work = tempfile.mkdtemp(prefix="aa-desktop-check-")
    out = os.path.join(work, "out")
    plan = {"inputs": [os.path.abspath(p) for p in args.inputs], "slow_input": os.path.abspath(args.slow) if args.slow else None, "out": out}
    plan_path = os.path.join(work, "plan.json")
    with open(plan_path, "w", encoding="utf-8") as handle:
        json.dump(plan, handle)
    # The AI interpretation is checked with a stand-in for the model: a program on this machine
    # that answers with one statement citing the first finding it was shown. Nothing leaves the
    # machine, and the user's own settings are not read.
    agent = os.path.join(work, "agent.py")
    with open(agent, "w", encoding="utf-8") as handle:
        handle.write(
            "import json, re, sys\n"
            "found = re.search(r'\"id\"\\s*:\\s*\"([0-9a-f]{8,64})\"', sys.stdin.read())\n"
            "cites = [found.group(1)] if found else []\n"
            "print(json.dumps({'summary': [{'text': 'A stand-in said this.', 'cites': cites}], 'notable': [], 'next_steps': []}))\n"
        )
    config = os.path.join(work, "config.toml")
    with open(config, "w", encoding="utf-8") as handle:
        handle.write("[ai]\nengine = \"command\"\ncommand = " + json.dumps([sys.executable, agent]) + "\n")
    stand_in = args.ai_config is None
    if not stand_in:
        config = os.path.abspath(args.ai_config)
    environment = dict(os.environ, AA_DESKTOP_SELFTEST=plan_path, AA_DESKTOP_DATA_DIR=os.path.join(work, "data"), AA_CONFIG=config)
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
        check(f"exported {kind} is byte for byte what `analyze-anything` writes", same, exported)
    sbom = os.path.join(exports, f"{stem}.sbom.cdx.json")
    check("exported sbom is byte for byte what `analyze-anything` writes", os.path.exists(sbom) and filecmp.cmp(sbom, os.path.join(reference, "sbom.cdx.json"), shallow=False), sbom)
    folder = os.path.join(exports, f"{stem} report")
    names = sorted(os.listdir(reference))
    check("the exported folder holds the same files as `analyze-anything` writes", os.path.isdir(folder) and sorted(os.listdir(folder)) == names, folder)
    if os.path.isdir(folder):
        _, different, errors = filecmp.cmpfiles(folder, reference, names, shallow=False)
        check("every file in the exported folder is byte for byte what `analyze-anything` writes", not different and not errors, different + errors)
        verified = subprocess.run([os.path.abspath(args.aa), "verify", folder], capture_output=True, text=True)
        check("`analyze-anything verify` accepts the exported folder", verified.returncode == 0, verified.stdout[-500:])

    # The folder exported after the interpretation was made holds it, and is still accepted.
    with_ai = os.path.join(exports, f"{stem} report 2")
    if result.get("notes", {}).get("ai"):
        have = sorted(os.listdir(with_ai)) if os.path.isdir(with_ai) else []
        check("the folder exported after an AI interpretation holds ai.json and ai.md besides the rest", have == sorted(names + ["ai.json", "ai.md"]), have)
        if have:
            _, different, errors = filecmp.cmpfiles(with_ai, reference, [n for n in names if n != "manifest.json"], shallow=False)
            check("the report files in that folder are still byte for byte what `analyze-anything` writes", not different and not errors, different + errors)
            with open(os.path.join(with_ai, "ai.json"), encoding="utf-8") as handle:
                made = json.load(handle)
            check("ai.json is marked as AI-generated and names the engine", made.get("ai_generated") is True and (made.get("engine") == "command" or not stand_in), {k: made.get(k) for k in ("ai_generated", "engine", "model")})
            verified = subprocess.run([os.path.abspath(args.aa), "verify", with_ai], capture_output=True, text=True)
            check("`analyze-anything verify` accepts the folder with the interpretation", verified.returncode == 0, verified.stdout[-500:])
    left = os.listdir(os.path.join(work, "data", "ai", "work")) if os.path.isdir(os.path.join(work, "data", "ai", "work")) else []
    check("no copy of a report is left where the AI interpretation worked", not left, left)
    ai_folder = os.path.join(work, "data", "ai")
    kept = [name for name in os.listdir(ai_folder) if name.endswith(".json")] if os.path.isdir(ai_folder) else []
    check("the interpretations went with the reports that were deleted", not kept, kept)
    finish()


def finish():
    print(f"\n{PASSED[0]} checks passed, {len(FAILURES)} failed", flush=True)
    for name in FAILURES:
        print("  failed: " + name)
    raise SystemExit(1 if FAILURES else 0)


main()
