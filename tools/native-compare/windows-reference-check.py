"""Checks supplied-file relationships through the CLI, without activating any shortcut."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=120)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cli = str(args.cli.resolve())
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).resolve().parents[2] / "crates/aa-windows/tests/data/upstream-test.lnk"
    help_text = run([cli, "analyze", "--help"])
    # Default-feature builds can auto-interpret; explicitly suppress that optional network step.
    no_ai = ["--no-ai"] if b"--no-ai" in help_text else []
    inputs = [destination / "old.zip", destination / "new.zip"]
    for path in inputs:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in [("launch.lnk", fixture.read_bytes()), ("a.txt", b"supplied text")]:
                archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), content)
    reports = []
    for index, path in enumerate(inputs):
        output = destination / f"report-{index}"
        command = [cli, str(path), "-o", str(output), "--format", "json,md,html", *no_ai]
        run(command)
        raw = (output / "report.json").read_bytes()
        report = json.loads(raw)
        assert len(report["artifacts"]) == 3
        assert not report["coverage"]["truncated"]
        source = next(a for a in report["artifacts"] if a["path"].endswith("/launch.lnk"))
        reference = next(r for r in source["facts"]["windows.input-references"]["references"] if r["field"] == "RelativePath")
        assert reference["target"] == f"{path.name}/a.txt"
        assert reference["target_sha256"] == hashlib.sha256(b"supplied text").hexdigest()
        assert not source["facts"]["windows.shell-link"]["target_resolved"]
        assert any(f["rule"] == "windows.input-reference" for f in report["findings"])
        assert "1 declaration is linked" in (output / "report.md").read_text(encoding="utf-8")
        assert "windows.input-reference" in (output / "report.html").read_text(encoding="utf-8")
        run(command)
        assert raw == (output / "report.json").read_bytes(), "same input must produce identical reports"
        reports.append(output / "report.json")
    difference = json.loads(run([cli, "diff", str(reports[0]), str(reports[1]), "--json"]))
    for key in ("added", "removed", "changed"):
        assert not difference["findings"][key], f"renamed input changed findings: {key}"
        assert not difference["files"][key], f"renamed input changed files: {key}"
    chinese = destination / "report-zh"
    run([cli, str(inputs[0]), "-o", str(chinese), "--format", "md", "--lang", "zh", *no_ai])
    assert "声明关联到输入中的文件" in (chinese / "report.md").read_text(encoding="utf-8")
    record = {"checks": ["supplied target and digest", "no extra artifacts", "runtime target remains unresolved", "repeated JSON identical", "renamed-input diff unchanged", "English and Chinese Markdown", "HTML includes finding"], "input_sha256": hashlib.sha256(inputs[0].read_bytes()).hexdigest()}
    (destination / "checks.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"passed {len(record['checks'])} CLI relationship checks")


if __name__ == "__main__":
    main()
