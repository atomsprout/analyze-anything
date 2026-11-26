#!/usr/bin/env python3
"""Reproduce the five real-input report review; inputs are only read, never installed.

Published sample URLs/licences and manual reading answers are in
docs/spikes/report-workflow.md. Download samples separately; this check has no network.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "installer": ("98330e7e6db3507b444d576dc437a9ac4d82333a88a6bb6ef36a91fe3d85fa92", ["overview.product", "windows.installer-files", "windows.msi-unsigned"]),
    "installed": (None, ["overview.kind-folder", "binary.pe-identity", "windows.manifest-elevation"]),
    "mobile": ("74b22a209340c5dc6e94975d8c07e4814ae2299dfe0b62cfa22640090d80f36c", ["overview.identifier", "apple.usage-description", "apple.signature"]),
    "linux": ("41b6b84a05e30d35b2ac224c5f4600b2a4e976d19f7d0bfdf0565dd729962d84", ["deb.identity", "deb.dependencies", "composition.components"]),
    "bundle": ("a2daa6a33a9c2b791ae31d9092e7935c339d1e03e89bfb747618ce2f4e819e20", ["overview.product", "dotnet-bundle.contents", "windows.dotnet-assemblies"]),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def inventory(path):
    if path.is_file():
        return {path.name: sha(path)}
    return {p.relative_to(path).as_posix(): sha(p) for p in sorted(path.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=Path)
    for name in ("installer", "installed", "mobile", "bundle"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    program = args.program.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    def run(arguments):
        result = subprocess.run([str(program), *map(str, arguments)], capture_output=True,
                                encoding="utf-8", timeout=180)
        require(result.returncode in (0, 2), f"{arguments}: {result.stderr}")
        return result.stdout

    offline = ["--no-ai"] if "--no-ai" in run(["analyze", "--help"]) else []
    records = []
    for name, (digest, expected_rules) in EXPECTED.items():
        supplied = (ROOT / "crates/aa-linux/tests/data/node-isarray_2.0.5-1_all.deb" if name == "linux" else getattr(args, name)).resolve(strict=True)
        require(not output.is_relative_to(supplied), "output must be outside the supplied tree")
        before = inventory(supplied)
        if digest:
            require(sha(supplied) == digest, f"{name}: unexpected published sample hash")
        folder = output / name
        run([supplied, "-o", folder, "--format", "json,md,html", *offline])
        path = folder / "report.json"
        report_bytes = path.read_bytes()
        report = json.loads(report_bytes)
        run([supplied, "-o", output / f"{name}-repeat", "--format", "json", *offline])
        require((output / f"{name}-repeat/report.json").read_bytes() == report_bytes, f"{name}: nondeterministic report")
        run(["render", path, "-o", output / f"{name}-zh", "--format", "md,html", "--lang", "zh"])
        artifacts = {a["path"]: a for a in report["artifacts"]}
        require(report["coverage"]["artifacts_analyzed"] == report["coverage"]["artifacts_total"], f"{name}: unread input")
        require(not report["coverage"]["truncated"] and report["coverage"]["content_lost"] == 0, f"{name}: lost content")
        for finding in report["findings"]:
            require(finding["evidence"] and finding["confidence"] in ("verified", "derived", "heuristic"), f"{name}: evidence/confidence missing")
            require(all(e["artifact"] in artifacts for e in finding["evidence"]), f"{name}: dangling evidence")
            for evidence in finding["evidence"]:
                artifact = artifacts[evidence["artifact"]]
                require(evidence["sha256"] == artifact["digests"]["sha256"], f"{name}: evidence digest mismatch")
                location = evidence["location"]
                if isinstance(location, dict) and "bytes" in location:
                    span = location["bytes"]
                    require(0 <= span["offset"] <= span["offset"] + span["length"] <= artifact["size"], f"{name}: evidence outside file")
        selected = []
        for rule in expected_rules:
            finding = next((f for f in report["findings"] if f["rule"] == rule), None)
            require(finding is not None, f"{name}: missing {rule}")
            explanation = run(["explain", path, finding["id"]])
            require(finding["id"] in explanation, f"{name}: explain navigation failed")
            selected.append(finding)
        coverage = json.loads(run(["query", path, "coverage"]))
        require(coverage["selected_artifacts"] == len(artifacts), f"{name}: query coverage disagreement")
        require(path.read_bytes() == report_bytes and inventory(supplied) == before, f"{name}: input/report changed")
        if name == "installed":
            require({p: a["digests"]["sha256"] for p, a in artifacts.items()} == before, "installed directory inventory mismatch")
        reference = {}
        if name == "mobile":
            with zipfile.ZipFile(supplied) as archive:
                expected = {i.filename: hashlib.sha256(archive.read(i)).hexdigest() for i in archive.infolist() if not i.is_dir()}
                actual = {p.removeprefix(supplied.name + "/"): a["digests"]["sha256"] for p, a in artifacts.items() if a["parent"] == supplied.name}
                require(actual == expected, "IPA direct-member digests disagree with zipfile")
                identity = plistlib.loads(archive.read("Payload/iSH.app/Info.plist"))
                identifier = next(f for f in report["findings"] if f["rule"] == "overview.identifier")
                require(identity["CFBundleIdentifier"] in identifier["params"].values(), "IPA identity disagreement")
                reference = {"reader": "Python stdlib zipfile/plistlib", "direct_members": len(expected), "identifier": identity["CFBundleIdentifier"], "native_codesign": "not run on Windows"}
        if name == "linux":
            native = json.loads((ROOT / "docs/spikes/linux-packages-native.json").read_text(encoding="utf-8"))
            sample = next(row for row in native["records"] if row["sample"] == supplied.name)
            require(sample["sha256"] == digest, "Linux reference belongs to different bytes")
            members = 0
            for archive in sample["native"]["archives"]:
                for entry in archive["entries"]:
                    if "sha256" not in entry:
                        continue
                    prefix = f"{supplied.name}/{archive['member']}/{archive['member'].removesuffix('.xz')}/"
                    path = prefix + entry["path"].removeprefix("./")
                    require(artifacts[path]["digests"]["sha256"] == entry["sha256"], f"Linux native member mismatch: {path}")
                    members += 1
            reference = {"record": "docs/spikes/linux-packages-native.json", "native_member_digests": members}
        if name == "installer":
            require(report["artifacts"][0]["facts"]["windows.installer"]["files"] == 106, "MSI declared file count")
            require(any(g["code"] == "windows.installer-semantics-unresolved" for g in report["limitations"]), "installer semantics silently omitted")
        if name == "bundle":
            require(any(g["code"] == "windows.dotnet-code-unread" for g in report["limitations"]), "IL blind spot silently omitted")
        records.append({"scenario": name, "input": supplied.name, "input_sha256": digest,
                        "source_files": before, "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                        "coverage": report["coverage"], "finding_count": len(report["findings"]),
                        "selected_findings": selected, "limitations": report["limitations"], "independent_reference": reference})
        print(f"PASS {name}: {len(artifacts)} artifacts, {len(report['findings'])} findings", flush=True)
    record = {"program_sha256": sha(program), "program_version": run(["--version"]).strip(),
              "checks": ["pinned-inputs", "repeat-report", "bilingual-html-markdown", "evidence-confidence", "explain", "offline-query", "input-report-preservation", "directory-digests", "semantic-gaps"], "scenarios": records}
    (output / "review.json").write_text(json.dumps(record, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
