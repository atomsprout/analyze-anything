"""Qualify one pinned upstream driver snapshot without installing or loading it.

Supply Drivers/x64 from dorssel/usbipd-win commit
aa3db8b82c4cb5071fd31bc54211606c70886912 (v5.3.0). This development reference
never downloads samples, modifies the originals or adds catalogs/certificates to stores.
The sample's GPL-3.0-only binaries remain external to this repository.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from windows_tools import find_signtool


EXPECTED = {
    "VBoxUSB.cat": "021addb8c696fb291a93b3e398cf1f7d3f9d9a4e7cf669360d3d7e1f00c08299",
    "VBoxUSB.inf": "841ad3678046b54b1e980c41744da9f64ca7d6e090cad62a661734deadf26189",
    "VBoxUSB.sys": "06cee818949d6dce18e6ec291b8ac521a5f0c168c792be8eacd7a8ae99d8fdf9",
}


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def analyze(cli, source, destination, inf, root, no_ai):
    command = [str(cli), str(source), "-o", str(destination), "--format", "json,md",
               "--windows-source-root", inf, root, *no_ai]
    result = subprocess.run(command, capture_output=True, timeout=120,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return (destination / "report.json").read_bytes()


def policy_check(signtool, catalog, payload):
    # Explicit-catalog policy is a separate observation, not an offline trust verdict.
    result = subprocess.run([signtool, "verify", "/pa", "/v", "/c", str(catalog), str(payload)],
                            capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
    return {"exit_code": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("the native reference requires Windows")
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    sample = args.sample.resolve()
    if not output.is_relative_to(repository / "out") or output.is_relative_to(sample) or sample.is_relative_to(output):
        parser.error("output must be below this checkout's out directory and outside the sample")
    original = {}
    for name, digest in EXPECTED.items():
        if (sample / name).stat().st_size > 512 * 1024:
            parser.error("sample exceeds the pinned snapshot byte profile: " + name)
        data = (sample / name).read_bytes()
        if sha256(data) != digest:
            parser.error("sample bytes do not match the pinned upstream snapshot: " + name)
        original[name] = data
    signtool = find_signtool()
    if not signtool:
        parser.error("SDK SignTool is required for the explicit-catalog reference")
    cli = args.cli.resolve()
    help_result = subprocess.run([str(cli), "analyze", "--help"], capture_output=True, timeout=30,
                                 creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    output.mkdir(parents=True, exist_ok=True)
    catalog_api = module("windows-catalog-check")
    sip = module("windows-sip-hash")
    native = catalog_api.native_catalog(sample / "VBoxUSB.cat", 2)
    signature = catalog_api.native_signature(sample / "VBoxUSB.cat")
    assert signature["signatures"][0]["combined_content_and_signature"] == "passed"
    native_hashes = {name: sip.sip_hash(sample / name, "SHA256") for name in ("VBoxUSB.inf", "VBoxUSB.sys")}
    records = []
    for case in ("original", "changed-sys", "missing-sys", "renamed-sys", "archive"):
        folder = output / (case + "-input")
        if folder.is_symlink() or folder.is_junction():
            raise ValueError("case directory must not redirect through a link or junction")
        files = original.copy()
        if case == "changed-sys":
            changed = bytearray(files["VBoxUSB.sys"])
            changed[100] ^= 1
            files["VBoxUSB.sys"] = bytes(changed)
        elif case == "missing-sys":
            del files["VBoxUSB.sys"]
        elif case == "renamed-sys":
            files["renamed.sys"] = files.pop("VBoxUSB.sys")
        folder.mkdir(exist_ok=True)
        if set(p.name for p in folder.iterdir()) - set(files):
            raise ValueError("unexpected existing case files; choose a fresh output directory")
        for name, data in files.items():
            if (folder / name).is_symlink() or (folder / name).is_junction():
                raise ValueError("case files must not redirect through links or junctions")
            (folder / name).write_bytes(data)
        source, inf, root = folder, "VBoxUSB.inf", "."
        if case == "archive":
            source = output / "package.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, data in sorted(files.items()):
                    archive.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data)
            inf, root = "package.zip/VBoxUSB.inf", "package.zip"
        archive_before = source.read_bytes() if case == "archive" else None
        destination = output / (case + "-report")
        raw = analyze(cli, source, destination, inf, root, no_ai)
        report = json.loads(raw)
        cat = next(a for a in report["artifacts"] if a["path"].endswith("VBoxUSB.cat"))
        declared = cat["facts"]["windows.catalog"]
        for entry in declared["entries"]:
            expected = next(n for n in native if n["reference_tag"].lower() == entry["subject_identifier"])
            names = [a["name_value"] for a in entry["attributes"] if "name_value" in a]
            assert sorted(names, key=lambda a: a["name"]) == sorted(expected["attributes"], key=lambda a: a["name"])
            if entry["digest"] is not None:
                for key in ("digest", "digest_algorithm", "data_oid", "sip_guid"):
                    assert entry[key] == expected[key]
        assert len(declared["entries"]) == len(native) == 4
        assert declared["signatures"][0]["checks"]["signature"] == "passed"
        assert declared["signatures"][0]["checks"]["content_digest"] == "passed"
        assert not declared["windows_trust_checked"]
        comparisons = cat["facts"]["windows.catalog-membership"]["entries"]
        pe = next(e for e in comparisons if e.get("sip_hash_profile") == "pe-default")
        flat = next(e for e in comparisons if e.get("sip_hash_profile") == "flat-file")
        assert pe["declared_digest"] == native_hashes["VBoxUSB.sys"]
        assert pe["status"] == ("no-matching-checked-artifact" if case in ("changed-sys", "missing-sys") else "digest-agreement")
        # This pinned upstream INF differs from the catalog's named INF declaration.
        # Keep that observation separate from claims about when or why it changed.
        assert flat["declared_digest"] != native_hashes["VBoxUSB.inf"]
        assert flat["status"] == "no-matching-checked-artifact"
        inf_file = next(a for a in report["artifacts"] if a["path"].endswith("VBoxUSB.inf"))
        mapping = inf_file["facts"]["windows.source-files"]["records"][0]
        assert mapping["status"] == ("not-supplied-at-candidate-path" if case in ("missing-sys", "renamed-sys") else "associated-supplied-artifact")
        if case not in ("missing-sys", "renamed-sys"):
            assert mapping["target_sha256"] == sha256(files["VBoxUSB.sys"])
        assert raw == analyze(cli, source, destination, inf, root, no_ai), "report changed on repeat"
        for name, data in files.items():
            assert (folder / name).read_bytes() == data, "case input changed"
        if archive_before is not None:
            assert source.read_bytes() == archive_before, "archive input changed"
        policy = {}
        for name in ("VBoxUSB.inf", "VBoxUSB.sys", "renamed.sys"):
            if name in files:
                policy[name] = policy_check(signtool, folder / "VBoxUSB.cat", folder / name)
        records.append({"case": case, "repeated_json_identical": True, "input_hashes_unchanged": True,
                        "pe_member_status": pe["status"], "inf_member_status": flat["status"],
                        "source_mapping_status": mapping["status"], "signtool_policy": policy})
    for name, data in original.items():
        assert (sample / name).read_bytes() == data, "original sample changed"
    result = {"source": "dorssel/usbipd-win", "revision": "aa3db8b82c4cb5071fd31bc54211606c70886912",
              "license": "GPL-3.0-only; external test inputs, not redistributed",
              "sha256": EXPECTED, "native_catalog": native, "signature_only": signature,
              "native_sip_sha256": native_hashes, "cases": records}
    (output / "checks.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("matched catalog attributes, explicit digests and source mappings across five pinned-package layouts")


if __name__ == "__main__":
    main()
