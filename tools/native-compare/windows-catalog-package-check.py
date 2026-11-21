"""Compare controlled supplied catalog/payload layouts, without installing a package."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from windows_tools import find_signtool


def module(filename):
    spec = importlib.util.spec_from_file_location(filename, Path(__file__).with_name(filename + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def run(command):
    result = subprocess.run(command, capture_output=True, timeout=120,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("the native package comparison requires Windows")
    repository = Path(__file__).resolve().parents[2]
    fixtures = repository / "crates/aa-windows/tests/data"
    destination = args.output.resolve()
    if not destination.is_relative_to(repository / "out"):
        parser.error("generated layouts must remain below this checkout's out directory")
    destination.mkdir(parents=True, exist_ok=True)
    sip = module("windows-sip-hash")
    cli = str(args.cli.resolve())
    no_ai = ["--no-ai"] if b"--no-ai" in run([cli, "analyze", "--help"]) else []
    signtool = find_signtool()
    if not signtool:
        parser.error("the explicit-catalog comparison requires SDK SignTool")
    signed_catalog = (fixtures / "native-catalog-v2.cat").read_bytes()
    pe = (fixtures / "hello.exe").read_bytes()
    signed_pe = (fixtures / "hello-signed.exe").read_bytes()
    payload = b"Analyze Anything catalog fixture.\r\n"
    reference = json.loads((fixtures / "native-catalog-v2.cat.ref.json").read_bytes())
    expected = next(m["digest"] for m in reference["members"] if m["data_oid"] == "1.3.6.1.4.1.311.2.1.15")
    records = []
    for case in ("catalog-only", "dual", "modified", "missing", "embedded-only", "archive"):
        source = destination / (case + "-input")
        source.mkdir(exist_ok=True)
        files = {"payload.txt": payload}
        if case != "embedded-only":
            files["package.cat"] = signed_catalog
        if case != "missing":
            content = bytearray(signed_pe if case in ("dual", "embedded-only") else pe)
            if case == "modified":
                content[100] ^= 1
            files["hello.exe"] = bytes(content)
        files["driver.inf"] = (
            '[Version]\r\nSignature="$Windows NT$"\r\nCatalogFile=%Catalog%\r\n'
            f'[SourceDisksFiles]\r\nhello.exe=1,,{len(files.get("hello.exe", pe))}\r\npayload.txt=1,,{len(payload)}\r\n'
            '[SourceDisksNames]\r\n1=Controlled media\r\n[Strings]\r\nCatalog=package.cat\r\n'
        ).encode("ascii")
        # Refuse old extra files rather than silently changing the supplied scope on rerun.
        if set(p.name for p in source.iterdir()) - set(files):
            raise ValueError("controlled input contains unexpected files; choose a fresh output directory")
        for name, content in files.items():
            (source / name).write_bytes(content)
        input_path = source
        if case == "archive":
            input_path = destination / "package.zip"
            with zipfile.ZipFile(input_path, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, content in sorted(files.items()):
                    archive.writestr(zipfile.ZipInfo(name, (1980,1,1,0,0,0)), content)
        report_path = destination / (case + "-report")
        logical_inf = "package.zip/driver.inf" if case == "archive" else "driver.inf"
        logical_root = "package.zip" if case == "archive" else "."
        command = [cli, str(input_path), "-o", str(report_path), "--format", "json,md,html",
                   "--windows-source-root", logical_inf, logical_root, *no_ai]
        run(command)
        raw = (report_path / "report.json").read_bytes()
        report = json.loads(raw)
        artifacts = report["artifacts"]
        source_inf = next(a for a in artifacts if a["path"].endswith("driver.inf"))
        source_mapping = source_inf["facts"]["windows.source-files"]
        assert source_mapping["root"] == logical_root
        mapped_executable = next(row for row in source_mapping["records"] if row["relative_path"] == "hello.exe")
        assert mapped_executable["status"] == ("not-supplied-at-candidate-path" if case == "missing" else "associated-supplied-artifact")
        if case != "missing":
            assert mapped_executable["size_agreement"]
        assert not source_mapping["windows_installation_checked"]
        native = None
        if "hello.exe" in files:
            native = sip.sip_hash(source / "hello.exe", "SHA256")
            assert (native == expected) == (case != "modified")
        if case != "embedded-only":
            catalog = next(a for a in artifacts if a["path"].endswith("package.cat"))
            fact = catalog["facts"]["windows.catalog-membership"]
            comparison = next(e for e in fact["entries"] if e.get("sip_hash_profile") == "pe-default")
            assert (comparison["status"] == "digest-agreement") == (case not in ("missing", "modified"))
            assert comparison["search_complete"]
            assert fact["signed_content_binding_signers"] == [0]
            assert not fact["windows_trust_checked"]
            source_inf = next(a for a in artifacts if a["path"].endswith("driver.inf"))
            assert source_inf["facts"]["windows.input-references"]["references"][0]["target"] == catalog["path"]
        else:
            assert not any("windows.catalog-membership" in a["facts"] for a in artifacts)
            source_inf = next(a for a in artifacts if a["path"].endswith("driver.inf"))
            assert source_inf["facts"]["windows.input-references"]["references"][0]["status"] == "unresolved"
        if case in ("dual", "embedded-only"):
            executable = next(a for a in artifacts if a["path"].endswith("hello.exe"))
            assert executable["facts"]["windows.authenticode"]["signatures"][0]["checks"]["signature"] == "passed"
        if case != "embedded-only":
            assert "windows.catalog-digest-agreement" in (report_path / "report.html").read_text(encoding="utf-8")
            assert "Catalog digests agree with supplied artifacts" in (report_path / "report.md").read_text(encoding="utf-8")
            if case in ("missing", "modified"):
                assert "1 member digest declaration matches" in (report_path / "report.md").read_text(encoding="utf-8")
        # SignTool's trust-policy status is an observation, never a replacement for the
        # SIP digest oracle or a requirement that the fixture root be trusted by this host.
        native_policy = None
        if "hello.exe" in files or case == "missing":
            native_command = [signtool, "verify", "/pa", "/v"]
            if case != "embedded-only":
                native_command += ["/c", str(source / "package.cat")]
            native_command.append(str(source / "hello.exe"))
            result = subprocess.run(native_command, capture_output=True, timeout=60,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            native_policy = {"exit_code": result.returncode,
                             "stdout": result.stdout.decode("utf-8", errors="replace"),
                             "stderr": result.stderr.decode("utf-8", errors="replace")}
        run(command)
        assert raw == (report_path / "report.json").read_bytes()
        assert all((source / name).read_bytes() == content for name, content in files.items())
        records.append({"case": case, "inputs": {n:hashlib.sha256(b).hexdigest() for n,b in files.items()},
                        "source_mapping": mapped_executable,
                        "native_sip_sha256": native, "expected_catalog_pe_digest": expected,
                        "signtool_policy_observation": native_policy, "repeated_json_identical": True})
    chinese = destination / "zh-report"
    run([cli, str(destination / "catalog-only-input"), "-o", str(chinese), "--format", "md", "--lang", "zh",
         "--windows-source-root", "driver.inf", ".", *no_ai])
    assert "目录摘要与输入中的文件一致" in (chinese / "report.md").read_text(encoding="utf-8")
    assert "声明的源路径关联到输入文件" in (chinese / "report.md").read_text(encoding="utf-8")
    (destination / "checks.json").write_text(json.dumps({"cases": records},indent=2)+"\n",encoding="utf-8")
    print(f"passed {len(records)} supplied-layout cases")


if __name__ == "__main__":
    main()
