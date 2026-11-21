"""Compare resource/device declarations with native APIs, without selecting or installing packages."""

import argparse
import html
import io
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if sys.platform != "win32" or output.exists() or not output.is_relative_to(repository / "out"):
        parser.error("choose a fresh directory below this Windows checkout's out directory")
    output.mkdir(parents=True)
    import importlib.util
    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
        result = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(result)
        return result
    api = load("appx_reference", "windows-msix-blockmap.py")
    bundle = load("bundle_reference", "windows-msix-bundle-check.py")
    app = load("manifest_reference", "windows-msix-manifest-check.py")
    cli = str(args.cli.resolve())
    help_result = subprocess.run([cli, "analyze", "--help"], capture_output=True, timeout=30, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    no_ai = ["--no-ai"] if b"--no-ai" in help_result.stdout else []
    manifest_name = "AppxMetadata/AppxBundleManifest.xml"
    def analyze(source, folder):
        original, previous = source.read_bytes(), None
        for _ in range(2):
            done = subprocess.run([cli, str(source), "-o", str(folder), "--format", "json,md,html", *no_ai],
                                  capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
            assert done.returncode in (0, 2), done.stderr.decode("utf-8", errors="replace")
            data = (folder / "report.json").read_bytes()
            assert previous is None or previous == data
            previous = data
        assert source.read_bytes() == original
        report = json.loads(data)
        root = next(a for a in report["artifacts"] if a["parent"] is None)
        return report, root["facts"]["windows.msix-bundle-checks"]
    def dimensions(rows):
        return {"languages": sorted({r["language"].lower() for r in rows if r["language"]}),
                "scales": sorted({r["scale"] for r in rows if r["scale"]}),
                "dx_feature_levels": sorted({{1:"dx9",2:"dx10",3:"dx11"}[r["dx_feature_level"]] for r in rows if r["dx_feature_level"]}),
                "default_rows": sum(all(v is None for v in r.values()) for r in rows)}
    def families(rows):
        return {r["Name"]:{"minimum":r["MinVersion"],"maximum_tested":r["MaxVersionTested"]} for r in rows}
    results = []
    for name in ["native-msix-bundle.appxbundle", "native-msix-qualifiers.appxbundle", "upstream-BundleWithIntlPackage.appxbundle", "upstream-SignedUntrustedCert.appxbundle"]:
        source = repository / "crates/aa-windows/tests/data" / name
        folder = output / name
        folder.mkdir()
        with zipfile.ZipFile(source) as archive:
            path = folder / "bundle.xml"
            path.write_bytes(archive.read(manifest_name))
            native = {"bundle":bundle.native(path, api, include_families=True),"inner":[]}
            assert len(native["bundle"]["packages"]) <= 128
            for index, row in enumerate(native["bundle"]["packages"]):
                encoded = quote(row["file_name"], safe="-._~")
                with zipfile.ZipFile(io.BytesIO(archive.read(encoded))) as inner:
                    path = folder / ("inner-" + str(index) + ".xml")
                    path.write_bytes(inner.read("AppxManifest.xml"))
                    native["inner"].append({"name":encoded,"manifest":app.native(path, api, include_resources=True)})
        (output / (name + ".declarations.ref.json")).write_text(json.dumps(native, indent=2) + "\n", encoding="utf-8")
        report, checked = analyze(source, folder / "report")
        for record, declared, observed in zip(checked["records"], native["bundle"]["packages"], native["inner"]):
            result = record["result"]
            resource = result["resource_declaration_comparison"]
            assert resource["status"] == "agrees" and resource["declared"] == dimensions(declared["resources"])
            assert resource["observed"] == dimensions(observed["manifest"]["resources"])
            target = next(a for a in report["artifacts"] if a["path"] == result["target"] + "/AppxManifest.xml")
            assert target["facts"]["windows.msix"]["source_sha256"] == observed["manifest"]["source_sha256"]
            device = result["target_device_family_comparison"]
            if declared["target_device_families"]:
                assert device["status"] == "agrees" and device["declared"] == families(declared["target_device_families"])
                assert device["observed"] == families(observed["manifest"]["target_device_families"])
            else:
                assert device["status"] == "not-declared"
            assert not device["host_compatibility_checked"] and not resource["host_resource_selection_performed"]
        results.append({"case":name,"native":native,"checks":checked,"input_unchanged":True,"repeated_json_identical":True})
    original = repository / "crates/aa-windows/tests/data/native-msix-qualifiers.appxbundle"
    with zipfile.ZipFile(original) as archive:
        entries = [(i.filename, archive.read(i)) for i in archive.infolist()]
    xml = dict(entries)[manifest_name].decode("utf-8")
    family = re.search(r'<b4:TargetDeviceFamily Name="Windows.Universal"[^>]*/>', xml).group()
    desktop = re.search(r'<b4:TargetDeviceFamily Name="Windows.Desktop"[^>]*/>', xml).group()
    variants = {
        "control": xml,
        "language-case": xml.replace('Language="zh-CN"','Language="ZH-cn"'),
        "language-order": xml.replace('<Resource Language="en-US"/>','<Resource Language="TEMP"/>').replace('Language="fr-FR"','Language="en-US"').replace('Language="TEMP"','Language="fr-FR"'),
        "language-difference": xml.replace('Language="zh-CN"','Language="ja-JP"'),
        "scale-difference": xml.replace('Scale="200"','Scale="250"'),
        "resource-duplicate": xml.replace('<Resource Language="zh-CN"/>','<Resource Language="zh-CN"/><Resource Language="zh-CN"/>'),
        "resource-foreign": xml.replace('<Resource Language="zh-CN"/>','<Resource Language="zh-CN"/><evil:Resource xmlns:evil="urn:foreign" Language="ja-JP"/>'),
        "resource-placeholder": xml.replace('Language="zh-CN"','Language="x-generate"'),
        "family-difference": xml.replace('MaxVersionTested="10.0.22621.0"','MaxVersionTested="10.0.26100.0"'),
        "family-order": xml.replace(desktop,"FAMILY-TEMP",1).replace(family,desktop,1).replace("FAMILY-TEMP",family,1),
        "family-duplicate": xml.replace(family,family+family,1),
        "family-foreign": xml.replace('<b4:TargetDeviceFamily Name="Windows.Universal"','<b4:TargetDeviceFamily xmlns:b4="urn:foreign" Name="Windows.Universal"',1),
        "family-missing-version": xml.replace('MaxVersionTested="10.0.22621.0"',''),
        "family-not-declared": xml.replace(re.search(r'<b4:Dependencies>.*?</b4:Dependencies>',xml,re.S).group(),'',1),
    }
    def wrapped(text):
        def write(text):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer,"w",compression=zipfile.ZIP_STORED) as archive:
                for name, content in entries:
                    archive.writestr(name,text.encode("utf-8") if name==manifest_name else content)
            return buffer.getvalue()
        draft = write(text)
        with zipfile.ZipFile(io.BytesIO(draft)) as archive:
            def offsets(match):
                tag=match.group()
                name=html.unescape(re.search(r'FileName="([^"]+)"',tag).group(1))
                entry=archive.getinfo(quote(name,safe="-._~"))
                tag=re.sub(r'Offset="[^"]+"','Offset="'+str(entry.header_offset+30+len(entry.filename.encode("utf-8")))+'"',tag)
                return re.sub(r'Size="[^"]+"','Size="'+str(entry.file_size)+'"',tag)
            text=re.sub(r'<Package\b[^>]*>',offsets,text)
        return write(text)
    for case,text in variants.items():
        folder=output/case
        folder.mkdir()
        source=folder/"variant.appxbundle"
        source.write_bytes(wrapped(text))
        _, checked=analyze(source,folder/"report")
        resource_diff=int(case in ("language-difference","scale-difference"))
        resource_unknown=int(case in ("resource-duplicate","resource-foreign","resource-placeholder"))
        family_diff=int(case=="family-difference")
        family_unknown=int(case in ("family-duplicate","family-foreign","family-missing-version"))
        family_absent=int(case=="family-not-declared")
        assert checked["packages_corresponding"]==4 and checked["packages_differing"]==0,(case,checked)
        assert checked["resource_declarations_agree"]==4-resource_diff-resource_unknown and checked["resource_declarations_differ"]==resource_diff,(case,checked)
        assert checked["resource_declarations_unresolved"]==resource_unknown
        assert checked["target_device_families_agree"]==4-family_diff-family_unknown-family_absent and checked["target_device_families_differ"]==family_diff,(case,checked)
        assert checked["target_device_families_unresolved"]==family_unknown and checked["target_device_families_not_declared"]==family_absent
        path=folder/"bundle.xml"
        with zipfile.ZipFile(source) as archive:
            path.write_bytes(archive.read(manifest_name))
        try:
            native={"bundle":bundle.native(path,api,include_families=True)}
        except OSError as error:
            native={"bundle_reader_error":str(error)}
        results.append({"case":case,"native":native,"checks":checked,"input_unchanged":True,"repeated_json_identical":True})
    chinese=output/"chinese-report"
    done=subprocess.run([cli,str(output/"family-difference/variant.appxbundle"),"-o",str(chinese),"--format","json,md","--lang","zh",*no_ai],
                        capture_output=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
    assert done.returncode in (0,2)
    assert "MSIX bundle 与内部清单的目标设备声明不同" in (chinese/"report.md").read_text(encoding="utf-8")
    (output/"checks.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    print("compared four original bundles and fourteen resource/device declaration variants")


if __name__=="__main__":
    main()
