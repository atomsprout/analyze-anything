"""Compare an explicitly supplied INF with read-only SetupAPI field access and the CLI.

No file queue, installer, driver load, Include/Needs expansion or registry write is used.
Only use controlled fixtures with this development reference, never untrusted input.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys


class InfContext(ctypes.Structure):
    _fields_ = [("inf", ctypes.c_void_p), ("current", ctypes.c_void_p),
                ("section", wintypes.UINT), ("line", wintypes.UINT)]


def native_fields(sample):
    api = ctypes.WinDLL("setupapi", use_last_error=True, winmode=0x800)  # System32 only
    api.SetupOpenInfFileW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.UINT)]
    api.SetupOpenInfFileW.restype = ctypes.c_void_p
    api.SetupCloseInfFile.argtypes = [ctypes.c_void_p]
    api.SetupCloseInfFile.restype = None
    api.SetupEnumInfSectionsW.argtypes = [ctypes.c_void_p, wintypes.UINT, wintypes.LPWSTR,
                                         wintypes.UINT, ctypes.POINTER(wintypes.UINT)]
    api.SetupEnumInfSectionsW.restype = wintypes.BOOL
    api.SetupGetLineByIndexW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.POINTER(InfContext)]
    api.SetupGetLineByIndexW.restype = wintypes.BOOL
    api.SetupGetFieldCount.argtypes = [ctypes.POINTER(InfContext)]
    api.SetupGetFieldCount.restype = wintypes.DWORD
    api.SetupGetStringFieldW.argtypes = [ctypes.POINTER(InfContext), wintypes.DWORD,
                                       wintypes.LPWSTR, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    api.SetupGetStringFieldW.restype = wintypes.BOOL
    error_line = wintypes.UINT()
    # A full path prevents SetupAPI's implicit search of the host INF directories.
    handle = api.SetupOpenInfFileW(str(sample.resolve()), None, 2, ctypes.byref(error_line))
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), f"SetupOpenInfFile failed at line {error_line.value}")
    sections = []
    try:
        for index in range(1024):
            name = ctypes.create_unicode_buffer(1024)
            size = wintypes.UINT()
            if not api.SetupEnumInfSectionsW(handle, index, name, len(name), ctypes.byref(size)):
                if ctypes.get_last_error() == 259:  # ERROR_NO_MORE_ITEMS
                    break
                raise ctypes.WinError(ctypes.get_last_error())
            entries = []
            for row in range(8192):
                context = InfContext()
                if not api.SetupGetLineByIndexW(handle, name.value, row, ctypes.byref(context)):
                    # The enumerated section exists; exhausted row index is expected.
                    if ctypes.get_last_error() & 0xFFFFFFFF in (259, 0xE0000102):  # ERROR_LINE_NOT_FOUND
                        break
                    raise ctypes.WinError(ctypes.get_last_error())
                values = []
                count = api.SetupGetFieldCount(ctypes.byref(context))
                if count > 128:
                    raise ValueError("native field count exceeded reference budget")
                for field in range(count + 1):
                    value = ctypes.create_unicode_buffer(4096)
                    required = wintypes.DWORD()
                    ok = api.SetupGetStringFieldW(ctypes.byref(context), field, value,
                                                 len(value), ctypes.byref(required))
                    if not ok and field != 0:
                        raise ctypes.WinError(ctypes.get_last_error())
                    values.append(value.value if ok else None)
                entries.append({"key": values[0], "fields": values[1:]})
            else:
                raise ValueError("native row enumeration exceeded reference budget")
            sections.append({"name": name.value, "entries": entries})
        else:
            raise ValueError("native section enumeration exceeded reference budget")
    finally:
        api.SetupCloseInfFile(handle)
    return sections


def run(command):
    result = subprocess.run(command, capture_output=True, timeout=120)
    if result.returncode not in (0, 2):
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-native-added-sections", action="store_true",
                        help="record native-only section names and compare all source sections; never copy native additions into the report")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("the SetupAPI reference requires Windows")
    if bool(args.cli) != bool(args.output):
        parser.error("--cli and --output must be supplied together")
    if args.allow_native_added_sections and not args.cli:
        parser.error("--allow-native-added-sections requires --cli and --output")
    before = args.sample.read_bytes()
    sections = native_fields(args.sample)
    record = {"sample": args.sample.name, "sha256": hashlib.sha256(before).hexdigest(),
              "reference": "SetupOpenInfFileW/SetupEnumInfSectionsW/SetupGetStringFieldW",
              "sections": sections}
    if args.cli:
        cli = str(args.cli.resolve())
        help_text = run([cli, "analyze", "--help"])
        no_ai = ["--no-ai"] if b"--no-ai" in help_text else []
        command = [cli, str(args.sample.resolve()), "-o", str(args.output.resolve()),
                   "--format", "json,md,html", *no_ai]
        run(command)
        raw = (args.output / "report.json").read_bytes()
        report = json.loads(raw)
        artifact = next(a for a in report["artifacts"] if "windows.inf" in a["facts"])
        fact = artifact["facts"]["windows.inf"]
        assert fact["issue_count"] == 0
        assert not fact["platform_selected"] and not fact["installed"] and not fact["catalog_verified"]
        # This reference compares files with unique section names. Repeated INF sections
        # are merged by SetupAPI; the analyzer deliberately preserves their source occurrences.
        assert len({s["name"].lower() for s in fact["sections"]}) == len(fact["sections"])
        source_names = {s["name"].lower() for s in fact["sections"]}
        native_names = {s["name"].lower() for s in sections}
        assert source_names <= native_names, "native reference omitted source sections"
        native_added = sorted(native_names - source_names)
        if not args.allow_native_added_sections:
            assert not native_added, "native-only sections require an explicit recorded comparison scope"
        checked = 0
        by_name = {s["name"].lower(): s for s in sections}
        for actual in fact["sections"]:
            expected = by_name[actual["name"].lower()]
            assert len(actual["entries"]) == len(expected["entries"]), actual["name"]
            for actual_row, native_row in zip(actual["entries"], expected["entries"]):
                if actual_row["key"] is not None and "%" not in actual_row["key"]:
                    assert actual_row["key"] == native_row["key"], actual_row
                projected = actual_row["neutral_fields"]
                if projected is not None:
                    assert projected == native_row["fields"], (actual["name"], actual_row, native_row)
                    checked += len(projected)
                else:
                    assert len(actual_row["fields"]) == len(native_row["fields"])
        assert checked > 0
        graph = artifact["facts"].get("windows.inf-declarations")
        graph_checked = 0
        if graph is not None:
            assert not graph["installed"] and not graph["platform_selected"]
            assert not graph["host_registry_consulted"] and not graph["external_infs_followed"]
            for declaration in graph["records"]:
                section = fact["sections"][declaration["section"]]
                row = section["entries"][declaration["entry"]]
                assert (declaration["line"], declaration["end_line"]) == (row["line"], row["end_line"])
                projected = row["neutral_fields"]
                values = projected if projected is not None else row["fields"]
                assert declaration["field_basis"] == ("neutral-projection" if projected is not None else "literal")
                details = declaration["details"]
                if "values" in details:
                    assert details["values"] == values
                if declaration["kind"] == "device-model":
                    assert details["install_base"] == values[0]
                    assert details["hardware_id"] == (values[1] if len(values) > 1 else "")
                    assert details["compatible_ids"] == values[2:]
                if declaration["kind"] == "service-addition":
                    assert details["service_name"] == values[0]
                    assert details["flags_literal"] == (values[1] if len(values) > 1 else "")
                    assert isinstance(details["null_associated_service"], bool)
                if declaration["kind"] == "copy-file":
                    assert details["destination_filename"] == values[0]
                    assert details["source_filename"] == (values[1] if len(values) > 1 and values[1] else values[0])
                    assert not details["copy_performed"] and not details["supplied_path_resolved"]
                if declaration["kind"] == "registry-row":
                    assert details["root"] == values[0]
                    assert details["data_fields"] == values[4:]
                    assert not details["operation_performed"] and not details["root_context_resolved"]
                # Directory-ID expansions from native SetupAPI never supply graph values.
                if projected is not None:
                    native_row = by_name[section["name"].lower()]["entries"][declaration["entry"]]
                    assert values == native_row["fields"]
                    graph_checked += 1
            for reference in graph["references"]:
                assert all(0 <= target < len(fact["sections"]) for target in reference["target_sections"])
                assert len(reference["target_sections"]) <= reference["observed_target_count"]
        run(command)
        assert raw == (args.output / "report.json").read_bytes(), "report changed on repeat"
        assert "windows.inf" in (args.output / "report.html").read_text(encoding="utf-8")
        assert "Windows INF declarations" in (args.output / "report.md").read_text(encoding="utf-8")
        chinese = args.output / "zh"
        run([cli, str(args.sample.resolve()), "-o", str(chinese.resolve()),
             "--format", "md", "--lang", "zh", *no_ai])
        assert "Windows INF 声明" in (chinese / "report.md").read_text(encoding="utf-8")
        if graph is not None and graph["records"]:
            assert "windows.inf-declarations" in (args.output / "report.html").read_text(encoding="utf-8")
            assert "INF device, service and file declarations" in (args.output / "report.md").read_text(encoding="utf-8")
            assert "INF 设备、服务及文件声明" in (chinese / "report.md").read_text(encoding="utf-8")
            details = {
                "device-model": ("windows.inf-model-declaration", "Declared device model", "声明的设备型号"),
                "service-addition": ("windows.inf-service-declaration", "Declared service association", "声明的服务关联"),
                "service-property": ("windows.inf-service-property", "Declared service property", "声明的服务属性"),
                "copy-file": ("windows.inf-copy-declaration", "Declared file copy source", "声明的文件复制源"),
                "direct-copy-source": ("windows.inf-copy-declaration", "Declared file copy source", "声明的文件复制源"),
                "source-file": ("windows.inf-source-declaration", "Declared source media file", "声明的源介质文件"),
                "registry-row": ("windows.inf-registry-declaration", "Declared registry location", "声明的注册表位置"),
            }
            if "report_details_omitted" in graph:
                assert graph["report_details_omitted"] == 0, "these controlled sources fit the detail budget"
                for kind in {row["kind"] for row in graph["records"]} & details.keys():
                    rule, english, translated = details[kind]
                    findings = [finding for finding in report["findings"] if finding["rule"] == rule]
                    assert findings and all(finding["evidence"] for finding in findings)
                    assert english in (args.output / "report.md").read_text(encoding="utf-8")
                    assert translated in (chinese / "report.md").read_text(encoding="utf-8")
        record["comparison"] = {"projected_fields_equal": checked, "repeated_json_identical": True,
                                "english_chinese_markdown": True, "graph_source_rows_checked": graph_checked,
                                "native_added_sections": native_added,
                                "native_added_sections_allowed": args.allow_native_added_sections}
        print(f"matched {checked} projected fields against SetupAPI")
    assert args.sample.read_bytes() == before, "input was modified"
    args.reference.parent.mkdir(parents=True, exist_ok=True)
    args.reference.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
