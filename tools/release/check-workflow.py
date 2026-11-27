#!/usr/bin/env python3
"""Check an extracted CLI's real analysis/query/worker workflow using only the stdlib.

The executable is the analyzer under test. Supplied inputs are inert bytes, never run.
Every process gets a private temporary root; no shared development cache is touched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Client:
    def __init__(self, program, arguments, env):
        self.process = subprocess.Popen(
            [str(program), *map(str, arguments)], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        )
        self.messages = queue.Queue()
        self.errors = []
        self.next_id = 0

        def read():
            try:
                for line in self.process.stdout:
                    self.messages.put(json.loads(line))
            except Exception as error:
                self.messages.put(error)
            finally:
                self.messages.put(EOFError("server stdout closed"))

        def diagnostics():
            # Drain stderr concurrently so diagnostics cannot block the protocol.
            for line in self.process.stderr:
                self.errors.append(line)

        self.reader = threading.Thread(target=read, daemon=True)
        self.diagnostics = threading.Thread(target=diagnostics, daemon=True)
        self.reader.start()
        self.diagnostics.start()

    def send(self, method, params, request=True):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if request:
            self.next_id += 1
            message["id"] = self.next_id
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return message.get("id")

    def request(self, method, params):
        identifier = self.send(method, params)
        reply = self.messages.get(timeout=60)
        if isinstance(reply, Exception):
            raise reply
        require(reply.get("id") == identifier, f"unexpected response: {reply}")
        require("error" not in reply, f"protocol error: {reply}")
        return reply["result"]

    def initialize(self):
        result = self.request("initialize", {"protocolVersion": "2025-06-18"})
        require(result["protocolVersion"] == "2025-06-18", "protocol version")
        self.send("notifications/initialized", {}, request=False)

    def tool(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        require(not result.get("isError"), f"tool failed: {result}")
        return json.loads(result["content"][0]["text"])

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            status = self.process.wait(timeout=10)
            require(status == 0, f"server exit {status}: {''.join(self.errors)}")
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.reader.join(timeout=2)
            self.diagnostics.join(timeout=2)
            require(not self.reader.is_alive() and not self.diagnostics.is_alive(), "server or worker retained protocol/diagnostic pipes after exit")
            self.process.stdout.close()
            self.process.stderr.close()


def run(program, args, env, codes=(0,)):
    result = subprocess.run([str(program), *map(str, args)], env=env,
                            capture_output=True, encoding="utf-8", timeout=120)
    require(result.returncode in codes, f"{args}: exit {result.returncode}: {result.stderr}")
    return result


def wait_worker(root, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if root.exists() and list(root.glob(f"worker-{process.pid}-*")):
            return
        require(process.poll() is None, "server exited before starting a worker")
        time.sleep(0.005)
    raise AssertionError("no active worker scratch observed")


def wait_worker_exit(root, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, "agent exited while cancelling its worker")
        if not list(root.glob(f"worker-{process.pid}-*")):
            return
        time.sleep(0.01)
    raise AssertionError("cancelled worker scratch did not disappear")


QUERY_TOOLS = {"list_findings", "get_finding", "list_files", "get_file", "list_evidence", "list_limitations", "get_coverage"}


def query_suite(client, path, finding_id, report_id=None):
    def call(name, arguments):
        if report_id is not None:
            arguments = dict(arguments, report_id=report_id)
        answer = client.tool(name, arguments)
        if report_id is not None:
            require(answer["report_id"] == report_id, "query escaped immutable report ID")
        return answer

    require(call("list_findings", {"limit": 1})["matching"] > 0, "missing findings")
    require(call("get_finding", {"id": finding_id})["full_id"] == finding_id, "finding lookup disagrees")
    require(call("list_files", {})["matching"] == 1, "snapshot depends on original input")
    require(call("get_file", {"path": path})["path"] == path, "file lookup disagrees")
    require(call("list_evidence", {"query": "example.invalid"})["matching"] > 0, "evidence lookup failed")
    require(call("list_limitations", {})["matching"] == 0, "unexpected limitation on inert text")
    require(call("get_coverage", {})["selected_artifacts"] == 1, "MCP coverage")


def check(program, base, aged, offline):
    temporary = base / "temporary"
    temporary.mkdir(parents=True)
    env = dict(os.environ, TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
    source = base / "supplied"
    source.mkdir()
    small = source / "中文 ' sample.txt"
    small.write_bytes(b"https://example.invalid/workflow\nStatic supplied data.\n")
    original = small.read_bytes()
    scratch = temporary / "analyze-anything-workers"
    scratch.mkdir()
    sentinel = scratch / "caller-owned.txt"
    sentinel.write_bytes(b"Never remove caller-owned bytes.\n")
    old = time.time() - 3600
    if aged:
        os.utime(scratch, (old, old))
    unowned = temporary / "analyze-anything-unowned"
    unowned.mkdir()
    (unowned / "caller-owned.txt").write_bytes(b"Not engine scratch.")
    os.utime(unowned, (old, old))
    report_dir = base / "report"
    run(program, [small, "-o", report_dir, "--format", "json,md,html", *offline], env)
    report_path = report_dir / "report.json"
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    repeated = base / "repeated"
    run(program, [small, "-o", repeated, "--format", "json", *offline], env)
    require((repeated / "report.json").read_bytes() == report_bytes, "repeat report differs")
    require(small.read_bytes() == original, "analysis modified input")
    coverage = json.loads(run(program, ["query", report_path, "coverage"], env).stdout)
    require(coverage["selected_artifacts"] == 1, "CLI coverage")
    run(program, ["explain", report_path, report["findings"][0]["id"]], env)
    snapshot = Client(program, ["mcp", report_path], env)
    try:
        snapshot.initialize()
        tools = snapshot.request("tools/list", {})["tools"]
        require({t["name"] for t in tools} == QUERY_TOOLS and all(t["annotations"]["readOnlyHint"] for t in tools), "snapshot tools")
        small.unlink()
        query_suite(snapshot, small.name, report["findings"][0]["id"])
    finally:
        snapshot.close()
    require(report_path.read_bytes() == report_bytes, "queries changed saved report")
    small.write_bytes(original)
    (source / "second.txt").write_bytes(b"second inert file")
    agent = Client(program, ["agent", "--root", source, "--analysis-timeout", "60"], env)
    try:
        agent.initialize()
        tools = agent.request("tools/list", {})["tools"]
        require({t["name"] for t in tools} == QUERY_TOOLS | {"analyze_input"}, "agent tools")
        require(all(t["annotations"]["readOnlyHint"] == (t["name"] != "analyze_input") for t in tools), "agent read-only annotations")
        answer = agent.tool("analyze_input", {"path": small.name})
        require(answer["report_id"] == report_id, "packaged CLI/agent report disagreement")
        query_suite(agent, small.name, report["findings"][0]["id"], report_id)
        partial = agent.tool("analyze_input", {"path": ".", "max_files": 1})
        require(partial["partial"] and partial["coverage"]["truncated"], "missing explicit partial status")
        require(agent.tool("list_limitations", {"report_id": partial["report_id"]})["matching"] > 0, "missing partial limitation")
        # Keep the slow cancellation input out of the bounded-file partial check.
        with (source / "large.bin").open("wb") as handle:
            handle.truncate(512 * 1024 * 1024)
        pending = agent.send("tools/call", {"name": "analyze_input", "arguments": {"path": "large.bin"}})
        wait_worker(scratch, agent.process)
        agent.send("notifications/cancelled", {"requestId": pending}, request=False)
        require(agent.request("ping", {}) == {}, "cancelled server unresponsive")
        require(agent.tool("get_coverage", {"report_id": partial["report_id"]})["selected_artifacts"] == 1, "cancellation replaced previous report")
        # Cancellation is asynchronous. Observe its cleanup before starting a distinct
        # EOF case, rather than accidentally observing the preceding worker's scratch.
        wait_worker_exit(scratch, agent.process)
        agent.send("tools/call", {"name": "analyze_input", "arguments": {"path": "large.bin"}})
        wait_worker(scratch, agent.process)
        require(agent.request("ping", {}) == {}, "EOF analysis did not start")
        require(list(scratch.glob(f"worker-{agent.process.pid}-*")), "EOF case finished before observation")
        # Close while a worker is present; EOF must stop it and remove its scratch.
    finally:
        agent.close()
    require(sentinel.read_bytes() == b"Never remove caller-owned bytes.\n", "caller sentinel lost")
    require((unowned / "caller-owned.txt").read_bytes() == b"Not engine scratch.", "aged unmarked directory was swept")
    require(not list(scratch.glob("worker-*")), "worker scratch survived normal/cancel/EOF exit")
    require(sorted(p.name for p in source.iterdir()) == sorted([small.name, "second.txt", "large.bin"]), "unexpected writes in supplied root")
    return {"root": "aged" if aged else "fresh", "report_id": report_id, "checks": "analysis/repeat/query/explain/snapshot/source-removal/agent/partial/cancel/active-EOF/scratch/input-preservation"}


def check_msi(program, base, offline):
    """Exercise this release's MSI feature against a pinned native reference."""
    base.mkdir()
    fixtures = Path(__file__).resolve().parents[2] / "crates/aa-windows/tests/data"
    original = (fixtures / "native-actions.msi").read_bytes()
    native = json.loads((fixtures / "native-actions.msi.ref.json").read_text(encoding="utf-8"))
    require(hashlib.sha256(original).hexdigest() == native["sha256"], "native MSI reference belongs to different bytes")
    source = base / "中文 ' actions.msi"
    source.write_bytes(original)
    env = os.environ.copy()
    for name in ("TMP", "TEMP", "TMPDIR"):
        env[name] = str(base.resolve())
    output = base / "report"
    run(program, [source, "-o", output, "--format", "json,md,html", *offline], env)
    report_path = output / "report.json"
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    root = next(a for a in report["artifacts"] if a["parent"] is None)
    model = root["facts"]["windows.msi-actions"]
    require(not model["incomplete"] and not model["conditions_evaluated"] and not model["execution_established"], "MSI static profile")
    rows = {s["table"]: [r["row"] for r in s["rows"]] for s in model["sequences"]}
    rows["CustomAction"] = [a["row"] for a in model["custom_actions"]]
    rows["LaunchCondition"] = model["launch_conditions"]
    for table, expected in native["tables"].items():
        if table == "Binary":
            continue
        ordered = lambda entries: sorted(entries, key=lambda r: json.dumps(r, sort_keys=True))
        require(ordered(rows[table]) == ordered(expected), f"MSI {table} differs from native reference")
    references = root["facts"]["windows.msi-action-targets"]["references"]
    matched = [r for r in references if r["status"] == "matched-supplied-declaration"]
    require(len(matched) == 5 and len(references) == 7, "MSI target resolution counts")
    for reference in matched:
        target = next(a for a in report["artifacts"] if a["path"] == reference["target"])
        require(target["parent"] == root["path"], "MSI target escaped container")
        require(target["digests"]["sha256"] == reference["target_sha256"] == native["tables"]["Binary"][0]["Data"]["sha256"], "MSI Binary stream digest")
    repeat = base / "repeat"
    run(program, [source, "-o", repeat, "--format", "json", *offline], env)
    require((repeat / "report.json").read_bytes() == report_bytes, "MSI report is not deterministic")
    require(source.read_bytes() == original, "MSI source was modified")
    native_checks = None
    if os.name == "nt":
        native_record = base / "native.json"
        reference_script = Path(__file__).resolve().parents[1] / "native-compare/windows-msi-actions.py"
        checked = subprocess.run([sys.executable, str(reference_script), str(source), str(report_path), "--record", str(native_record)],
                                 env=env, capture_output=True, encoding="utf-8", timeout=60)
        require(checked.returncode == 0, f"fresh native MSI reference failed: {checked.stderr}")
        native_checks = json.loads(native_record.read_text(encoding="utf-8"))["checks"]
    source.unlink()
    findings = json.loads(run(program, ["query", report_path, "findings", "--args", json.dumps({"rule": "windows.msi-action"})], env).stdout)
    require(findings["matching"] == 7, "MSI finished-report finding query")
    client = Client(program, ["mcp", report_path], env)
    try:
        client.initialize()
        for finding in findings["findings"]:
            detail = client.tool("get_finding", {"id": finding["full_id"]})
            require("CustomAction" in json.dumps(detail), "MSI source evidence missing from MCP")
    finally:
        client.close()
    markdown = (output / "report.md").read_text(encoding="utf-8")
    require("CustomAction table, row RunPayload" in markdown and "binary-row-not-unique-or-missing" in markdown, "MSI relationship index")
    return {"sample_sha256": native["sha256"], "actions": len(references), "matched_binary_sources": len(matched),
            "fresh_windows_native_checks": native_checks,
            "checks": "native-table-snapshot/binary-hashes/repeat/input-preservation/source-removal/query/MCP/relationship-index"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=Path)
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    program = args.program.resolve(strict=True)
    help_text = run(program, ["analyze", "--help"], os.environ).stdout
    offline = ["--no-ai"] if "--no-ai" in help_text else []
    with tempfile.TemporaryDirectory(prefix="aa-packaged-workflow-") as folder:
        results = [check(program, Path(folder) / name, aged, offline) for name, aged in (("fresh", False), ("aged", True))]
        msi = check_msi(program, Path(folder) / "msi", offline)
    record = {"program_sha256": hashlib.sha256(program.read_bytes()).hexdigest(), "results": results, "msi": msi}
    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
