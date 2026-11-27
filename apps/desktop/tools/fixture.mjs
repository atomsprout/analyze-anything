// Use Node for the copy: npm scripts run through cmd.exe on Windows, which has no cp.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const desktop = fileURLToPath(new URL("../", import.meta.url));
const fixtures = join(desktop, "tests", "fixtures");
// A caller can reuse an already built CLI after clearing development caches.
const suppliedCli = process.env.AA_FIXTURE_CLI;
let acceptsNoAi = true;
if (suppliedCli) {
  const help = spawnSync(suppliedCli, ["analyze", "--help"], { cwd: desktop, encoding: "utf8", windowsHide: true });
  if (help.error) throw help.error;
  if (help.status !== 0) throw new Error(`Fixture CLI help failed: ${help.stderr}`);
  acceptsNoAi = help.stdout.includes("--no-ai");
}
function runCli(args) {
  const prefix = suppliedCli ? [] : ["run", "-q", "--release", "-p", "aa-cli", "--"];
  return spawnSync(suppliedCli ?? "cargo", [...prefix, ...args.filter((arg) => acceptsNoAi || arg !== "--no-ai")],
    { cwd: desktop, stdio: "inherit", windowsHide: true });
}
mkdirSync(fixtures, { recursive: true });
for (const [input, output, name] of [
  ["../../crates/aa-apple/tests/data/tiny.dmg", "out", "sample-report"],
  ["../../crates/aa-windows/tests/data/native.lnk", "relationships", "relationships-report"],
  ["../../crates/aa-windows/tests/data/native-actions.msi", "msi-actions", "msi-actions-report"],
]) {
  const result = runCli([
    "analyze",
    input, "-o", `tests/fixtures/${output}`, "-f", "html,json", "--no-ai",
  ]);
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  copyFileSync(join(fixtures, output, "report.html"), join(fixtures, `${name}.html`));
}

// Exercise a target beyond the initial group/variant pages using the production renderer.
const large = JSON.parse(readFileSync(join(fixtures, "out", "report.json"), "utf8"));
const source = large.artifacts[0];
large.rules["navigation.fixture"] = {
  title_en: "Navigation fixture", title_zh: "导航测试结论",
  text_en: "Declared item {index}: {marker}", text_zh: "声明条目 {index}：{marker}",
};
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
large.findings = Array.from({ length: 12000 }, (_, index) => {
  const finding = { id: "", section: "code", analyzer: "navigation", rule: "navigation.fixture",
    params: { index, marker: index === 11999 ? "<script>untrusted-navigation-marker</script>" : "static data" },
    confidence: "verified", severity: "info", references: [],
    evidence: [{ artifact: source.path, sha256: source.digests?.sha256 ?? null, location: { field: `item-${index}` }, value: { index } }],
  };
  finding.id = createHash("sha256").update(JSON.stringify(canonical(finding))).digest("hex");
  return finding;
});
const largeJson = join(fixtures, "large-report.json");
writeFileSync(largeJson, JSON.stringify(large));
const rendered = runCli(["render", largeJson, "-o", "tests/fixtures/large", "--format", "html"]);
if (rendered.error) throw rendered.error;
if (rendered.status !== 0) process.exit(rendered.status ?? 1);
copyFileSync(join(fixtures, "large", "report.html"), join(fixtures, "large-report.html"));
