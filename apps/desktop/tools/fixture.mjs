// Use Node for the copy: npm scripts run through cmd.exe on Windows, which has no cp.
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const desktop = fileURLToPath(new URL("../", import.meta.url));
const fixtures = join(desktop, "tests", "fixtures");
mkdirSync(fixtures, { recursive: true });
for (const [input, output, name] of [
  ["../../crates/aa-apple/tests/data/tiny.dmg", "out", "sample-report"],
  ["../../crates/aa-windows/tests/data/native.lnk", "relationships", "relationships-report"],
]) {
  const result = spawnSync("cargo", [
    "run", "-q", "--release", "-p", "aa-cli", "--", "analyze",
    input, "-o", `tests/fixtures/${output}`, "-f", "html", "--no-ai",
  ], { cwd: desktop, stdio: "inherit", windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  copyFileSync(join(fixtures, output, "report.html"), join(fixtures, `${name}.html`));
}
