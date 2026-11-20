// Use Node for the copy: npm scripts run through cmd.exe on Windows, which has no cp.
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const desktop = fileURLToPath(new URL("../", import.meta.url));
const fixtures = join(desktop, "tests", "fixtures");
const result = spawnSync("cargo", [
  "run", "-q", "--release", "-p", "aa-cli", "--", "analyze",
  "../../crates/aa-apple/tests/data/tiny.dmg", "-o", "tests/fixtures/out", "-f", "html", "--no-ai",
], { cwd: desktop, stdio: "inherit", windowsHide: true });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
mkdirSync(fixtures, { recursive: true });
copyFileSync(join(fixtures, "out", "report.html"), join(fixtures, "sample-report.html"));
