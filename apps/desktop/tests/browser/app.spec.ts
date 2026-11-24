import { expect, test, type Page } from "@playwright/test";

// Needs the sample report: `npm run fixture`.

interface Mock {
  dialogAnswer: string | null;
  stepDelay: number;
  failWith: string | null;
  aiReady: boolean;
  aiFailWith: string | null;
  aiCite: string | null;
  calls: string[];
  offer(path: string): void;
  drag(over: boolean): void;
  menu(id: string): void;
}

const mock = <T>(page: Page, use: (mock: Mock) => T) => page.evaluate(`(${use.toString()})(window.__mock)`) as Promise<T>;

async function openSample(page: Page) {
  await page.goto("/");
  await page.evaluate(() => window.localStorage.setItem("lang", "en"));
  await page.reload();
  await page.getByRole("button", { name: "Open File…" }).click();
  await expect(page.locator(".progress")).toBeVisible();
  await expect(page.locator(".report")).toBeVisible();
}

async function viewEvidenceBytes(page: Page) {
  const report = page.frameLocator("iframe.report-frame");
  const button = report.getByRole("button", { name: "View bytes", exact: true }).first();
  const summaries = report.locator("details.evidence > summary");
  // The host can be visible before its report loads. count() does not wait for the frame.
  await expect(summaries.first()).toBeVisible();
  const count = await summaries.count();
  for (let i = 0; i < count && !(await button.isVisible()); i += 1) await summaries.nth(i).click();
  await button.click();
}

test("source mapping is optional, validated and scoped to the chosen input", async ({ page }) => {
  await page.goto("/");
  const panel = page.locator(".source-root-options");
  await expect(panel).not.toHaveAttribute("open", "");
  await panel.locator("summary").click();
  await page.getByRole("button", { name: "Add source root", exact: true }).click();
  await page.getByRole("textbox", { name: "Logical INF path", exact: true }).fill("Pkg/DRIVER.INF");
  const root = page.getByRole("textbox", { name: "Logical distribution root", exact: true });
  await root.fill("C:/drivers");
  await page.getByRole("button", { name: "Open File…" }).click();
  await expect(page.locator(".toast")).toContainText("Check the source roots");
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("startAnalysis")))).toEqual([]);
  await expect(root).toHaveValue("C:/drivers");
  await root.fill("PKG");
  await page.getByRole("button", { name: "Open File…" }).click();
  await expect(page.locator(".report")).toBeVisible();
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("startAnalysis")))).toEqual([
    'startAnalysis("/Users/me/Downloads/Sample.dmg",[{"inf":"pkg/driver.inf","root":"pkg"}])',
  ]);
  await page.getByRole("button", { name: "‹ Home" }).click();
  await expect(page.locator(".source-root-row")).toHaveCount(0);
  await page.getByRole("button", { name: "Open File…" }).click();
  await expect(page.locator(".report")).toBeVisible();
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("startAnalysis")).at(-1))).toBe('startAnalysis("/Users/me/Downloads/Sample.dmg")');
});

test("language changes retain source-mapping drafts", async ({ page }) => {
  await page.goto("/");
  await page.locator(".source-root-options summary").click();
  await page.getByRole("button", { name: "Add source root", exact: true }).click();
  await page.getByRole("textbox", { name: "Logical INF path", exact: true }).fill("driver.inf");
  await page.getByRole("textbox", { name: "Logical distribution root", exact: true }).fill(".");
  await mock(page, (m) => m.menu("lang:zh"));
  await page.locator(".source-root-options summary").click();
  await expect(page.getByRole("textbox", { name: "INF 逻辑路径", exact: true })).toHaveValue("driver.inf");
  await expect(page.getByRole("textbox", { name: "逻辑分发根目录", exact: true })).toHaveValue(".");
});

test("reanalyzing a kept report retains its source mappings", async ({ page }) => {
  await page.goto("/");
  await page.locator(".source-root-options summary").click();
  await page.getByRole("button", { name: "Add source root", exact: true }).click();
  await page.getByRole("textbox", { name: "Logical INF path", exact: true }).fill("driver.inf");
  await page.getByRole("textbox", { name: "Logical distribution root", exact: true }).fill(".");
  await mock(page, (m) => m.offer("/drivers.zip"));
  await expect(page.locator(".report")).toBeVisible();
  await page.getByRole("button", { name: "‹ Home" }).click();
  await mock(page, (m) => m.offer("/other.zip"));
  await expect(page.locator(".report")).toBeVisible();
  await page.getByRole("button", { name: "‹ Home" }).click();
  // Hold the kept report until its host is visible, as on a slow filesystem or CI runner.
  let releaseReport!: () => void;
  const reportReleased = new Promise<void>((resolve) => { releaseReport = resolve; });
  await page.route("**/sample-report?*", async (route) => {
    await reportReleased;
    await route.continue();
  });
  await page.locator(".entry").filter({ hasText: "drivers.zip" }).locator(".entry-main").click();
  await expect(page.locator(".report")).toBeVisible();
  // Starting the interaction before release exercises the wait inside viewEvidenceBytes.
  const viewing = viewEvidenceBytes(page);
  releaseReport();
  await viewing;
  await page.getByRole("button", { name: "Analyze again", exact: true }).click();
  await expect(page.locator(".report")).toBeVisible();
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("startAnalysis")).at(-1))).toBe('startAnalysis("/drivers.zip",[{"inf":"driver.inf","root":"."}])');
});

test("the report page, on its own, has its own controls and no host buttons", async ({ page }) => {
  await page.goto("/sample-report");
  await expect(page.locator("header.top .tools")).toBeVisible();
  await page.locator("details.evidence > summary").first().click();
  await expect(page.locator(".evlist .ev").first()).toBeVisible();
  await expect(page.locator(".hostlink")).toHaveCount(0);
});

test("opening questions lead to the original finding and coverage", async ({ page }) => {
  await page.goto("/sample-report");
  const questions = page.locator("#questions");
  await expect(questions).toBeVisible();
  await expect(questions.locator("h4")).toHaveCount(4);
  await questions.getByRole("button").first().click();
  await expect(page.locator("#findings :focus")).toBeVisible();
  await questions.locator('a[href="#coverage"]').click();
  await expect(page.locator("#coverage")).toBeInViewport();
});

test("unresolved relationships retain their reasons and open the source evidence", async ({ page }) => {
  await page.goto("/relationships-report");
  const relationships = page.locator("#relationships");
  await expect(relationships.locator("tbody tr")).toHaveCount(4);
  await expect(relationships).toContainText("unresolved");
  await expect(relationships).toContainText("absolute-or-device-path-not-anchored");
  await relationships.getByRole("button").first().click();
  await expect(page.locator("#detail")).toContainText("native.lnk");
  await expect(page.locator("#detail")).toContainText("windows.input-references");
});

test("opening a file shows progress, then the report in a sandboxed frame", async ({ page }) => {
  await openSample(page);
  const frame = page.locator("iframe.report-frame");
  await expect(frame).toHaveAttribute("sandbox", "allow-scripts");
  const report = page.frameLocator("iframe.report-frame");
  // In its host the report leaves language and colours to the host.
  await expect(report.locator("#app")).toBeVisible();
  await expect(report.locator("header.top .tools")).toHaveCount(0);
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("startAnalysis")))).toEqual(['startAnalysis("/Users/me/Downloads/Sample.dmg")']);
});

test("the report asks its host for bytes, and the host shows them with the evidence marked", async ({ page }) => {
  await openSample(page);
  // Every finding's evidence is behind a disclosure; open them until one cites a byte range.
  await viewEvidenceBytes(page);

  await expect(page.locator(".drawer")).toBeVisible();
  await expect(page.locator(".hexrow").first()).toBeVisible();
  const read = await mock(page, (m) => m.calls.find((c) => c.startsWith("readBytes")) ?? "");
  expect(read).toMatch(/^readBytes\("[^"]+","[^"]+",0,16\)$/);
  // The stand-in's bytes are their own offsets, so the marked bytes say where the view is.
  await expect(page.locator(".hexbytes mark").first()).toBeVisible();
  const evidence = await page.locator(".drawer-evidence span").innerText();
  const offset = Number(/offset ([\d,]+)/.exec(evidence)?.[1]?.replace(/,/g, ""));
  // The row is drawn at once and filled in when its piece of the file arrives.
  await expect.poll(async () => Number.parseInt(await page.locator(".hexbytes mark").first().innerText(), 16)).toBe(offset & 0xff);

  await page.locator(".offset").fill("0x2000");
  await page.getByRole("button", { name: "Go", exact: true }).click();
  await expect(page.locator(".hexoffset").first()).toHaveText("00001FE0");
  await page.keyboard.press("Escape");
  await expect(page.locator(".drawer")).toBeHidden();
});

test("the report page sends its host nothing but what the host asked to be told", async ({ page }) => {
  // Observe the first load. Reloading before that load finishes can mix two ready messages.
  await page.addInitScript(() => {
    const seen: unknown[] = [];
    Object.defineProperty(window, "__reportMessages", { value: seen });
    window.addEventListener("message", (event) => seen.push(event.data));
  });
  await openSample(page);
  const messages = await page.evaluate(
    () =>
      new Promise<unknown[]>((resolve) => {
        const seen = (window as Window & { __reportMessages?: unknown[] }).__reportMessages ?? [];
        window.setTimeout(() => resolve(seen), 1500);
      }),
  );
  expect(messages).toEqual([{ source: "analyze-anything-report", kind: "ready" }]);
});

test("the host sets the report's language", async ({ page }) => {
  await openSample(page);
  const report = page.frameLocator("iframe.report-frame");
  await expect(report.locator("nav").getByText("Summary", { exact: true })).toBeVisible();
  await mock(page, (m) => m.menu("lang:zh"));
  await expect(page.getByRole("button", { name: "‹ 主页" })).toBeVisible();
  await expect(page.frameLocator("iframe.report-frame").locator("nav").getByText("摘要", { exact: true })).toBeVisible();
});

test("exporting says where the file went, and a cancelled dialog says nothing", async ({ page }) => {
  await openSample(page);
  await page.getByRole("button", { name: "Export ▾" }).click();
  await page.getByRole("menuitem", { name: "PDF…" }).click();
  await expect(page.locator(".toast")).toContainText("Exported to /Users/me/Desktop/out.pdf");
  await mock(page, (m) => {
    m.dialogAnswer = null;
  });
  await mock(page, (m) => m.menu("export:folder"));
  await expect(page.locator(".toast")).toBeHidden();
  expect(await mock(page, (m) => m.calls.filter((c) => c.startsWith("export")).length)).toBe(2);
});

test("history: open, compare two, delete one", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => window.localStorage.setItem("lang", "en"));
  await page.reload();
  await expect(page.locator(".entry")).toHaveCount(2);
  const compare = page.getByRole("button", { name: "Compare the two selected" });
  await expect(compare).toBeDisabled();
  await page.locator(".entry input").nth(0).check();
  await page.locator(".entry input").nth(1).check();
  await compare.click();
  await expect(page.locator(".compare")).toBeVisible();
  // The older report is "before", whichever was ticked first.
  expect(await mock(page, (m) => m.calls.find((c) => c.startsWith("compareReports")))).toBe('compareReports("20261118-090000","20261119-101500")');
  await expect(page.locator(".tile-count")).toHaveText(["1", "1", "1", "442", "1", "1", "1", "436"]);
  await expect(page.locator(".diff-row").first()).toContainText("App Transport Security is off");
  await expect(page.locator(".was")).toContainText("Version: 1.0 (build 10).");
  await page.getByPlaceholder("Filter…").fill("old.dat");
  await expect(page.locator(".diff-row")).toHaveCount(1);

  await page.getByRole("button", { name: "‹ Home" }).click();
  await page.locator(".entry > .plain").first().click();
  await expect(page.locator(".dialog")).toContainText("Example-1.1.ipa");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator(".entry")).toHaveCount(2);
  await page.locator(".entry > .plain").first().click();
  await page.locator(".dialog .danger").click();
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("a dropped file is analyzed, a failure is said, and cancelling returns home", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => window.localStorage.setItem("lang", "en"));
  await page.reload();
  // The backend is imported asynchronously; home appears after its event handlers exist.
  await expect(page.locator(".home")).toBeVisible();
  await mock(page, (m) => m.drag(true));
  await expect(page.locator(".drop")).toHaveClass(/over/);
  await expect(page.locator(".drop h2")).toHaveText("Release to analyze");
  await mock(page, (m) => {
    m.drag(false);
    m.failWith = "cannot read /x: permission denied";
    m.offer("/Users/me/Desktop/Thing.app");
  });
  await expect(page.locator(".progress h2")).toHaveText("Thing.app");
  await expect(page.locator(".toast.error")).toContainText("permission denied");
  await expect(page.locator(".home")).toBeVisible();

  await mock(page, (m) => {
    m.stepDelay = 400;
  });
  await page.getByRole("button", { name: "Open File…" }).click();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator(".toast")).toContainText("cancelled");
  await expect(page.locator(".home")).toBeVisible();
  await expect(page.locator(".entry")).toHaveCount(2);
});

test("AI interpretation: nothing is asked until the user says so, and what is not set up says how", async ({ page }) => {
  await openSample(page);
  await mock(page, (m) => {
    m.aiReady = false;
  });
  const panel = page.locator(".ai-panel");
  await expect(panel).toBeHidden();
  await page.getByRole("button", { name: "AI interpretation" }).click();
  await expect(panel).toBeVisible();
  await expect(panel).toContainText("not set up, so nothing is sent anywhere");
  await expect(panel.locator(".ai-commands")).toContainText("analyze-anything ai claude");
  await expect(panel).toContainText("/Users/me/.analyze-anything/config.toml");
  await expect(panel.getByRole("button", { name: "Interpret", exact: true })).toHaveCount(0);

  // Once it is set up, "Check again" offers it, and says who would be asked before anything is.
  await mock(page, (m) => {
    m.aiReady = true;
  });
  await panel.getByRole("button", { name: "Check again" }).click();
  await expect(panel.locator(".ai-sends")).toContainText("sample-model at https://example.test/v1");
  expect(await mock(page, (m) => m.calls.filter((call) => call.startsWith("aiInterpret")).length)).toBe(0);
  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
});

test("AI interpretation: the statements are shown as the model's, and a cited finding opens in the report", async ({ page }) => {
  await openSample(page);
  const report = page.frameLocator("iframe.report-frame");
  await expect(report.locator("#app")).toBeVisible();
  // Cite a finding the sample report really has.
  const id = await report.locator("#report-data").evaluate((node) => (JSON.parse(node.textContent ?? "{}") as { findings: { id: string }[] }).findings[0]?.id ?? "");
  expect(id).toMatch(/^[0-9a-f]{64}$/);
  await page.evaluate(`window.__mock.aiCite = ${JSON.stringify(id)}; window.__mock.stepDelay = 150;`);

  await mock(page, (m) => m.menu("ai"));
  const panel = page.locator(".ai-panel");
  await expect(panel).toBeVisible();
  await expect(page.getByRole("button", { name: "AI interpretation" })).toHaveAttribute("aria-pressed", "true");
  await panel.getByRole("button", { name: "Interpret", exact: true }).click();
  await expect(panel.locator(".ai-running")).toBeVisible();
  await expect(panel.locator(".ai-step")).toHaveText("looking up list_findings");
  await expect(panel.locator(".ai-statement")).toHaveCount(2);
  await expect(panel.locator(".ai-banner")).toContainText("Written by the language model sample-model, not by the analyzer");
  await expect(panel).toContainText("left out because they cited no finding of the report: 1.");
  await expect(panel.locator(".ai-section h3")).toHaveText(["Summary", "Worth attention"]);

  // Long words from a report (digests, identifiers) wrap inside the panel instead of widening it.
  expect(await panel.locator(".ai-body").evaluate((body) => body.scrollWidth <= body.clientWidth)).toBe(true);
  expect(await panel.locator(".ai-statement").evaluateAll((items) => items.every((item) => item.getBoundingClientRect().right <= window.innerWidth))).toBe(true);

  await panel.locator(".cite").first().click();
  await expect(report.locator(".flash")).toBeVisible();

  // It is kept: closing and opening the report again shows it without asking the model again.
  await page.getByRole("button", { name: "‹ Home" }).click();
  await page.locator(".entry-main").first().click();
  await page.getByRole("button", { name: "AI interpretation" }).click();
  await expect(page.locator(".ai-statement")).toHaveCount(2);
  expect(await mock(page, (m) => m.calls.filter((call) => call.startsWith("aiInterpret")).length)).toBe(1);
});

test("AI interpretation: a failure is said in the panel and can be tried again", async ({ page }) => {
  await openSample(page);
  await mock(page, (m) => {
    m.aiFailWith = "the service answered 401 (is the API key right?)";
  });
  await page.getByRole("button", { name: "AI interpretation" }).click();
  const panel = page.locator(".ai-panel");
  await panel.getByRole("button", { name: "Interpret", exact: true }).click();
  await expect(panel.locator(".ai-problem")).toContainText("did not finish: the service answered 401");
  await panel.getByRole("button", { name: "Interpret", exact: true }).click();
  await expect(panel.locator(".ai-statement")).toHaveCount(2);
});
