import { expect, test } from "@playwright/test";

test("a late finding opens directly without expanding thousands of preceding variants", async ({ page }, testInfo) => {
  await page.goto("/large-report");
  await expect(page.locator("#app")).toBeVisible();
  const ids = await page.locator("#report-data").evaluate((node) => {
    const report = JSON.parse(node.textContent ?? "{}") as { findings: { id: string }[] };
    return report.findings.slice(-2).map((finding) => finding.id);
  });
  await page.goto(`/large-report#finding-${ids[1]}`);
  const selected = page.locator("#focused-finding");
  await expect(selected).toBeVisible();
  await expect(selected.locator(".ftext")).toContainText("Declared item 11999");
  await expect(selected.locator(".evlist")).toContainText("11999");
  await expect(selected.getByRole("button", { name: "Next finding", exact: true })).toBeDisabled();
  await expect(page.locator("#ch-code .variants > .inst")).toHaveCount(10);
  await page.screenshot({ path: testInfo.outputPath("focused-large-report.png") });
  expect(await page.locator(".finding").count()).toBeLessThan(30);
  await expect(selected.locator("script")).toHaveCount(0);
  await expect(selected.locator(".ftext")).toContainText("<script>untrusted-navigation-marker</script>");
  await selected.getByRole("button", { name: "Previous finding", exact: true }).click();
  await expect(selected.locator(".ftext")).toContainText("Declared item 11998");
  await expect(page).toHaveURL(new RegExp(`#finding-${ids[0]}$`));
  await page.goBack();
  await expect(selected.locator(".ftext")).toContainText("Declared item 11999");
  await page.reload();
  await expect(selected.locator(".ftext")).toContainText("Declared item 11999");
  await expect(page.locator("#ch-code .variants > .inst")).toHaveCount(10);
});

test("ID lookup and focused navigation retain filters and return keyboard focus", async ({ page }) => {
  await page.goto("/large-report");
  const search = page.locator("#fsearch");
  await expect(search).toBeVisible();
  const id = await page.locator("#report-data").evaluate((node) => {
    const report = JSON.parse(node.textContent ?? "{}") as { findings: { id: string }[] };
    const finding = report.findings[11999];
    if (!finding) throw new Error("Large report fixture is missing its last finding");
    return finding.id;
  });
  await search.fill(id);
  await search.press("Enter");
  const selected = page.locator("#focused-finding");
  await expect(selected.locator("#focused-card")).toBeFocused();
  await expect(page.locator("#fstatus")).toHaveText("Showing 1 of 12,000 findings");
  await page.getByRole("button", { name: "中文", exact: true }).click();
  await expect(selected.locator(".ftext")).toContainText("声明条目 11999");
  await expect(selected.getByRole("button", { name: "上一条结论", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "English", exact: true }).click();
  await selected.getByRole("button", { name: "Previous finding", exact: true }).click();
  await expect(search).toHaveValue(id);
  await expect(page.locator("#fstatus")).toHaveText("Showing 1 of 12,000 findings");
  await selected.getByRole("button", { name: "Return to results", exact: true }).click();
  await expect(selected).toBeHidden();
  await expect(search).toBeFocused();
  await expect(search).toHaveValue(id);
});

test("an unknown or malformed finding fragment leaves the report usable", async ({ page }) => {
  await page.goto(`/large-report#finding-${"0".repeat(64)}`);
  await expect(page.locator("#app")).toBeVisible();
  await expect(page.locator("#focused-finding")).toBeHidden();
  await page.evaluate(() => { window.location.hash = "#finding-javascript:alert(1)"; });
  await expect(page.locator("#focused-finding")).toBeHidden();
  await expect(page.locator("#ch-code .variants > .inst")).toHaveCount(10);
});
