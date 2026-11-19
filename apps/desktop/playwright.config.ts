import { defineConfig, devices } from "@playwright/test";

// The page in real browser engines, with a stand-in for the rest of the app (src/mock.ts) and a
// real report page in the frame. WebKit is the engine the app uses on macOS.
export default defineConfig({
  testDir: "tests/browser",
  fullyParallel: true,
  reporter: "list",
  use: { baseURL: "http://localhost:1420" },
  webServer: { command: "npm run dev", url: "http://localhost:1420", reuseExistingServer: true },
  projects: [
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
