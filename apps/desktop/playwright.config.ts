import { defineConfig, devices } from "@playwright/test";

// The page in real browser engines, with a stand-in for the rest of the app (src/mock.ts) and a
// real report page in the frame. WebKit is the engine the app uses on macOS.
export default defineConfig({
  testDir: "tests/browser",
  fullyParallel: true,
  // Hosted Windows runs have timed out creating Chromium pages with two workers.
  // Keep the same assertions and timeouts while avoiding concurrent browser starts there.
  workers: process.env.CI && process.platform === "win32" ? 1 : undefined,
  reporter: "list",
  // Use the same address family for Vite, readiness and browser navigation on every host.
  use: { baseURL: "http://127.0.0.1:1420" },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1",
    url: "http://127.0.0.1:1420",
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
