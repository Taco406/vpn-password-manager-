import { defineConfig, devices } from "@playwright/test";

// Drive the built app via `vite preview`. The Chromium that ships in this environment
// lives at /opt/pw-browsers/chromium; point executablePath at it so no download is
// attempted.
const CHROMIUM = process.env.SENTINEL_CHROMIUM || "/opt/pw-browsers/chromium";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: false,
  reporter: [["list"]],
  webServer: {
    command: "pnpm preview",
    url: "http://localhost:4173",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  use: {
    baseURL: "http://localhost:4173",
    viewport: { width: 1440, height: 900 },
    launchOptions: { executablePath: CHROMIUM },
  },
  projects: [
    { name: "dark", use: { ...devices["Desktop Chrome"], colorScheme: "dark" } },
    { name: "light", use: { ...devices["Desktop Chrome"], colorScheme: "light" } },
  ],
});
