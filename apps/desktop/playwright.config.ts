import { defineConfig, devices } from "@playwright/test";

// Drive the built app via `vite preview`. If SENTINEL_CHROMIUM points at a prebuilt
// Chromium (as in the dev container at /opt/pw-browsers/chromium) we use it directly;
// otherwise we let Playwright resolve its own installed browser (as on CI runners,
// where `playwright install chromium` provides it).
const CHROMIUM = process.env.SENTINEL_CHROMIUM;

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
    ...(CHROMIUM ? { launchOptions: { executablePath: CHROMIUM } } : {}),
  },
  projects: [
    { name: "dark", use: { ...devices["Desktop Chrome"], colorScheme: "dark" } },
    { name: "light", use: { ...devices["Desktop Chrome"], colorScheme: "light" } },
  ],
});
