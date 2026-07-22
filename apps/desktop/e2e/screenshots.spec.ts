// Generates the /showcase screenshot set from the mock bridge with seeded data. Each
// screen is captured frozen (data-freeze) for pixel stability, in both themes.

import { test, expect } from "@playwright/test";

// Screens to capture. `dark`/`light` marks which themes to render for each.
const SHOTS: { name: string; url: string; both?: boolean; wait?: number }[] = [
  { name: "unlock", url: "/?freeze=1#/unlock", both: false },
  { name: "vault", url: "/?unlocked=1&freeze=1#/vault", both: true },
  { name: "vault-item", url: "/?unlocked=1&freeze=1#/vault/06060606-0606-0606-0606-060606060606", both: false },
  { name: "vpn-idle", url: "/?unlocked=1&freeze=1#/vpn", both: false, wait: 400 },
  { name: "vpn-connected", url: "/?unlocked=1&freeze=1&vpn=connected&region=eu-central#/vpn", both: true, wait: 600 },
  { name: "health", url: "/?unlocked=1&freeze=1#/health", both: false, wait: 300 },
  { name: "devices", url: "/?unlocked=1&freeze=1#/devices", both: false },
  { name: "settings", url: "/?unlocked=1&freeze=1#/settings", both: false },
  { name: "report", url: "/?unlocked=1&freeze=1#/report", both: false, wait: 300 },
];

for (const shot of SHOTS) {
  test(`screenshot ${shot.name}`, async ({ page }, testInfo) => {
    const theme = testInfo.project.name; // "dark" | "light"
    if (theme === "light" && !shot.both) test.skip();

    // Ensure theme is applied before app boot: add it to the query.
    const url = shot.url.replace("#", `&theme=${theme}#`).replace("/?&", "/?");
    await page.goto(url);
    await page.waitForTimeout(shot.wait ?? 200);
    // Wait for the canvas/fonts to settle.
    await page.evaluate(() => document.fonts?.ready);
    await page.waitForTimeout(150);

    const dir = theme === "light" ? "light" : "dark";
    await page.screenshot({ path: `../../showcase/${dir}/${shot.name}.png` });
    expect(true).toBeTruthy();
  });
}
