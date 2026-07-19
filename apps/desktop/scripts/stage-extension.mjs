// Stage the built browser extension into the Tauri resource tree so the installer bundles it.
//
// The extension lives in apps/extension and builds to apps/extension/dist. Tauri bundles
// files under apps/desktop/src-tauri/resources (see `bundle.resources` in tauri.conf.json),
// so we copy the freshly-built dist there. Run AFTER `pnpm --filter @sentinel/extension build`;
// the Tauri `beforeBuildCommand` chains both. Safe to run repeatedly (it clears the dest first).
import { cp, rm, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url)); // apps/desktop/scripts
const src = resolve(here, "../../extension/dist"); // apps/extension/dist
const dest = resolve(here, "../src-tauri/resources/extension"); // apps/desktop/src-tauri/resources/extension

if (!existsSync(src)) {
  console.error(
    `[stage-extension] source not found: ${src}\n` +
      `  build it first: pnpm --filter @sentinel/extension build`,
  );
  process.exit(1);
}

await rm(dest, { recursive: true, force: true });
await mkdir(dest, { recursive: true });
await cp(src, dest, { recursive: true });
console.log(`[stage-extension] copied ${src} -> ${dest}`);
