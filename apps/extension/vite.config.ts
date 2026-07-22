import { defineConfig } from "vite";
import { resolve } from "node:path";
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";

// Build the MV3 extension: background + content as IIFE-safe ES modules, the popup as
// its own HTML entry, and copy the manifest into dist.
export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    rollupOptions: {
      input: {
        background: resolve(__dirname, "src/background.ts"),
        content: resolve(__dirname, "src/content.ts"),
        inpage: resolve(__dirname, "src/inpage.ts"),
        popup: resolve(__dirname, "popup.html"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "[name].js",
        assetFileNames: "[name].[ext]",
      },
    },
  },
  plugins: [
    {
      name: "copy-manifest-and-icons",
      closeBundle() {
        const dist = resolve(__dirname, "dist");
        mkdirSync(dist, { recursive: true });
        copyFileSync(resolve(__dirname, "manifest.json"), resolve(dist, "manifest.json"));
        const iconsSrc = resolve(__dirname, "icons");
        const iconsDst = resolve(dist, "icons");
        mkdirSync(iconsDst, { recursive: true });
        for (const f of readdirSync(iconsSrc)) {
          copyFileSync(resolve(iconsSrc, f), resolve(iconsDst, f));
        }
      },
    },
  ],
});
