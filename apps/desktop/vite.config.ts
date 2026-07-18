import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Tauri expects a fixed dev port; harmless for browser-mode dev too.
  server: { port: 5173, strictPort: false },
  build: { target: "es2022", outDir: "dist", sourcemap: false },
});
