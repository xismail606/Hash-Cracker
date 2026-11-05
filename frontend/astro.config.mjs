// @ts-check
import { defineConfig } from "astro/config";
import react from "@astrojs/react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is built as a fully static site and served by the local
// Flask server (python -m password_audit serve). The build output goes to
// src/password_audit/static/ so Flask can serve it directly.
export default defineConfig({
  integrations: [react()],
  vite: {
    plugins: [tailwindcss()],
    // `astro dev` and `astro preview` proxy /api to the local Flask backend so
    // the dashboard works during development. Loopback only; for the real
    // dashboard run `python -m password_audit serve`, which serves the built
    // assets and the API from one server.
    server: {
      proxy: {
        "/api": { target: "http://127.0.0.1:8765", changeOrigin: false },
      },
    },
    preview: {
      proxy: {
        "/api": { target: "http://127.0.0.1:8765", changeOrigin: false },
      },
    },
  },
  outDir: "../src/password_audit/static",
  emptyOutDir: true,
});
