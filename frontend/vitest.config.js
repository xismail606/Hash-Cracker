import { defineConfig } from "vitest/config";

export default defineConfig({
  // The component uses the automatic JSX runtime; esbuild handles .jsx
  // without the React plugin.
  esbuild: { jsx: "automatic" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.js"],
    include: ["src/**/*.test.{js,jsx}"],
  },
});
