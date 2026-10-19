import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    // `npm run test:coverage`; CI fails under these.
    coverage: {
      provider: "v8",
      include: ["src/server/**/*.ts", "src/client/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        // Barrels: re-exports only.
        "src/server/index.ts",
        // Imports `cloudflare:workers`, so it only loads in workerd. The
        // integration suite (`npm run test:integration`) is what runs it.
        "src/server/durable-object.ts",
      ],
      reporter: ["text", "html"],
      // The floor is what the unit suite reaches, rounded down. It sits low
      // because src/client and integrations.ts only run in a browser or
      // against Cloudflare (the e2e suite), which this doesn't measure; they're
      // included so they show as 0% rather than not at all.
      thresholds: {
        lines: 80,
        functions: 70,
        branches: 80,
        statements: 80,
        "src/server/store.ts": { lines: 95, functions: 100, branches: 95, statements: 95 },
        // Every route and every check on the way to it. A branch nobody
        // exercises here is a refusal nobody has seen refuse.
        "src/server/auth.ts": { lines: 100, functions: 100, branches: 100, statements: 100 },
      },
    },
  },
});
