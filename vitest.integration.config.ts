/** Opt-in integration suite: sign-in against a real Durable Object, on the
 * SQLite that actually ships. `npm test` never runs this — it's `npm run
 * test:integration`, because it boots workerd and is an order of magnitude
 * slower than the unit tests.
 *
 * The unit suite (AuthStore over node:sqlite) proves the logic and that the
 * SQL parses. This proves it runs where it is deployed: DO SQLite (BLOBs,
 * NULL bindings, ALTERs), reached through the Durable Object's RPC. */
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

// @cloudflare/vitest-plugin is the renamed @cloudflare/vitest-pool-workers:
// the same Vite plugin and options, on the line that supports Vitest 5.
export default defineConfig({
  plugins: [
    cloudflareTest({
      isolatedStorage: true,
      wrangler: { configPath: "./test/integration/wrangler.jsonc" },
    }),
  ],
  test: {
    include: ["test/integration/**/*.test.ts"],
  },
});
