/** End-to-end: the example app in Chromium, with real WebAuthn against a
 * virtual authenticator (Chrome DevTools Protocol), real cookies, and the
 * library running in wrangler dev — nothing mocked. */
import { defineConfig, devices } from "@playwright/test";

const PORT = 8791;

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: `http://localhost:${PORT}`, ...devices["Desktop Chrome"] },
  webServer: {
    // A fresh database each run; a short step-up window so a test can outlast it.
    command: `rm -rf .wrangler/e2e-state examples/basic/.wrangler/tmp/email && npx wrangler dev --config examples/basic/wrangler.jsonc --port ${PORT} --persist-to .wrangler/e2e-state --var REAUTH_WINDOW_MS:3000`,
    url: `http://localhost:${PORT}/auth/config`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
