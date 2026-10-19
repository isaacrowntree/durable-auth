/** A "device" for the journeys: a browser context with its own virtual
 * passkey authenticator (Face ID or a fingerprint, as far as the page can
 * tell) and its own client IP — sign-in is rate limited per IP. */
import { test as base, expect, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

export interface Device {
  page: Page;
  context: BrowserContext;
  /** Uncaught exceptions seen on this device. */
  errors: string[];
  /** Copy this device's passkeys onto another — what iCloud Keychain or
   * Google Password Manager does between one person's devices. */
  sharePasskeysWith(other: Device): Promise<void>;
  addCredentials(credentials: unknown[]): Promise<void>;
}

let ip = 0;

async function newDevice(browser: Browser): Promise<Device> {
  ip++;
  const context = await browser.newContext({ extraHTTPHeaders: { "cf-connecting-ip": `10.0.0.${ip}` } });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    page,
    context,
    errors,
    async sharePasskeysWith(other) {
      const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
      await other.addCredentials(credentials);
    },
    async addCredentials(credentials) {
      for (const credential of credentials) {
        await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: credential as never });
      }
    },
  };
}

export const test = base.extend<{ device: () => Promise<Device> }>({
  device: async ({ browser }, provide) => {
    const devices: Device[] = [];
    await provide(async () => {
      const d = await newDevice(browser);
      devices.push(d);
      return d;
    });
    for (const d of devices) await d.context.close();
    expect(devices.flatMap((d) => d.errors)).toEqual([]);
  },
});

/** The code in the newest email sent since `since` (ms). Locally the email
 * binding writes each message under .wrangler/tmp/email/; the journeys run
 * one at a time, so the newest is ours. */
export async function emailedCode(since: number): Promise<string> {
  const roots = [".wrangler/tmp/email", "examples/basic/.wrangler/tmp/email"].map((r) => path.resolve(r));
  for (let tries = 0; tries < 50; tries++) {
    const files = roots
      .flatMap((root) => {
        try {
          return readdirSync(root, { recursive: true, withFileTypes: true })
            .filter((d) => d.isFile() && d.parentPath.endsWith("email-text"))
            .map((d) => path.join(d.parentPath, d.name));
        } catch {
          return [];
        }
      })
      .filter((f) => statSync(f).mtimeMs >= since)
      .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
    const code = files.length ? /verification code is (\d{6})/.exec(readFileSync(files[0]!, "utf8"))?.[1] : undefined;
    if (code) return code;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("No code was emailed");
}

export async function signUp(page: Page, name: string): Promise<void> {
  await page.goto("/");
  await page.getByLabel("Name").fill(name);
  await page.getByRole("button", { name: "Create account with a passkey" }).click();
  await expect(page.getByText(`Signed in as ${name}`)).toBeVisible();
}

export async function addRecoveryEmail(page: Page, email: string): Promise<void> {
  const since = Date.now();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByRole("button", { name: "Send code" }).click();
  await page.getByLabel("Confirmation code").fill(await emailedCode(since));
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText(`Recovery email: ${email}`)).toBeVisible();
}

export { expect };
