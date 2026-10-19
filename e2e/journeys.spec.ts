import { addRecoveryEmail, emailedCode, expect, signUp, test } from "./fixtures";

test("a passkey is the whole login: sign up, stay signed in, sign out, sign back in", async ({ device }) => {
  const { page } = await device();
  await signUp(page, "Sam");
  await expect(page.getByText("Hello, Sam")).toBeVisible();

  await page.reload();
  await expect(page.getByText("Signed in as Sam")).toBeVisible();

  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  expect((await page.request.get("/api/hello")).status()).toBe(401);

  // No username: the passkey says who.
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByText("Signed in as Sam")).toBeVisible();
});

test("a lost device: back in by email on a new one, and the lost one is locked out", async ({ device }) => {
  const lost = await device();
  await signUp(lost.page, "Ana");
  await addRecoveryEmail(lost.page, "ana@example.com");

  const fresh = await device();
  await fresh.page.goto("/");
  const since = Date.now();
  await fresh.page.getByLabel("Recovery email").fill("Ana@Example.com");
  await fresh.page.getByRole("button", { name: "Email me a code" }).click();
  await expect(fresh.page.getByText("If that email has an account")).toBeVisible();
  await fresh.page.getByLabel("Recovery code").fill(await emailedCode(since));
  // Recovering adds a passkey for this device straight away.
  await fresh.page.getByRole("button", { name: "Recover" }).click();
  await expect(fresh.page.getByText("Signed in as Ana")).toBeVisible();
  await expect(fresh.page.locator("#passkeys li")).toHaveCount(1);

  // The lost device's session is gone, and so is its passkey.
  await lost.page.reload();
  await expect(lost.page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  await lost.page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(lost.page.getByRole("status")).toHaveText("No account uses this passkey");

  // The new device's passkey works.
  await fresh.page.getByRole("button", { name: "Sign out", exact: true }).click();
  await fresh.page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(fresh.page.getByText("Signed in as Ana")).toBeVisible();
});

test("a recovery email for an address nobody uses looks exactly the same", async ({ device }) => {
  const { page } = await device();
  await page.goto("/");
  await page.getByLabel("Recovery email").fill("nobody@example.com");
  await page.getByRole("button", { name: "Email me a code" }).click();
  await expect(page.getByText("If that email has an account")).toBeVisible();
});

test("deleting the account asks for the passkey again once the session is stale", async ({ device }) => {
  const { page } = await device();
  await signUp(page, "Leo");
  await page.waitForTimeout(3_500); // past the e2e step-up window

  const reauth = page.waitForResponse((r) => r.url().endsWith("/auth/reauth-verify"));
  await page.getByRole("button", { name: "Delete account" }).click();
  expect((await reauth).status()).toBe(200);
  await expect(page.getByRole("status")).toHaveText("Account deleted.");

  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("status")).toHaveText("No account uses this passkey");
});

test("the only passkey can't be removed", async ({ device }) => {
  const { page } = await device();
  await signUp(page, "Kim");
  await page.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByRole("status")).toHaveText("That's your only passkey — add another before removing it");
  await expect(page.locator("#passkeys li")).toHaveCount(1);
});

test("signing out other devices keeps this one", async ({ device }) => {
  const here = await device();
  await signUp(here.page, "Mo");
  // The same passkey, synced to a second device that signs in on its own.
  const there = await device();
  await here.sharePasskeysWith(there);
  await there.page.goto("/");
  await there.page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(there.page.getByText("Signed in as Mo")).toBeVisible();

  await here.page.getByRole("button", { name: "Sign out other devices" }).click();
  await expect(here.page.getByRole("status")).toHaveText("Other devices are signed out.");

  await there.page.reload();
  await expect(there.page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  await here.page.reload();
  await expect(here.page.getByText("Signed in as Mo")).toBeVisible();
});
