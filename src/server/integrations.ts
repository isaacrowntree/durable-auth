/** Ready-made `createAuth` options for Cloudflare's own services. Each is a
 * few lines; read them before you trust them, and swap in your own as needed. */

import type { CodePurpose } from "./store";

/** The slice of a `send_email` binding this needs. */
export interface EmailBinding {
  send(message: {
    to: string;
    from: { email: string; name: string };
    subject: string;
    text: string;
    html: string;
  }): Promise<unknown>;
}

/** `sendCode` over Cloudflare Email Sending. `from`'s domain must be onboarded
 * (`wrangler email sending enable <domain>`); it adds records on a
 * `cf-bounce` subdomain, so a domain already on Gmail or Workspace keeps them.
 *
 * The wording — "<code> is your <app> verification code" — is the phrasing
 * mail apps look for to offer a one-tap Copy code. */
export function cloudflareEmail(binding: EmailBinding, options: { from: string; appName: string }) {
  const { from, appName } = options;
  return async (to: string, code: string, purpose: CodePurpose): Promise<void> => {
    const what = purpose === "recover" ? `sign back in to ${appName}` : `confirm this as your ${appName} recovery email`;
    const text = `Your ${appName} verification code is ${code}\n\nEnter it to ${what}. It expires in 10 minutes.\n\nIf you didn't ask for this, ignore this email — nothing changes without the code.`;
    const html = `<p style="font:16px/1.5 -apple-system,system-ui,sans-serif">Your ${escape(appName)} verification code is</p>
<p style="font:600 32px/1.2 ui-monospace,Menlo,monospace;letter-spacing:4px">${code}</p>
<p style="font:16px/1.5 -apple-system,system-ui,sans-serif">Enter it to ${escape(what)}. It expires in 10 minutes.</p>
<p style="font:14px/1.5 -apple-system,system-ui,sans-serif;color:#666">If you didn't ask for this, ignore this email — nothing changes without the code.</p>`;
    await binding.send({
      to,
      from: { email: from, name: appName },
      subject: `${code} is your ${appName} verification code`,
      text,
      html,
    });
  };
}

/** Turnstile's server-side check, for `turnstile.verify`.
 *
 * `hostnames`: refuse a token solved on any other site using the same
 * widget. `checkAction`: refuse a token solved on a different form — render
 * the widget with `data-action="signup"` on sign-up and `"recover"` on
 * recovery, and a token from one won't pass the other. */
export function turnstileVerifier(secret: string, expect: { hostnames?: string[]; checkAction?: boolean } = {}) {
  return async (token: string, ip: string | null, action?: string): Promise<boolean> => {
    const form = new FormData();
    form.append("secret", secret);
    form.append("response", token);
    if (ip) form.append("remoteip", ip);
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const outcome = (await res.json().catch(() => null)) as {
      success?: boolean;
      hostname?: string;
      action?: string;
    } | null;
    if (outcome?.success !== true) return false;
    if (expect.hostnames && !expect.hostnames.includes(outcome.hostname ?? "")) return false;
    if (expect.checkAction && action !== undefined && outcome.action !== action) return false;
    return true;
  };
}

/** The slice of a `ratelimits` binding this needs. */
export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** `rateLimit` over a Workers rate-limit binding. A limiter that errors lets
 * the request through: an outage there shouldn't lock everyone out. */
export function rateLimitBinding(binding: RateLimitBinding) {
  return async (key: string): Promise<boolean> => (await binding.limit({ key }).catch(() => ({ success: true }))).success;
}

function escape(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
}
