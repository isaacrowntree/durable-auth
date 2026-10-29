import { afterEach, describe, expect, it, vi } from "vitest";
import { turnstileVerifier } from "./integrations.js";
import { rateLimitSubject, sameOrigin } from "./auth.js";

function siteverify(outcome: Record<string, unknown>) {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json(outcome)));
}

afterEach(() => vi.unstubAllGlobals());

describe("turnstileVerifier", () => {
  it("passes a successful token and refuses a failed one", async () => {
    siteverify({ success: true });
    expect(await turnstileVerifier("s")("t", null, "signup")).toBe(true);
    siteverify({ success: false });
    expect(await turnstileVerifier("s")("t", null, "signup")).toBe(false);
  });

  // The same widget on another site, or a token from the other form.
  it("can insist on the site and the form the token was solved on", async () => {
    const verify = turnstileVerifier("s", { hostnames: ["app.test"], checkAction: true });
    siteverify({ success: true, hostname: "evil.test", action: "signup" });
    expect(await verify("t", null, "signup")).toBe(false);
    siteverify({ success: true, hostname: "app.test", action: "signup" });
    expect(await verify("t", null, "recover")).toBe(false);
    expect(await verify("t", null, "signup")).toBe(true);
  });
});

describe("sameOrigin", () => {
  const post = (headers: Record<string, string>) => new Request("https://app.test/api/x", { method: "POST", headers });

  it("lets reads through and refuses a write from elsewhere", () => {
    expect(sameOrigin(new Request("https://app.test/api/x"))).toBe(true);
    expect(sameOrigin(post({ origin: "https://app.test" }))).toBe(true);
    expect(sameOrigin(post({ origin: "https://evil.test" }))).toBe(false);
    expect(sameOrigin(post({ origin: "null" }))).toBe(false);
  });

  // No Origin at all: only the browser's own same-origin marker will do.
  it("needs Sec-Fetch-Site when there's no Origin", () => {
    expect(sameOrigin(post({}))).toBe(false);
    expect(sameOrigin(post({ "sec-fetch-site": "cross-site" }))).toBe(false);
    expect(sameOrigin(post({ "sec-fetch-site": "same-origin" }))).toBe(true);
  });

  it("takes a list of allowed origins", () => {
    expect(sameOrigin(post({ origin: "https://www.app.test" }), ["https://www.app.test"])).toBe(true);
  });
});

describe("rateLimitSubject", () => {
  it("keeps IPv4 as it is and folds IPv6 to its /64", () => {
    expect(rateLimitSubject("203.0.113.7")).toBe("203.0.113.7");
    expect(rateLimitSubject("2001:DB8:0a:b:1:2:3:4")).toBe("2001:db8:a:b::/64");
    expect(rateLimitSubject("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(rateLimitSubject("::1")).toBe("0:0:0:0::/64");
  });
});
