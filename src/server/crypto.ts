/** The secrets sign-in hands out, and the hashes it keeps instead.
 *
 * Session tokens are 256 random bits, so a plain SHA-256 is all the storage
 * needs: nobody brute-forces that space. Codes are only six digits, so a
 * plain hash of one is a million guesses from reversed: they're keyed with a
 * secret the store never sees. Online, what protects them is the attempt cap
 * in the store. */

export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** A random, unguessable account id. */
export function newAccountId(): string {
  return `u_${randomToken(16)}`;
}

/** Six uniform digits. Rejection-sampled: `n % 1e6` over a 32-bit value
 * would favour the low codes. */
export function sixDigitCode(): string {
  const limit = Math.floor(0xffffffff / 1_000_000) * 1_000_000;
  const buf = new Uint32Array(1);
  for (;;) {
    const [n] = crypto.getRandomValues(buf) as unknown as [number];
    if (n < limit) return String(n % 1_000_000).padStart(6, "0");
  }
}

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return base64url(new Uint8Array(digest));
}

/** The key codes are hashed under. It lives in a Worker secret, outside the
 * store, so a copy of the store alone can't try the million codes offline. */
export function codeKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
}

export async function hashCode(key: CryptoKey, email: string, purpose: string, code: string): Promise<string> {
  const text = `${purpose}:${email.trim().toLowerCase()}:${code.trim()}`;
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text))));
}

export function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
