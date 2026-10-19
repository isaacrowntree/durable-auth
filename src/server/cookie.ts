/** The session cookie.
 *
 * HttpOnly so no script can read it, SameSite=Lax so another site can't post
 * with it, and `__Host-` and Secure so it can only ever be set by this origin,
 * over HTTPS. Plain http://localhost can't hold a `__Host-` cookie in every
 * browser, so there — and only there — the prefix and the flag are dropped.
 * It's decided per request, so there's no "dev mode" to forget to turn off;
 * any other plain-http host gets a Secure cookie the browser won't keep. */

/** Re-sent on every session check, so the browser's own expiry slides along
 * with the server's (browsers cap cookies at 400 days). */
const MAX_AGE_S = 400 * 24 * 60 * 60;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class SessionCookie {
  constructor(private readonly name: string) {}

  private secure(req: Request): boolean {
    const url = new URL(req.url);
    return !(url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname));
  }

  private fullName(req: Request): string {
    return this.secure(req) ? `__Host-${this.name}` : this.name;
  }

  set(req: Request, token: string): string {
    return `${this.fullName(req)}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${MAX_AGE_S}${this.secure(req) ? "; Secure" : ""}`;
  }

  clear(req: Request): string {
    return `${this.fullName(req)}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${this.secure(req) ? "; Secure" : ""}`;
  }

  read(req: Request): string | null {
    const header = req.headers.get("cookie");
    if (!header) return null;
    const name = this.fullName(req);
    for (const part of header.split(";")) {
      const eq = part.indexOf("=");
      if (eq < 0) continue;
      if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim() || null;
    }
    return null;
  }
}
