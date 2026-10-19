/** The session cookie.
 *
 * HttpOnly so no script can read it, SameSite=Lax so another site can't post
 * with it, and `__Host-` over HTTPS so it can only ever be set by this origin.
 * Plain http://localhost can't hold a `__Host-` cookie in every browser, so
 * there the prefix and the Secure flag are dropped — decided per request, by
 * the request's own scheme, so there's no "dev mode" to forget to turn off. */

/** Re-sent on every session check, so the browser's own expiry slides along
 * with the server's (browsers cap cookies at 400 days). */
const MAX_AGE_S = 400 * 24 * 60 * 60;

export class SessionCookie {
  constructor(private readonly name: string) {}

  private secure(req: Request): boolean {
    return new URL(req.url).protocol === "https:";
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
