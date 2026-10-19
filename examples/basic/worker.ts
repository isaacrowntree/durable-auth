/** A complete app on durable-auth: passkey sign-up and sign-in, recovery by
 * email, and one route of the app's own that needs a signed-in user. */

import {
  AuthDurableObject,
  cloudflareEmail,
  createAuth,
  rateLimitBinding,
  type EmailBinding,
  type RateLimitBinding,
} from "../../src/server/index";

export class Auth extends AuthDurableObject {}

interface Env {
  AUTH: DurableObjectNamespace<Auth>;
  EMAIL: EmailBinding;
  EMAIL_FROM: string;
  AUTH_LIMITER: RateLimitBinding;
  /** Only the end-to-end suite sets this, to make step-up testable. */
  REAUTH_WINDOW_MS?: string;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const auth = createAuth({
      store: env.AUTH,
      rpName: "durable-auth example",
      sendCode: cloudflareEmail(env.EMAIL, { from: env.EMAIL_FROM, appName: "durable-auth example" }),
      rateLimit: rateLimitBinding(env.AUTH_LIMITER),
      waitUntil: (work) => ctx.waitUntil(work),
      reauthWindowMs: env.REAUTH_WINDOW_MS ? Number(env.REAUTH_WINDOW_MS) : undefined,
    });

    const handled = await auth.handle(req);
    if (handled) return handled;

    // The app's own API: a signed-in user, or 401.
    if (new URL(req.url).pathname === "/api/hello") {
      const account = await auth.account(req);
      if (!account) return Response.json({ error: "Not signed in" }, { status: 401 });
      return Response.json({ message: `Hello, ${account.name}` });
    }
    return new Response("Not found", { status: 404 });
  },
};
