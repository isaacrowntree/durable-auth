// Bundles the page script (and @simplewebauthn/browser) for the browser, and
// gives a fresh checkout the local-only secrets in .dev.vars.
import { build } from "esbuild";
import { copyFileSync, existsSync } from "node:fs";

const devVars = new URL("./.dev.vars", import.meta.url).pathname;
if (!existsSync(devVars)) copyFileSync(new URL("./.dev.vars.example", import.meta.url).pathname, devVars);

await build({
  entryPoints: [new URL("./app.ts", import.meta.url).pathname],
  outfile: new URL("./public/app.js", import.meta.url).pathname,
  bundle: true,
  format: "esm",
  target: "es2022",
});
