// Bundles the page script (and @simplewebauthn/browser) for the browser.
import { build } from "esbuild";

await build({
  entryPoints: [new URL("./app.ts", import.meta.url).pathname],
  outfile: new URL("./public/app.js", import.meta.url).pathname,
  bundle: true,
  format: "esm",
  target: "es2022",
});
