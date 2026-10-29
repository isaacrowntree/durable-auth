import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Published as plain ESM: every relative import needs its extension, or
 * anything but a bundler fails to resolve it. */
describe("relative imports", () => {
  it("all name their .js file", () => {
    const root = join(__dirname);
    const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));
    const bare = files.flatMap((f) =>
      [...readFileSync(join(root, f), "utf8").matchAll(/from\s+"(\.\.?\/[^"]+)"/g)]
        .map((m) => m[1]!)
        .filter((spec) => !spec.endsWith(".js"))
        .map((spec) => `${f}: ${spec}`),
    );
    expect(bare).toEqual([]);
  });
});
