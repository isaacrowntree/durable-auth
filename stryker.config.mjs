/** Mutation testing: `npm run test:mutation`. Stryker changes auth.ts and
 * store.ts one small way at a time (a `>=` to `>`, a check deleted, a
 * `fail()` emptied) and runs the unit suite against each. A mutant the suite
 * doesn't notice is a rule nothing would stop someone breaking. Slow, so CI
 * runs it on a schedule (.github/workflows/mutation.yml), not on every push.
 *
 * @type {import("@stryker-mutator/api/core").PartialStrykerOptions} */
export default {
  mutate: ["src/server/auth.ts", "src/server/store.ts"],
  // The whole unit suite per mutant, as a command. @stryker-mutator/
  // vitest-runner would pick only the tests covering each mutant, but its
  // test-name filter ("suite test") doesn't match Vitest 5's ("suite > test"),
  // so every mutant ran no tests and "survived". Swap back once it does.
  testRunner: "command",
  commandRunner: { command: "npx vitest run --bail 1 --reporter dot" },
  coverageAnalysis: "off",
  // Stryker reads tsconfig.json through TypeScript's JS API to rewrite
  // `extends` and `references` for its sandbox. TypeScript 7 has no JS API,
  // and ours has neither, so point it at nothing. (The same is why there's no
  // TypeScript checker plugin.)
  tsconfigFile: "stryker-has-no-tsconfig.json",
  // Only what the unit suite needs goes in the sandbox.
  ignorePatterns: ["dist", "coverage", "docs", "e2e", "examples", ".wrangler", "test-results", "playwright-report"],
  reporters: ["clear-text", "progress", "html"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
  // break: CI fails under it. A few points under the score it last reached,
  // so a new route without tests trips it but one stray mutant doesn't.
  thresholds: { high: 95, low: 90, break: 88 },
};
