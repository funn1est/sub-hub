import assert from "node:assert/strict";
import test from "node:test";

import {
  conversionRuntimeFromToml,
  tomlFlags,
  tomlString,
} from "./wrangler-contract.mjs";

test("conversionRuntimeFromToml reads date and flags", () => {
  const runtime = conversionRuntimeFromToml(`
name = "example"
compatibility_date = "2026-01-02"
compatibility_flags = [
  "alpha",
  "bravo",
]
`);
  assert.equal(runtime.compatibilityDate, "2026-01-02");
  assert.deepEqual(runtime.compatibilityFlags, ["alpha", "bravo"]);
});

test("toml helpers reject missing keys", () => {
  assert.throws(
    () => tomlString('name = "x"\n', "compatibility_date"),
    /missing compatibility_date/,
  );
  assert.throws(() => tomlFlags('name = "x"\n'), /missing compatibility_flags/);
});
