import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..", "..", "..");

function assignment(script, name) {
  const match = script.match(new RegExp(`^${name}=(\\S+)`, "m"));
  assert.ok(match, `missing ${name}`);
  return match[1];
}

test("Workers Builds toolchain pins match the workspace", () => {
  const script = fs.readFileSync(
    path.join(here, "install-workers-toolchain.sh"),
    "utf8",
  );
  const mise = fs.readFileSync(path.join(repoRoot, "mise.toml"), "utf8");
  const toolchain = fs.readFileSync(
    path.join(repoRoot, "rust-toolchain.toml"),
    "utf8",
  );
  const rust = assignment(script, "RUST_TOOLCHAIN");
  const workerBuild = assignment(script, "WORKER_BUILD_VERSION");

  assert.equal(rust, "1.97.1");
  assert.equal(assignment(script, "WASM_TARGET"), "wasm32-unknown-unknown");
  assert.equal(workerBuild, "0.8.5");
  assert.match(mise, new RegExp(`version = "${rust}"`));
  assert.match(toolchain, new RegExp(`channel = "${rust}"`));
  assert.match(script, /pnpm install --frozen-lockfile/);
  const commands = script
    .split(/\r?\n/)
    .filter((line) => !/^\s*(#|$)/.test(line))
    .join("\n");
  assert.doesNotMatch(commands, /pnpm run deploy/);
});

test("Workers Builds deploy helper keeps vars and skips token ensure", () => {
  const script = fs.readFileSync(
    path.join(here, "workers-builds-deploy.sh"),
    "utf8",
  );
  assert.match(script, /wrangler deploy --keep-vars/);
  assert.match(script, /wrangler versions upload --keep-vars/);
  assert.match(script, /install-workers-toolchain\.sh/);
  assert.doesNotMatch(script, /ensure-access-token/);
  assert.doesNotMatch(script, /pnpm run deploy/);
});
