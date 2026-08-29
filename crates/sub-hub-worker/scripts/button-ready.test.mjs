import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const workerRoot = path.join(here, "..");
const repoRoot = path.join(workerRoot, "..", "..");

function readUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

test("repository-root package.json pre-populates C1 Workers Builds commands", () => {
  const pkg = JSON.parse(readUtf8(path.join(repoRoot, "package.json")));
  assert.equal(pkg.private, true);
  assert.equal(
    pkg.scripts.build,
    "sh crates/sub-hub-worker/scripts/install-workers-toolchain.sh",
  );
  assert.equal(
    pkg.scripts.deploy,
    "sh crates/sub-hub-worker/scripts/workers-builds-deploy.sh",
  );
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  const description = pkg.cloudflare?.bindings?.SUB_HUB_ACCESS_TOKEN?.description;
  assert.equal(typeof description, "string");
  assert.match(description, /secret/i);
  assert.match(description, /\.dev\.vars\.example/);
  assert.equal(fs.existsSync(path.join(repoRoot, "wrangler.toml")), false);
  assert.equal(fs.existsSync(path.join(repoRoot, "wrangler.json")), false);
  assert.equal(fs.existsSync(path.join(repoRoot, "wrangler.jsonc")), false);
});

test("Worker package.json keeps the local CI-refusing deploy helper", () => {
  const pkg = JSON.parse(readUtf8(path.join(workerRoot, "package.json")));
  assert.equal(pkg.scripts.deploy, "node scripts/deploy-cloudflare.mjs");
  assert.equal(pkg.scripts.build, "worker-build --release");
});

test("access-token example is button schema, not a secret put", () => {
  const example = readUtf8(path.join(workerRoot, ".dev.vars.example"));
  assert.match(example, /^SUB_HUB_ACCESS_TOKEN=$/m);
  assert.doesNotMatch(example, /^SUB_HUB_ACCESS_TOKEN=./m);
  const ensure = readUtf8(path.join(here, "ensure-access-token.mjs"));
  const buildsDeploy = readUtf8(path.join(here, "workers-builds-deploy.sh"));
  const localDeploy = readUtf8(path.join(here, "deploy-cloudflare.mjs"));
  assert.doesNotMatch(ensure, /\.dev\.vars\.example/);
  assert.doesNotMatch(buildsDeploy, /\.dev\.vars/);
  assert.doesNotMatch(localDeploy, /\.dev\.vars\.example/);
});
