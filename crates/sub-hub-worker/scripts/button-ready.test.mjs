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

function tomlString(text, key) {
  const match = text.match(new RegExp(`^${key} = "([^"]+)"`, "m"));
  assert.ok(match, `missing ${key}`);
  return match[1];
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
  assert.equal(pkg.scripts.release, "node scripts/cut-native-release.mjs");
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  const description = pkg.cloudflare?.bindings?.SUB_HUB_ACCESS_TOKEN?.description;
  assert.equal(typeof description, "string");
  assert.match(description, /secret/i);
  assert.match(description, /1–128|1-128/);
  assert.doesNotMatch(description, /\.dev\.vars\.example/);
});

test("repository-root wrangler.toml is the Deploy-to-Cloudflare contract", () => {
  const rootToml = readUtf8(path.join(repoRoot, "wrangler.toml"));
  const crateToml = readUtf8(path.join(workerRoot, "wrangler.toml"));
  assert.equal(tomlString(rootToml, "name"), "sub-hub");
  assert.equal(tomlString(rootToml, "name"), tomlString(crateToml, "name"));
  assert.equal(
    tomlString(rootToml, "compatibility_date"),
    tomlString(crateToml, "compatibility_date"),
  );
  assert.match(rootToml, /global_fetch_strictly_public/);
  assert.match(rootToml, /crates\/sub-hub-worker\/build\/worker/);
  assert.match(rootToml, /apps\/console\/dist/);
  assert.match(rootToml, /run_worker_first = \["\/version", "\/sub", "\/sub\/\*"\]/);
  assert.match(rootToml, /cd crates\/sub-hub-worker && worker-build --release/);
  const bindings = rootToml
    .split(/\r?\n/)
    .filter((line) => !/^\s*(#|$)/.test(line))
    .join("\n");
  assert.doesNotMatch(bindings, /account_id/);
  assert.doesNotMatch(bindings, /kv_namespaces|d1_databases|r2_buckets|secrets_store/i);
  assert.equal(fs.existsSync(path.join(repoRoot, "wrangler.json")), false);
  assert.equal(fs.existsSync(path.join(repoRoot, "wrangler.jsonc")), false);
});

test("Worker package.json keeps the local CI-refusing deploy helper", () => {
  const pkg = JSON.parse(readUtf8(path.join(workerRoot, "package.json")));
  assert.equal(pkg.scripts.deploy, "node scripts/deploy-cloudflare.mjs");
  assert.equal(pkg.scripts.build, "worker-build --release");
});

test("crate gitignore keeps .dev.vars and worker-build output off origin", () => {
  const ignore = readUtf8(path.join(workerRoot, ".gitignore"));
  assert.match(ignore, /^\.dev\.vars$/m);
  assert.match(ignore, /^build\/$/m);
});

test("access-token example is button schema, not a secret put", () => {
  const rootExample = readUtf8(path.join(repoRoot, ".dev.vars.example"));
  const crateExample = readUtf8(path.join(workerRoot, ".dev.vars.example"));
  assert.match(rootExample, /^SUB_HUB_ACCESS_TOKEN=$/m);
  assert.match(crateExample, /^SUB_HUB_ACCESS_TOKEN=$/m);
  assert.doesNotMatch(rootExample, /^SUB_HUB_ACCESS_TOKEN=./m);
  assert.doesNotMatch(crateExample, /^SUB_HUB_ACCESS_TOKEN=./m);
  const ensure = readUtf8(path.join(here, "ensure-access-token.mjs"));
  const buildsDeploy = readUtf8(path.join(here, "workers-builds-deploy.sh"));
  const localDeploy = readUtf8(path.join(here, "deploy-cloudflare.mjs"));
  assert.doesNotMatch(ensure, /\.dev\.vars\.example/);
  assert.doesNotMatch(buildsDeploy, /\.dev\.vars/);
  assert.doesNotMatch(localDeploy, /\.dev\.vars\.example/);
});
