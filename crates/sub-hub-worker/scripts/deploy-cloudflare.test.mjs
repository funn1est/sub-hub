import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

import {
  consoleDeployArgv,
  consoleIndexPath,
  conversionVarArgs,
  ensureDeployArgv,
  needsConsoleBuild,
  parseDeployArgv,
  parseLayout,
  parseWorkerOrigin,
  resolveDeployConfig,
  wranglerConfigArgs,
} from "./deploy-cloudflare.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

test("parseLayout accepts the three publish shapes", () => {
  assert.equal(parseLayout("all"), "all");
  assert.equal(parseLayout("worker"), "worker");
  assert.equal(parseLayout("console"), "console");
  assert.throws(() => parseLayout("stack"), /all, worker, or console/);
});

test("parseDeployArgv accepts token sources and forwards wrangler flags", () => {
  const parsed = parseDeployArgv([
    "--skip-build",
    "--worker-name",
    "other",
    "--from-env",
    "--preview-alias",
    "foo",
  ]);
  assert.equal(parsed.flags.skipBuild, true);
  assert.equal(parsed.flags.workerName, "other");
  assert.equal(parsed.flags.fromEnv, true);
  assert.equal(parsed.flags.layout, "all");
  assert.deepEqual(parsed.forwarded, ["--preview-alias", "foo"]);
  assert.equal(parseDeployArgv(["--name", "alias"]).flags.workerName, "alias");
  assert.throws(() => parseDeployArgv(["--tokens-file"]));
  assert.throws(() => parseDeployArgv(["--dev", "--preview"]));
});

test("parseDeployArgv accepts one layout and worker-only CORS", () => {
  assert.equal(parseDeployArgv(["--layout", "worker"]).flags.layout, "worker");
  assert.equal(parseDeployArgv(["--console-only"]).flags.layout, "console");
  assert.equal(
    parseDeployArgv(["--worker-only", "--cors-origin", "https://console.example"])
      .flags.corsOrigin,
    "https://console.example",
  );
  assert.throws(() => parseDeployArgv(["--all", "--worker-only"]));
  assert.throws(() => parseDeployArgv(["--layout", "nope"]));
  assert.throws(() =>
    parseDeployArgv(["--all", "--cors-origin", "https://console.example"]),
  );
  assert.throws(() => parseDeployArgv(["--console-only", "--tokens-file", "tokens.txt"]));
  assert.throws(() => parseDeployArgv(["--tokens", "alpha"]), /tokens-file or --from-env/);
  assert.equal(
    parseDeployArgv(["--layout", "console", "--name", "mine"]).flags.consoleName,
    "mine",
  );
});

test("resolveDeployConfig prefers flags then env then defaults", () => {
  const config = resolveDeployConfig({
    flags: { workerName: "flagged", layout: "worker" },
    env: { CLOUDFLARE_WORKER_NAME: "env-worker" },
    roots: { repoRoot: "/repo", workerRoot: "/repo/crates/sub-hub-worker" },
  });
  assert.equal(config.workerName, "flagged");
  assert.equal(config.layout, "worker");
  assert.equal(config.consoleDist, path.join("/repo", "apps", "console", "dist"));
  assert.equal(consoleIndexPath(config), path.join(config.consoleDist, "index.html"));
  assert.equal(needsConsoleBuild("all"), true);
  assert.equal(needsConsoleBuild("console"), true);
  assert.equal(needsConsoleBuild("worker"), false);

  const defaults = resolveDeployConfig({
    flags: {},
    env: {},
    roots: { repoRoot: "/repo", workerRoot: "/repo/crates/sub-hub-worker" },
  });
  assert.equal(defaults.workerName, undefined);
  assert.equal(defaults.layout, "all");
  assert.equal(defaults.dev, false);
  assert.equal(defaults.preview, false);
});

test("parseWorkerOrigin keeps the workers.dev origin", () => {
  assert.equal(
    parseWorkerOrigin("Published https://sub-hub.example.workers.dev"),
    "https://sub-hub.example.workers.dev",
  );
  assert.equal(parseWorkerOrigin("no urls"), null);
});

test("ensure argv stays explicit and does not write CORS on all", () => {
  assert.deepEqual(
    ensureDeployArgv({ layout: "all", fromEnv: true, workerName: "other" }),
    ["--deploy", "--from-env", "--name", "other"],
  );
  assert.deepEqual(
    ensureDeployArgv(
      { layout: "all", tokensFile: "tokens.txt", preview: true },
      ["--preview-alias", "foo"],
    ),
    ["--preview", "--tokens-file", "tokens.txt", "--preview-alias", "foo"],
  );
  assert.throws(
    () =>
      ensureDeployArgv({ layout: "all", tokensFile: "tokens.txt", fromEnv: true }),
    /only one/,
  );
  const ensureFromFile = ensureDeployArgv({
    layout: "all",
    tokensFile: "tokens.txt",
    fromEnv: false,
  });
  assert.deepEqual(ensureFromFile, ["--deploy", "--tokens-file", "tokens.txt"]);
  assert.ok(!ensureFromFile.includes("--tokens"));
  assert.ok(!ensureFromFile.includes("alpha"));
  assert.ok(!ensureFromFile.includes("bravo"));
  assert.ok(!ensureFromFile.includes("deployer-token"));
  const serialized = JSON.stringify(ensureFromFile);
  assert.equal(serialized.includes("CORS"), false);
  assert.equal(serialized.includes("SELF_HOSTS"), false);
  assert.throws(() => ensureDeployArgv({ layout: "console" }));
});

test("worker layout uses wrangler.worker.toml and optional CORS var", () => {
  const config = {
    layout: "worker",
    corsOrigin: "https://sub-hub-console.example.workers.dev",
  };
  assert.deepEqual(wranglerConfigArgs(config), [
    "--config",
    "wrangler.worker.toml",
  ]);
  assert.deepEqual(conversionVarArgs(config), [
    "--var",
    "SUB_HUB_CORS_ORIGINS:https://sub-hub-console.example.workers.dev",
  ]);
  assert.deepEqual(ensureDeployArgv(config), [
    "--deploy",
    "--config",
    "wrangler.worker.toml",
    "--var",
    "SUB_HUB_CORS_ORIGINS:https://sub-hub-console.example.workers.dev",
  ]);
  assert.deepEqual(conversionVarArgs({ layout: "all" }), []);
});

test("console layout deploys apps/console wrangler without a token put", () => {
  const config = {
    layout: "console",
    consoleWrangler: "/repo/apps/console/wrangler.toml",
    consoleName: "mine",
    preview: false,
  };
  assert.deepEqual(consoleDeployArgv(config), [
    "deploy",
    "--keep-vars",
    "--config",
    "/repo/apps/console/wrangler.toml",
    "--name",
    "mine",
  ]);
  assert.deepEqual(consoleDeployArgv({ ...config, preview: true, consoleName: undefined }), [
    "versions",
    "upload",
    "--keep-vars",
    "--config",
    "/repo/apps/console/wrangler.toml",
  ]);
});

test("all and worker wrangler configs share identity; only all has assets", () => {
  const allToml = fs.readFileSync(path.join(here, "..", "wrangler.toml"), "utf8");
  const workerOnly = fs.readFileSync(
    path.join(here, "..", "wrangler.worker.toml"),
    "utf8",
  );
  const name = /^name = "([^"]+)"/m;
  const date = /^compatibility_date = "([^"]+)"/m;
  assert.equal(allToml.match(name)[1], workerOnly.match(name)[1]);
  assert.equal(allToml.match(date)[1], workerOnly.match(date)[1]);
  assert.match(allToml, /directory = "\.\.\/\.\.\/apps\/console\/dist"/);
  assert.match(allToml, /not_found_handling = "single-page-application"/);
  assert.match(allToml, /run_worker_first = \["\/version", "\/sub", "\/sub\/\*"\]/);
  assert.doesNotMatch(workerOnly, /\[assets\]/);
  assert.doesNotMatch(allToml, /SUB_HUB_CORS_ORIGINS/);
  assert.doesNotMatch(allToml, /SUB_HUB_SELF_HOSTS/);
});

test("Workers Logs stay on without recording GET URLs", () => {
  const files = [
    path.join(here, "..", "wrangler.toml"),
    path.join(here, "..", "wrangler.worker.toml"),
    path.join(here, "..", "..", "..", "apps", "console", "wrangler.toml"),
  ];
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    assert.match(text, /^\[observability\]$/m);
    assert.match(text, /^enabled = true$/m);
    assert.match(text, /^\[observability\.logs\]$/m);
    assert.match(text, /^invocation_logs = false$/m);
  }
});

test("compressed Wasm fits Workers Free 3 MB gzip", () => {
  const wasm = path.join(here, "..", "build", "index_bg.wasm");
  if (!fs.existsSync(wasm)) {
    if (process.env.CI) {
      assert.fail("CI must build index_bg.wasm before the gzip gate");
    }
    return;
  }
  const gzip = zlib.gzipSync(fs.readFileSync(wasm), { level: 9 });
  assert.ok(
    gzip.length < 3 * 1024 * 1024,
    `gzip ${gzip.length} bytes must stay under 3 MiB`,
  );
});
