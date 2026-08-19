import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  DEFAULT_PAGES_PROJECT,
  DEFAULT_PRODUCTION_BRANCH,
  ensureDeployArgv,
  hostnameFromHttpsUrl,
  interpretProjectCreate,
  joinBindingList,
  needsSelfHostsFollowUp,
  pagesProjectExists,
  parsePagesProductionOrigin,
  parseStackArgv,
  parseWorkerOrigin,
  resolveConsoleOrigin,
  resolveStackConfig,
  workerVarArgs,
} from "./deploy-cloudflare.mjs";

test("parseStackArgv accepts stack flags and token sources", () => {
  const flags = parseStackArgv([
    "--skip-build",
    "--pages-project",
    "mine",
    "--worker-name",
    "other",
    "--from-env",
  ]);
  assert.equal(flags.skipBuild, true);
  assert.equal(flags.pagesProject, "mine");
  assert.equal(flags.workerName, "other");
  assert.equal(flags.fromEnv, true);
  assert.throws(() => parseStackArgv(["--pages-project"]));
  assert.throws(() => parseStackArgv(["--unknown"]));
});

test("resolveStackConfig prefers flags then env then defaults", () => {
  const config = resolveStackConfig({
    flags: { pagesProject: "flagged" },
    env: {
      CLOUDFLARE_PAGES_PROJECT: "env-project",
      CLOUDFLARE_WORKER_NAME: "env-worker",
      GITHUB_SHA: "abc123",
    },
    roots: { repoRoot: "/repo", workerRoot: "/repo/crates/sub-hub-worker" },
  });
  assert.equal(config.pagesProject, "flagged");
  assert.equal(config.workerName, "env-worker");
  assert.equal(config.branch, DEFAULT_PRODUCTION_BRANCH);
  assert.equal(config.commitHash, "abc123");
  assert.equal(config.consoleDist, path.join("/repo", "apps", "console", "dist"));

  const defaults = resolveStackConfig({
    flags: {},
    env: {},
    roots: { repoRoot: "/repo", workerRoot: "/repo/crates/sub-hub-worker" },
  });
  assert.equal(defaults.pagesProject, DEFAULT_PAGES_PROJECT);
  assert.equal(defaults.workerName, undefined);
});

test("parsePagesProductionOrigin ignores preview hashes", () => {
  assert.equal(
    parsePagesProductionOrigin(
      "Preview https://deadbeef.sub-hub-console.pages.dev\nLive https://sub-hub-console.pages.dev/\n",
    ),
    "https://sub-hub-console.pages.dev",
  );
  assert.equal(parsePagesProductionOrigin("no urls"), null);
  assert.equal(
    resolveConsoleOrigin("only https://aaaa.mine.pages.dev", "mine"),
    "https://mine.pages.dev",
  );
});

test("parseWorkerOrigin and hostnameFromHttpsUrl keep the workers.dev host", () => {
  assert.equal(
    parseWorkerOrigin("Published https://sub-hub.example.workers.dev"),
    "https://sub-hub.example.workers.dev",
  );
  assert.equal(
    hostnameFromHttpsUrl("https://sub-hub.example.workers.dev/"),
    "sub-hub.example.workers.dev",
  );
  assert.equal(hostnameFromHttpsUrl("http://example"), null);
});

test("joinBindingList and workerVarArgs skip empties and keep order", () => {
  assert.equal(
    joinBindingList(["https://a.pages.dev", "https://b.example,https://a.pages.dev", ""]),
    "https://a.pages.dev,https://b.example",
  );
  assert.deepEqual(
    workerVarArgs({
      corsOrigins: "https://a.pages.dev",
      selfHosts: "sub-hub.example.workers.dev",
    }),
    [
      "--var",
      "SUB_HUB_CORS_ORIGINS:https://a.pages.dev",
      "--var",
      "SUB_HUB_SELF_HOSTS:sub-hub.example.workers.dev",
    ],
  );
  assert.deepEqual(workerVarArgs({}), []);
});

test("pages project helpers are fail-closed unless JSON names match", () => {
  assert.equal(interpretProjectCreate(0, "", ""), "created");
  assert.equal(
    interpretProjectCreate(1, "", "A project with this name already exists"),
    "exists",
  );
  assert.equal(interpretProjectCreate(1, "", "auth error"), "failed");
  assert.equal(
    pagesProjectExists(
      '[{"name":"sub-hub-console","subdomain":"sub-hub-console.pages.dev"}]',
      "sub-hub-console",
    ),
    true,
  );
  assert.equal(pagesProjectExists("not json", "sub-hub-console"), false);
});

test("needsSelfHostsFollowUp only when the published host is missing", () => {
  assert.equal(needsSelfHostsFollowUp("", "sub-hub.example.workers.dev"), true);
  assert.equal(
    needsSelfHostsFollowUp(
      "alias.example,sub-hub.example.workers.dev",
      "sub-hub.example.workers.dev",
    ),
    false,
  );
  assert.equal(needsSelfHostsFollowUp("alias.example", ""), false);
});

test("ensure argv stays explicit", () => {
  assert.deepEqual(
    ensureDeployArgv(
      { fromEnv: false, workerName: "other" },
      { hasAccessToken: true },
    ),
    ["--deploy", "--from-env", "--name", "other"],
  );
  assert.deepEqual(
    ensureDeployArgv({ tokensFile: "tokens.txt" }, { hasAccessToken: false }),
    ["--deploy", "--tokens-file", "tokens.txt"],
  );
  assert.throws(
    () =>
      ensureDeployArgv(
        { tokens: "alpha", fromEnv: true },
        { hasAccessToken: true },
      ),
    /only one/,
  );
  assert.deepEqual(
    ensureDeployArgv({ tokens: "alpha" }, { hasAccessToken: true }),
    ["--deploy", "--tokens", "alpha"],
  );
});
