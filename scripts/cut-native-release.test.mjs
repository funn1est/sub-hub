import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { cutNativeRelease, parseCutArgv, runGit } from "./cut-native-release.mjs";
import { readWorkspaceVersion } from "./workspace-version.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

function git(cwd, args) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
  if ((result.status ?? 1) !== 0) {
    throw new Error((result.stderr || result.stdout || `git ${args.join(" ")}`).trim());
  }
  return (result.stdout || "").trim();
}

function writeTree(work) {
  fs.mkdirSync(path.join(work, "apps", "console"), { recursive: true });
  fs.writeFileSync(
    path.join(work, "Cargo.toml"),
    `[workspace]
members = ["crates/sub-hub-http"]

[workspace.package]
version = "0.1.0"
rust-version = "1.97.1"
`,
  );
  fs.writeFileSync(
    path.join(work, "Cargo.lock"),
    `[[package]]
name = "sub-hub-http"
version = "0.1.0"

[[package]]
name = "unrelated"
version = "0.1.0"
`,
  );
  fs.writeFileSync(
    path.join(work, "apps", "console", "package.json"),
    `{
  "name": "@sub-hub/console",
  "version": "0.1.0"
}
`,
  );
}

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cut-native-release-"));
  const origin = path.join(root, "origin.git");
  const work = path.join(root, "work");
  fs.mkdirSync(origin);
  git(origin, ["init", "--bare", "-b", "main"]);
  fs.mkdirSync(work);
  git(work, ["init", "-b", "main"]);
  git(work, ["config", "user.email", "dev@example"]);
  git(work, ["config", "user.name", "Dev"]);
  git(work, ["config", "commit.gpgsign", "false"]);
  git(work, ["config", "tag.gpgsign", "false"]);
  git(work, ["remote", "add", "origin", origin]);
  writeTree(work);
  git(work, ["add", "-A"]);
  git(work, ["commit", "-m", "seed"]);
  git(work, ["push", "-u", "origin", "main"]);
  return { root, origin, work };
}

test("parseCutArgv omits version for a patch bump and accepts dry-run no-push no-fetch", () => {
  assert.deepEqual(parseCutArgv([]), {
    version: undefined,
    dryRun: false,
    push: true,
    fetch: true,
  });
  assert.deepEqual(parseCutArgv(["0.2.0"]), {
    version: "0.2.0",
    dryRun: false,
    push: true,
    fetch: true,
  });
  assert.deepEqual(parseCutArgv(["--dry-run", "--no-push", "--no-fetch"]), {
    version: undefined,
    dryRun: true,
    push: false,
    fetch: false,
  });
  assert.throws(() => parseCutArgv(["v0.2.0"]), /X\.Y\.Z/);
  assert.throws(() => parseCutArgv(["0.2.0", "--wat"]), /unknown flag/);
});

test("cutNativeRelease dry-run does not commit or tag", () => {
  const { root, work } = makeRepo();
  try {
    const head = git(work, ["rev-parse", "HEAD"]);
    const plan = cutNativeRelease({
      root: work,
      version: "0.2.0",
      dryRun: true,
    });
    assert.equal(plan.tag, "v0.2.0");
    assert.equal(git(work, ["rev-parse", "HEAD"]), head);
    assert.equal(readWorkspaceVersion(fs.readFileSync(path.join(work, "Cargo.toml"), "utf8")), "0.1.0");
    const tags = spawnSync("git", ["show-ref", "--verify", "--quiet", "refs/tags/v0.2.0"], {
      cwd: work,
    });
    assert.notEqual(tags.status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("cutNativeRelease without a version patches the workspace version", () => {
  const { root, origin, work } = makeRepo();
  try {
    const plan = cutNativeRelease({ root: work });
    assert.equal(plan.current, "0.1.0");
    assert.equal(plan.version, "0.1.1");
    assert.equal(plan.tag, "v0.1.1");
    assert.equal(
      readWorkspaceVersion(fs.readFileSync(path.join(work, "Cargo.toml"), "utf8")),
      "0.1.1",
    );
    assert.equal(git(origin, ["tag", "-l", "v0.1.1"]), "v0.1.1");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("cutNativeRelease commits, tags, and pushes the version bump", () => {
  const { root, origin, work } = makeRepo();
  try {
    const plan = cutNativeRelease({
      root: work,
      version: "0.2.0",
    });
    assert.equal(plan.tag, "v0.2.0");
    assert.equal(
      readWorkspaceVersion(fs.readFileSync(path.join(work, "Cargo.toml"), "utf8")),
      "0.2.0",
    );
    assert.match(
      fs.readFileSync(path.join(work, "Cargo.lock"), "utf8"),
      /name = "sub-hub-http"\nversion = "0\.2\.0"/,
    );
    assert.match(
      fs.readFileSync(path.join(work, "Cargo.lock"), "utf8"),
      /name = "unrelated"\nversion = "0\.1\.0"/,
    );
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(work, "apps", "console", "package.json"), "utf8"))
        .version,
      "0.2.0",
    );
    assert.equal(git(work, ["log", "-1", "--format=%s"]), "chore: release v0.2.0");
    assert.equal(git(work, ["tag", "-l", "v0.2.0"]), "v0.2.0");
    assert.equal(git(origin, ["log", "-1", "--format=%s"]), "chore: release v0.2.0");
    assert.equal(git(origin, ["tag", "-l", "v0.2.0"]), "v0.2.0");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("cutNativeRelease refuses a dirty tree, a side branch, and a live tag", () => {
  const { root, work } = makeRepo();
  try {
    fs.writeFileSync(path.join(work, "dirty.txt"), "nope");
    assert.throws(
      () => cutNativeRelease({ root: work, version: "0.2.0" }),
      /not clean/,
    );
    fs.rmSync(path.join(work, "dirty.txt"));

    git(work, ["checkout", "-b", "topic"]);
    assert.throws(
      () => cutNativeRelease({ root: work, version: "0.2.0" }),
      /from main/,
    );
    git(work, ["checkout", "main"]);

    git(work, ["tag", "-a", "v0.2.0", "-m", "v0.2.0"]);
    assert.throws(
      () => cutNativeRelease({ root: work, version: "0.2.0" }),
      /already exists locally/,
    );
    git(work, ["tag", "-d", "v0.2.0"]);

    cutNativeRelease({ root: work, version: "0.2.0", push: false });
    assert.throws(
      () => cutNativeRelease({ root: work, version: "0.2.1", push: false, fetch: false }),
      /not origin\/main/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runGit is the default git runner", () => {
  assert.equal(typeof runGit, "function");
  const help = spawnSync(
    process.execPath,
    [path.join(here, "cut-native-release.mjs"), "--help"],
    { encoding: "utf8" },
  );
  assert.equal(help.status, 1);
  assert.match(help.stderr, /usage:/);
});
