import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ZERO_SHA,
  decideNativeRelease,
  parseBool,
  parseGateArgv,
  writeGateOutput,
} from "./native-release-gate.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

test("parseGateArgv requires the release event fields", () => {
  assert.deepEqual(
    parseGateArgv([
      "--event",
      "push",
      "--ref-type",
      "branch",
      "--ref-name",
      "main",
      "--current",
      "0.2.1",
      "--previous",
      "0.2.0",
      "--release-exists",
      "false",
    ]),
    {
      eventName: "push",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.1",
      previousVersion: "0.2.0",
      releaseExists: false,
    },
  );
  assert.equal(parseBool("true"), true);
  assert.equal(parseBool("false"), false);
  assert.throws(() => parseBool("yes"), /true or false/);
  assert.throws(() => parseGateArgv(["--help"]), /usage:/);
  assert.throws(
    () =>
      parseGateArgv([
        "--event",
        "push",
        "--ref-type",
        "branch",
        "--ref-name",
        "main",
        "--current",
        "0.2.1",
        "--release-exists",
        "false",
        "--wat",
        "x",
      ]),
    /unknown flag/,
  );
});

test("decideNativeRelease publishes a main push when the workspace version changes", () => {
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.1",
      previousVersion: "0.2.0",
      releaseExists: false,
    }),
    { publish: true, version: "0.2.1", reason: "version changed" },
  );
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.1",
      previousVersion: "0.2.1",
      releaseExists: false,
    }),
    { publish: false, version: "0.2.1", reason: "version unchanged" },
  );
});

test("decideNativeRelease skips when that GitHub Release already exists", () => {
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.1",
      previousVersion: "0.2.0",
      releaseExists: true,
    }),
    { publish: false, version: "0.2.1", reason: "release exists" },
  );
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "tag",
      refName: "v0.2.1",
      currentVersion: "0.2.1",
      previousVersion: "",
      releaseExists: true,
    }),
    { publish: false, version: "0.2.1", reason: "release exists" },
  );
});

test("decideNativeRelease publishes a matching tag or dispatch when the release is missing", () => {
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "tag",
      refName: "v0.2.1",
      currentVersion: "0.2.1",
      previousVersion: "",
      releaseExists: false,
    }),
    { publish: true, version: "0.2.1", reason: "tag" },
  );
  assert.throws(
    () =>
      decideNativeRelease({
        eventName: "push",
        refType: "tag",
        refName: "v0.2.0",
        currentVersion: "0.2.1",
        previousVersion: "",
        releaseExists: false,
      }),
    /does not match/,
  );
  assert.deepEqual(
    decideNativeRelease({
      eventName: "workflow_dispatch",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.1",
      previousVersion: "0.2.1",
      releaseExists: false,
    }),
    { publish: true, version: "0.2.1", reason: "dispatch" },
  );
});

test("decideNativeRelease treats a missing previous version as a publish on main", () => {
  assert.equal(ZERO_SHA.length, 40);
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "branch",
      refName: "main",
      currentVersion: "0.2.0",
      previousVersion: "",
      releaseExists: false,
    }),
    { publish: true, version: "0.2.0", reason: "no previous version" },
  );
  assert.deepEqual(
    decideNativeRelease({
      eventName: "push",
      refType: "branch",
      refName: "topic",
      currentVersion: "0.2.1",
      previousVersion: "0.2.0",
      releaseExists: false,
    }),
    { publish: false, version: "0.2.1", reason: "not a release event" },
  );
});

test("writeGateOutput records publish for GitHub Actions", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "native-release-gate-"));
  try {
    const githubOutput = path.join(dir, "output");
    const chunks = [];
    writeGateOutput(
      { publish: true, version: "0.2.1", reason: "version changed" },
      {
        githubOutput,
        stdout: { write: (text) => chunks.push(text) },
      },
    );
    assert.equal(chunks.join(""), "publish version changed\n");
    assert.equal(
      fs.readFileSync(githubOutput, "utf8"),
      "publish=true\nversion=0.2.1\nreason=version changed\n",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("native-release-gate CLI writes GITHUB_OUTPUT", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "native-release-gate-cli-"));
  try {
    const githubOutput = path.join(dir, "output");
    const result = spawnSync(
      process.execPath,
      [
        path.join(here, "native-release-gate.mjs"),
        "--event",
        "push",
        "--ref-type",
        "branch",
        "--ref-name",
        "main",
        "--current",
        "0.2.1",
        "--previous",
        "0.2.0",
        "--release-exists",
        "false",
      ],
      {
        encoding: "utf8",
        env: { ...process.env, GITHUB_OUTPUT: githubOutput },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "publish version changed\n");
    assert.match(fs.readFileSync(githubOutput, "utf8"), /publish=true/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Native release workflow publishes from a main version bump", () => {
  const workflow = fs.readFileSync(
    path.join(here, "..", ".github", "workflows", "native-release.yml"),
    "utf8",
  );
  assert.match(workflow, /branches:\r?\n\s+- main/);
  assert.match(workflow, /scripts\/native-release-gate\.mjs/);
  assert.match(workflow, /workspace-version\.mjs --stdin/);
  assert.match(workflow, /needs\.gate\.outputs\.publish == 'true'/);
  assert.match(workflow, /--target "\$GITHUB_SHA"/);
  assert.doesNotMatch(
    workflow,
    /github\.event_name == 'push' && github\.ref_type == 'tag'/,
  );
});
