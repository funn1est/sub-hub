import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  compareSemver,
  nextPatchVersion,
  outboundUserAgent,
  parseSemver,
  planWorkspaceRelease,
  readWorkspaceVersion,
  setWorkspaceVersion,
  versionBody,
  workspacePackageNames,
} from "./workspace-version.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");

const FIXTURE_TOML = `[workspace]
members = [
    "crates/sub-hub-conversion",
    "crates/sub-hub-http",
]
resolver = "3"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "AGPL-3.0-or-later"
rust-version = "1.97.1"

[workspace.dependencies]
http = "=1.3.1"
`;

const FIXTURE_LOCK = `[[package]]
name = "http"
version = "1.3.1"

[[package]]
name = "sub-hub-conversion"
version = "0.1.0"

[[package]]
name = "sub-hub-http"
version = "0.1.0"

[[package]]
name = "unrelated"
version = "0.1.0"
`;

const FIXTURE_CONSOLE = `{
  "name": "@sub-hub/console",
  "private": true,
  "version": "0.1.0",
  "type": "module"
}
`;

test("parseSemver accepts X.Y.Z and rejects a v prefix or prerelease", () => {
  assert.deepEqual(parseSemver("0.2.0"), {
    raw: "0.2.0",
    major: 0,
    minor: 2,
    patch: 0,
  });
  assert.throws(() => parseSemver("v0.2.0"), /X\.Y\.Z/);
  assert.throws(() => parseSemver("0.2"), /X\.Y\.Z/);
  assert.throws(() => parseSemver("0.2.0-rc.1"), /X\.Y\.Z/);
  assert.throws(() => parseSemver("01.0.0"), /X\.Y\.Z/);
});

test("workspace.package version is not rust-version", () => {
  assert.equal(readWorkspaceVersion(FIXTURE_TOML), "0.1.0");
  const bumped = setWorkspaceVersion(FIXTURE_TOML, "0.2.0");
  assert.equal(readWorkspaceVersion(bumped), "0.2.0");
  assert.match(bumped, /rust-version = "1\.97\.1"/);
  assert.match(bumped, /http = "=1\.3\.1"/);
});

test("workspace package names are member directory basenames", () => {
  assert.deepEqual(workspacePackageNames(FIXTURE_TOML), [
    "sub-hub-conversion",
    "sub-hub-http",
  ]);
});

test("planWorkspaceRelease bumps lockfile members only and Console version", () => {
  const plan = planWorkspaceRelease(
    {
      cargoToml: FIXTURE_TOML,
      lockfile: FIXTURE_LOCK,
      consolePackageJson: FIXTURE_CONSOLE,
    },
    "0.2.0",
  );
  assert.equal(plan.current, "0.1.0");
  assert.equal(plan.version, "0.2.0");
  assert.equal(plan.tag, "v0.2.0");
  assert.equal(plan.commitMessage, "chore: release v0.2.0");
  assert.equal(readWorkspaceVersion(plan.cargoToml), "0.2.0");
  assert.match(plan.lockfile, /name = "sub-hub-conversion"\nversion = "0\.2\.0"/);
  assert.match(plan.lockfile, /name = "sub-hub-http"\nversion = "0\.2\.0"/);
  assert.match(plan.lockfile, /name = "unrelated"\nversion = "0\.1\.0"/);
  assert.match(plan.lockfile, /name = "http"\nversion = "1\.3\.1"/);
  assert.equal(JSON.parse(plan.consolePackageJson).version, "0.2.0");
  assert.equal(JSON.parse(plan.consolePackageJson).private, true);
  assert.throws(
    () =>
      planWorkspaceRelease(
        {
          cargoToml: FIXTURE_TOML,
          lockfile: FIXTURE_LOCK,
          consolePackageJson: FIXTURE_CONSOLE,
        },
        "0.1.0",
      ),
    /not greater/,
  );
  assert.throws(
    () =>
      planWorkspaceRelease(
        {
          cargoToml: FIXTURE_TOML,
          lockfile: FIXTURE_LOCK,
          consolePackageJson: FIXTURE_CONSOLE,
        },
        "0.0.9",
      ),
    /not greater/,
  );
});

test("nextPatchVersion increments only the patch field", () => {
  assert.equal(nextPatchVersion("0.1.0"), "0.1.1");
  assert.equal(nextPatchVersion("1.2.9"), "1.2.10");
  assert.throws(() => nextPatchVersion("v0.1.0"), /X\.Y\.Z/);
});

test("compareSemver orders patch then minor then major", () => {
  assert.equal(compareSemver("0.1.1", "0.1.0"), 1);
  assert.equal(compareSemver("0.2.0", "0.1.9"), 1);
  assert.equal(compareSemver("1.0.0", "0.9.9"), 1);
  assert.equal(compareSemver("0.1.0", "0.1.0"), 0);
});

test("version body and outbound user-agent follow CARGO_PKG_VERSION spelling", () => {
  assert.equal(versionBody("0.2.0"), "sub-hub v0.2.0 backend");
  assert.equal(outboundUserAgent("0.2.0"), "sub-hub/0.2.0");
});

test("repository Cargo.toml and Cargo.lock match the helper", () => {
  const cargoToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const lockfile = fs.readFileSync(path.join(repoRoot, "Cargo.lock"), "utf8");
  const consolePackageJson = fs.readFileSync(
    path.join(repoRoot, "apps", "console", "package.json"),
    "utf8",
  );
  const version = readWorkspaceVersion(cargoToml);
  for (const name of workspacePackageNames(cargoToml)) {
    assert.match(
      lockfile,
      new RegExp(`name = "${name}"\\r?\\nversion = "${version}"`),
    );
  }
  const parsed = parseSemver(version);
  const next = `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
  const plan = planWorkspaceRelease(
    { cargoToml, lockfile, consolePackageJson },
    next,
  );
  assert.equal(readWorkspaceVersion(plan.cargoToml), next);
  assert.equal(JSON.parse(plan.consolePackageJson).name, "@sub-hub/console");
});

test("workspace-version CLI prints the live workspace version", () => {
  const cargoToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const version = readWorkspaceVersion(cargoToml);
  const result = spawnSync(process.execPath, [path.join(here, "workspace-version.mjs")], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, version);
  const body = spawnSync(
    process.execPath,
    [path.join(here, "workspace-version.mjs"), "--body"],
    { encoding: "utf8" },
  );
  assert.equal(body.status, 0, body.stderr);
  assert.equal(body.stdout, versionBody(version));
  const stdin = spawnSync(
    process.execPath,
    [path.join(here, "workspace-version.mjs"), "--stdin"],
    { encoding: "utf8", input: FIXTURE_TOML },
  );
  assert.equal(stdin.status, 0, stdin.stderr);
  assert.equal(stdin.stdout, "0.1.0");
});
