import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  nextPatchVersion,
  parseSemver,
  planWorkspaceRelease,
  readWorkspaceVersion,
} from "./workspace-version.mjs";

const USAGE =
  "usage: node scripts/cut-native-release.mjs [X.Y.Z] [--dry-run] [--no-push] [--no-fetch]";

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

export function parseCutArgv(argv) {
  let version;
  let dryRun = false;
  let push = true;
  let fetch = true;
  for (const arg of argv) {
    if (arg === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (arg === "--no-push") {
      push = false;
      continue;
    }
    if (arg === "--no-fetch") {
      fetch = false;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      throw new Error(USAGE);
    }
    if (arg.startsWith("-")) {
      throw new Error(`unknown flag ${arg}`);
    }
    if (version !== undefined) {
      throw new Error(USAGE);
    }
    version = parseSemver(arg).raw;
  }
  return { version, dryRun, push, fetch };
}

export function runGit(args, { cwd, env = process.env, allowFailure = false } = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...env, GIT_TERMINAL_PROMPT: "0" },
  });
  if (!allowFailure && (result.status ?? 1) !== 0) {
    const detail = (result.stderr || result.stdout || `git ${args.join(" ")}`).trim();
    throw new Error(detail);
  }
  return result;
}

function gitText(git, args, options) {
  return (git(args, options).stdout || "").trim();
}

export function assertReleaseGitState(root, tag, { git = runGit, fetch = true } = {}) {
  if (fetch) {
    git(["fetch", "origin"], { cwd: root });
  }
  const branch = gitText(git, ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root });
  if (branch !== "main") {
    throw new Error(`cut release from main, not ${branch}`);
  }
  const dirty = gitText(git, ["status", "--porcelain"], { cwd: root });
  if (dirty.length > 0) {
    throw new Error("working tree is not clean");
  }
  const head = gitText(git, ["rev-parse", "HEAD"], { cwd: root });
  const origin = git(["rev-parse", "--verify", "origin/main"], {
    cwd: root,
    allowFailure: true,
  });
  if ((origin.status ?? 1) !== 0) {
    throw new Error("origin/main is missing; fetch or push main first");
  }
  if (head !== (origin.stdout || "").trim()) {
    throw new Error("main is not origin/main; push or pull first");
  }
  const localTag = git(["show-ref", "--verify", "--quiet", `refs/tags/${tag}`], {
    cwd: root,
    allowFailure: true,
  });
  if ((localTag.status ?? 1) === 0) {
    throw new Error(`tag ${tag} already exists locally`);
  }
  const remoteTag = gitText(git, ["ls-remote", "--tags", "origin", `refs/tags/${tag}`], {
    cwd: root,
  });
  if (remoteTag.length > 0) {
    throw new Error(`tag ${tag} already exists on origin`);
  }
}

function readReleaseFiles(root) {
  return {
    cargoToml: fs.readFileSync(path.join(root, "Cargo.toml"), "utf8"),
    lockfile: fs.readFileSync(path.join(root, "Cargo.lock"), "utf8"),
    consolePackageJson: fs.readFileSync(
      path.join(root, "apps", "console", "package.json"),
      "utf8",
    ),
  };
}

function writeReleaseFiles(root, plan) {
  fs.writeFileSync(path.join(root, "Cargo.toml"), plan.cargoToml);
  fs.writeFileSync(path.join(root, "Cargo.lock"), plan.lockfile);
  fs.writeFileSync(
    path.join(root, "apps", "console", "package.json"),
    plan.consolePackageJson,
  );
}

export function cutNativeRelease({
  root,
  version,
  dryRun = false,
  push = true,
  fetch = true,
  git = runGit,
} = {}) {
  const files = readReleaseFiles(root);
  const next =
    version === undefined
      ? nextPatchVersion(readWorkspaceVersion(files.cargoToml))
      : parseSemver(version).raw;
  const plan = planWorkspaceRelease(files, next);
  assertReleaseGitState(root, plan.tag, { git, fetch });
  if (dryRun) {
    return plan;
  }
  writeReleaseFiles(root, plan);
  git(["add", "Cargo.toml", "Cargo.lock", "apps/console/package.json"], {
    cwd: root,
  });
  git(["commit", "-m", plan.commitMessage], { cwd: root });
  git(["tag", "-a", plan.tag, "-m", plan.tag], { cwd: root });
  if (push) {
    git(["push", "origin", "HEAD"], { cwd: root });
    git(["push", "origin", plan.tag], { cwd: root });
  }
  return plan;
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    const flags = parseCutArgv(process.argv.slice(2));
    const plan = cutNativeRelease({ root: repoRoot, ...flags });
    if (flags.dryRun) {
      process.stdout.write(`dry-run ${plan.tag} from ${plan.current}\n`);
    } else if (flags.push) {
      process.stdout.write(`pushed ${plan.tag}\n`);
    } else {
      process.stdout.write(`tagged ${plan.tag} (not pushed)\n`);
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}
