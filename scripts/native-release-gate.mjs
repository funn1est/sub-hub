import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { parseSemver } from "./workspace-version.mjs";

const USAGE =
  "usage: node scripts/native-release-gate.mjs --event <name> --ref-type <branch|tag> --ref-name <name> --current <X.Y.Z> [--previous <X.Y.Z>] --release-exists <true|false>";

export const ZERO_SHA = "0".repeat(40);

export function parseBool(raw) {
  if (raw === "true") {
    return true;
  }
  if (raw === "false") {
    return false;
  }
  throw new Error(`expected true or false, got ${raw}`);
}

export function parseGateArgv(argv) {
  const flags = {
    eventName: undefined,
    refType: undefined,
    refName: undefined,
    currentVersion: undefined,
    previousVersion: "",
    releaseExists: undefined,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      throw new Error(USAGE);
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("-")) {
      throw new Error(`missing value for ${arg}`);
    }
    index += 1;
    if (arg === "--event") {
      flags.eventName = value;
      continue;
    }
    if (arg === "--ref-type") {
      flags.refType = value;
      continue;
    }
    if (arg === "--ref-name") {
      flags.refName = value;
      continue;
    }
    if (arg === "--current") {
      flags.currentVersion = parseSemver(value).raw;
      continue;
    }
    if (arg === "--previous") {
      flags.previousVersion = value.length === 0 ? "" : parseSemver(value).raw;
      continue;
    }
    if (arg === "--release-exists") {
      flags.releaseExists = parseBool(value);
      continue;
    }
    throw new Error(`unknown flag ${arg}`);
  }
  if (
    flags.eventName === undefined ||
    flags.refType === undefined ||
    flags.refName === undefined ||
    flags.currentVersion === undefined ||
    flags.releaseExists === undefined
  ) {
    throw new Error(USAGE);
  }
  if (flags.refType !== "branch" && flags.refType !== "tag") {
    throw new Error("ref-type must be branch or tag");
  }
  return flags;
}

export function decideNativeRelease({
  eventName,
  refType,
  refName,
  currentVersion,
  previousVersion = "",
  releaseExists,
}) {
  const current = parseSemver(currentVersion).raw;
  if (releaseExists) {
    return { publish: false, version: current, reason: "release exists" };
  }
  if (refType === "tag") {
    const expected = `v${current}`;
    if (refName !== expected) {
      throw new Error(`tag ${refName} does not match workspace version ${expected}`);
    }
    return { publish: true, version: current, reason: "tag" };
  }
  if (eventName === "workflow_dispatch") {
    return { publish: true, version: current, reason: "dispatch" };
  }
  if (eventName === "push" && refName === "main") {
    if (previousVersion.length === 0) {
      return { publish: true, version: current, reason: "no previous version" };
    }
    const previous = parseSemver(previousVersion).raw;
    if (previous !== current) {
      return { publish: true, version: current, reason: "version changed" };
    }
    return { publish: false, version: current, reason: "version unchanged" };
  }
  return { publish: false, version: current, reason: "not a release event" };
}

export function writeGateOutput(decision, { githubOutput, stdout = process.stdout } = {}) {
  stdout.write(`${decision.publish ? "publish" : "skip"} ${decision.reason}\n`);
  if (!githubOutput) {
    return;
  }
  fs.appendFileSync(
    githubOutput,
    `publish=${decision.publish}\nversion=${decision.version}\nreason=${decision.reason}\n`,
  );
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    const flags = parseGateArgv(process.argv.slice(2));
    const decision = decideNativeRelease(flags);
    writeGateOutput(decision, { githubOutput: process.env.GITHUB_OUTPUT });
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}
