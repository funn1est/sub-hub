import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function parseSemver(text) {
  const match = SEMVER.exec(text);
  if (!match) {
    throw new Error(`version must be X.Y.Z, got ${text}`);
  }
  return {
    raw: match[0],
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

export function nextPatchVersion(version) {
  const current = parseSemver(version);
  return `${current.major}.${current.minor}.${current.patch + 1}`;
}

export function compareSemver(leftText, rightText) {
  const left = parseSemver(leftText);
  const right = parseSemver(rightText);
  for (const key of ["major", "minor", "patch"]) {
    if (left[key] < right[key]) {
      return -1;
    }
    if (left[key] > right[key]) {
      return 1;
    }
  }
  return 0;
}

export function versionBody(version) {
  return `sub-hub v${parseSemver(version).raw} backend`;
}

export function outboundUserAgent(version) {
  return `sub-hub/${parseSemver(version).raw}`;
}

export function tomlSection(text, header) {
  const escaped = header.replaceAll(".", "\\.");
  const startRe = new RegExp(`^\\[${escaped}\\][ \\t]*\\r?\\n`, "m");
  const match = startRe.exec(text);
  if (!match) {
    throw new Error(`missing [${header}]`);
  }
  const bodyStart = match.index + match[0].length;
  const rest = text.slice(bodyStart);
  const next = rest.search(/^\s*\[/m);
  const body = next === -1 ? rest : rest.slice(0, next);
  return { bodyStart, body };
}

export function readWorkspaceVersion(cargoToml) {
  const { body } = tomlSection(cargoToml, "workspace.package");
  const match = /^version\s*=\s*"([^"]+)"/m.exec(body);
  if (!match) {
    throw new Error("missing workspace.package version");
  }
  return parseSemver(match[1]).raw;
}

export function setWorkspaceVersion(cargoToml, version) {
  const next = parseSemver(version).raw;
  const { bodyStart, body } = tomlSection(cargoToml, "workspace.package");
  if (!/^version\s*=\s*"[^"]+"/m.test(body)) {
    throw new Error("missing workspace.package version");
  }
  const updated = body.replace(
    /^version\s*=\s*"[^"]+"/m,
    `version = "${next}"`,
  );
  return cargoToml.slice(0, bodyStart) + updated + cargoToml.slice(bodyStart + body.length);
}

export function workspacePackageNames(cargoToml) {
  const { body } = tomlSection(cargoToml, "workspace");
  const block = /members\s*=\s*\[([\s\S]*?)\]/.exec(body);
  if (!block) {
    throw new Error("missing workspace.members");
  }
  const names = [];
  for (const quoted of block[1].matchAll(/"([^"]+)"/g)) {
    const posix = quoted[1].replaceAll("\\", "/");
    const base = posix.split("/").filter(Boolean).at(-1);
    if (!base) {
      throw new Error(`invalid workspace member ${quoted[1]}`);
    }
    names.push(base);
  }
  if (names.length === 0) {
    throw new Error("workspace.members is empty");
  }
  return names;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function setLockfilePackageVersions(lockfile, names, oldVersion, newVersion) {
  parseSemver(oldVersion);
  const next = parseSemver(newVersion).raw;
  let updated = lockfile;
  for (const name of names) {
    const pattern = new RegExp(
      `(name = "${escapeRegExp(name)}"\\r?\\nversion = ")${escapeRegExp(oldVersion)}(")`,
    );
    if (!pattern.test(updated)) {
      throw new Error(`Cargo.lock missing ${name} ${oldVersion}`);
    }
    updated = updated.replace(pattern, `$1${next}$2`);
  }
  return updated;
}

export function setJsonPackageVersion(text, newVersion) {
  const next = parseSemver(newVersion).raw;
  const pkg = JSON.parse(text);
  if (typeof pkg.version !== "string") {
    throw new Error("package.json missing version");
  }
  const replaced = text.replace(/("version"\s*:\s*")([^"]+)(")/, `$1${next}$3`);
  if (JSON.parse(replaced).version !== next) {
    throw new Error("failed to set package.json version");
  }
  return replaced;
}

export function planWorkspaceRelease(files, newVersion) {
  const next = parseSemver(newVersion).raw;
  const current = readWorkspaceVersion(files.cargoToml);
  if (compareSemver(next, current) <= 0) {
    throw new Error(`version ${next} is not greater than ${current}`);
  }
  const names = workspacePackageNames(files.cargoToml);
  return {
    current,
    version: next,
    tag: `v${next}`,
    commitMessage: `chore: release v${next}`,
    cargoToml: setWorkspaceVersion(files.cargoToml, next),
    lockfile: setLockfilePackageVersions(
      files.lockfile,
      names,
      current,
      next,
    ),
    consolePackageJson: setJsonPackageVersion(files.consolePackageJson, next),
  };
}

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    const cargoToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
    const version = readWorkspaceVersion(cargoToml);
    const flag = process.argv[2];
    if (flag === "--body") {
      process.stdout.write(versionBody(version));
    } else if (flag === "--ua") {
      process.stdout.write(outboundUserAgent(version));
    } else if (flag === undefined) {
      process.stdout.write(version);
    } else {
      throw new Error("usage: node scripts/workspace-version.mjs [--body|--ua]");
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}
