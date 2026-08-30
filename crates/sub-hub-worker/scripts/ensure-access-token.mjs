import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const ACCESS_TOKEN_BINDING = "SUB_HUB_ACCESS_TOKEN";
const MAX_TOKENS = 8;
const MAX_LIST_BYTES = 2048;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]+$/;
const ENSURE_FLAGS = new Set([
  "--deploy",
  "--preview",
  "--tokens-file",
  "--from-env",
  "--replace",
  "--print-only",
  "--dry-run",
]);
const VALUE_FLAGS = new Set(["--tokens-file"]);
const TARGETING_FLAGS = new Set(["--name", "--env", "-e", "--config", "-c", "--cwd"]);

export function parseList(raw) {
  if (typeof raw !== "string") {
    throw new Error("invalid access token list");
  }
  const text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  if (Buffer.byteLength(text, "utf8") > MAX_LIST_BYTES) {
    throw new Error("invalid access token list");
  }
  const tokens = [];
  for (const part of text.split(/[,\n\r]/)) {
    const piece = part.replace(/^[ \t]+|[ \t]+$/g, "");
    if (piece.length === 0) {
      continue;
    }
    if (
      piece.length < 1 ||
      piece.length > 128 ||
      !TOKEN_PATTERN.test(piece)
    ) {
      throw new Error("invalid access token list");
    }
    if (tokens.includes(piece)) {
      continue;
    }
    if (tokens.length >= MAX_TOKENS) {
      throw new Error("invalid access token list");
    }
    tokens.push(piece);
  }
  if (tokens.length === 0) {
    throw new Error("invalid access token list");
  }
  return tokens;
}

export function generateToken() {
  return randomBytes(16).toString("hex");
}

export function splitArgv(argv) {
  const flags = {
    deploy: false,
    preview: false,
    replace: false,
    printOnly: false,
    dryRun: false,
    fromEnv: false,
    tokensFile: undefined,
  };
  const targeting = [];
  const forwarded = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      continue;
    }
    if (arg === "--deploy") {
      flags.deploy = true;
      continue;
    }
    if (arg === "--preview") {
      flags.preview = true;
      continue;
    }
    if (arg === "--replace") {
      flags.replace = true;
      continue;
    }
    if (arg === "--print-only") {
      flags.printOnly = true;
      continue;
    }
    if (arg === "--dry-run") {
      flags.dryRun = true;
      continue;
    }
    if (arg === "--from-env") {
      flags.fromEnv = true;
      continue;
    }
    if (arg === "--tokens") {
      throw new Error("use --tokens-file or --from-env");
    }
    if (VALUE_FLAGS.has(arg)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new Error(`missing value for ${arg}`);
      }
      index += 1;
      flags.tokensFile = value;
      continue;
    }
    if (TARGETING_FLAGS.has(arg)) {
      const value = argv[index + 1];
      if (value === undefined || ENSURE_FLAGS.has(value)) {
        throw new Error(`missing value for ${arg}`);
      }
      index += 1;
      targeting.push(arg, value);
      continue;
    }
    forwarded.push(arg);
  }

  return { flags, targeting, forwarded };
}

export function decide({ ci, listResult, flags }) {
  if (ci) {
    return "refuse-ci";
  }

  if (flags.printOnly) {
    if (
      flags.deploy ||
      flags.preview ||
      flags.replace ||
      flags.dryRun ||
      flags.tokensFile ||
      flags.fromEnv
    ) {
      return "abort-usage";
    }
    return "print-only";
  }
  if (flags.replace && !flags.deploy) {
    return "abort-usage";
  }
  if (flags.replace && flags.preview) {
    return "abort-usage";
  }
  if (flags.tokensFile || flags.fromEnv) {
    return "put-operator";
  }
  if (listResult === "indeterminate" || listResult == null) {
    return "abort-indeterminate";
  }
  if (listResult === "present") {
    return flags.replace && flags.deploy ? "generate-and-put" : "leave-existing";
  }
  if (listResult === "absent") {
    return "generate-and-put";
  }
  return "abort-usage";
}

export function classifySecretList(stdout, status) {
  if (status !== 0 || typeof stdout !== "string" || stdout.trim().length === 0) {
    return "indeterminate";
  }
  const parsed = parseLastJsonArray(stdout);
  if (!Array.isArray(parsed)) {
    return "indeterminate";
  }
  return parsed.some((item) => item && item.name === ACCESS_TOKEN_BINDING)
    ? "present"
    : "absent";
}

export function parseLastJsonArray(stdout) {
  const trimmed = stdout.trim();
  try {
    const value = JSON.parse(trimmed);
    if (Array.isArray(value)) {
      return value;
    }
  } catch {
    // Fall through and scan for the last array.
  }
  for (
    let start = trimmed.lastIndexOf("[");
    start >= 0;
    start = trimmed.lastIndexOf("[", start - 1)
  ) {
    try {
      const value = JSON.parse(trimmed.slice(start));
      if (Array.isArray(value)) {
        return value;
      }
    } catch {
      // Keep scanning left.
    }
  }
  return null;
}

export function secretsFileJson(blob) {
  return JSON.stringify({ [ACCESS_TOKEN_BINDING]: blob });
}

function printGeneratedBanner(token) {
  process.stdout.write(`================================================================
SUB_HUB ACCESS TOKEN — shown once. After save, Value is Value encrypted.
Save this value in a password manager or an uncommitted tokens file.
Subscription path: /sub/<token>

  ${token}

To add or revoke later, edit that file (full list) and run
  pnpm run deploy -- --tokens-file <path>
Settings → Runtime variables and secrets can only replace the whole blob;
it cannot show the live list.
================================================================
`);
}

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

const workerRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function runWrangler(args) {
  return spawnSync(
    process.execPath,
    [path.join(workerRoot, "node_modules", "wrangler", "bin", "wrangler.js"), ...args],
    {
      cwd: workerRoot,
      encoding: "utf8",
      env: { ...process.env, WRANGLER_LOG: "error" },
      windowsHide: true,
    },
  );
}

function resolveOperatorBlob(flags) {
  if (flags.tokensFile) {
    const raw = fs.readFileSync(flags.tokensFile, "utf8");
    parseList(raw);
    return raw;
  }
  if (flags.fromEnv) {
    const raw = process.env[ACCESS_TOKEN_BINDING];
    if (raw === undefined || raw === "") {
      throw new Error("SUB_HUB_ACCESS_TOKEN is missing; pass --from-env only when it is set");
    }
    parseList(raw);
    return raw;
  }
  return undefined;
}

function listSecrets(targeting) {
  const result = runWrangler(["secret", "list", "--format", "json", ...targeting]);
  return classifySecretList(result.stdout ?? "", result.status ?? 1);
}

function deployArgs(mode, targeting, forwarded, secretsFile) {
  const command = mode === "preview" ? ["versions", "upload"] : ["deploy"];
  const args = [...command, "--keep-vars", ...targeting, ...forwarded];
  if (secretsFile) {
    args.push("--secrets-file", secretsFile);
  }
  return args;
}

export function putAndDeploy(mode, targeting, forwarded, blob, run = runWrangler) {
  const file = path.join(
    os.tmpdir(),
    `sub-hub-secrets-${randomBytes(8).toString("hex")}.json`,
  );
  try {
    fs.writeFileSync(file, secretsFileJson(blob), { encoding: "utf8" });
    try {
      fs.chmodSync(file, 0o600);
    } catch {
      // Windows may not honor 0600; the file is still in the temp directory.
    }
    const result = run(deployArgs(mode, targeting, forwarded, file));
    if (result.error) {
      process.stderr.write(`${result.error.message}\n`);
    }
    if (result.stdout) {
      process.stdout.write(result.stdout);
    }
    if (result.stderr) {
      process.stderr.write(result.stderr);
    }
    if (result.status !== 0) {
      process.exit(result.status ?? 1);
    }
  } finally {
    fs.rmSync(file, { force: true });
  }
}

function leaveAndDeploy(mode, targeting, forwarded) {
  const result = runWrangler(deployArgs(mode, targeting, forwarded));
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env.CI) {
    fail("ensure-access-token refuses to run when CI is set", 2);
  }

  let split;
  try {
    split = splitArgv(argv);
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid arguments");
  }
  const { flags, targeting, forwarded } = split;
  const explicitSources = [Boolean(flags.tokensFile), flags.fromEnv].filter(Boolean)
    .length;
  if (explicitSources > 1) {
    fail("use only one of --tokens-file or --from-env");
  }

  let operatorBlob;
  try {
    operatorBlob = resolveOperatorBlob(flags);
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid access token list");
  }

  const needsList =
    operatorBlob === undefined && !flags.printOnly;
  const listResult = needsList ? listSecrets(targeting) : null;
  let action;
  try {
    action = decide({ ci: false, listResult, flags });
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid access token list");
  }

  if (action === "abort-usage") {
    if (flags.replace && flags.preview) {
      fail(
        "preview will not change the production secret; use pnpm run deploy -- --replace",
      );
    }
    fail("invalid ensure-access-token arguments");
  }
  if (action === "abort-indeterminate") {
    fail(
      "could not determine whether SUB_HUB_ACCESS_TOKEN exists; aborting without generating a token. Pass --tokens-file to set an explicit list.",
    );
  }
  if (action === "print-only") {
    printGeneratedBanner(generateToken());
    return;
  }

  const mode = flags.preview ? "preview" : flags.deploy ? "deploy" : null;
  if (flags.dryRun) {
    process.stdout.write(`${action}\n`);
    return;
  }
  if ((action === "put-operator" || action === "generate-and-put") && !mode) {
    fail("pass --deploy (pnpm run deploy) to apply access tokens");
  }
  if (action === "leave-existing" && !mode) {
    process.stdout.write(
      "SUB_HUB_ACCESS_TOKEN already present; leaving unchanged. Run pnpm run deploy to publish.\n",
    );
    return;
  }

  if (action === "leave-existing") {
    process.stdout.write("SUB_HUB_ACCESS_TOKEN already present; leaving unchanged.\n");
    leaveAndDeploy(mode, targeting, forwarded);
    return;
  }

  if (action === "put-operator") {
    const tokens = parseList(operatorBlob);
    process.stdout.write(
      `Configured ${tokens.length} access token(s) from operator input.\n`,
    );
    putAndDeploy(mode, targeting, forwarded, operatorBlob);
    return;
  }

  if (action === "generate-and-put") {
    const token = generateToken();
    printGeneratedBanner(token);
    putAndDeploy(mode, targeting, forwarded, token);
  }
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main();
}
