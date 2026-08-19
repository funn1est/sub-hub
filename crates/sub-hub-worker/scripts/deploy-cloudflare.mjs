import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { parseLastJsonArray } from "./ensure-access-token.mjs";

export const DEFAULT_PAGES_PROJECT = "sub-hub-console";
export const DEFAULT_PRODUCTION_BRANCH = "main";

const VALUE_FLAGS = new Set([
  "--pages-project",
  "--worker-name",
  "--branch",
  "--tokens",
  "--tokens-file",
]);

const workerRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.join(workerRoot, "..", "..");
const ensureScript = path.join(workerRoot, "scripts", "ensure-access-token.mjs");

export function parseStackArgv(argv) {
  const flags = {
    skipBuild: false,
    skipConsole: false,
    skipWorker: false,
    dryRun: false,
    fromEnv: false,
    replace: false,
    pagesProject: undefined,
    workerName: undefined,
    branch: undefined,
    tokens: undefined,
    tokensFile: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      continue;
    }
    if (arg === "--skip-build") {
      flags.skipBuild = true;
      continue;
    }
    if (arg === "--skip-console") {
      flags.skipConsole = true;
      continue;
    }
    if (arg === "--skip-worker") {
      flags.skipWorker = true;
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
    if (arg === "--replace") {
      flags.replace = true;
      continue;
    }
    if (VALUE_FLAGS.has(arg)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new Error(`missing value for ${arg}`);
      }
      index += 1;
      if (arg === "--pages-project") {
        flags.pagesProject = value;
      } else if (arg === "--worker-name") {
        flags.workerName = value;
      } else if (arg === "--branch") {
        flags.branch = value;
      } else if (arg === "--tokens") {
        flags.tokens = value;
      } else {
        flags.tokensFile = value;
      }
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return flags;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

export function resolveStackConfig({ flags, env, roots = { repoRoot, workerRoot } }) {
  return {
    skipBuild: Boolean(flags.skipBuild),
    skipConsole: Boolean(flags.skipConsole),
    skipWorker: Boolean(flags.skipWorker),
    dryRun: Boolean(flags.dryRun),
    fromEnv: Boolean(flags.fromEnv),
    replace: Boolean(flags.replace),
    tokens: flags.tokens,
    tokensFile: flags.tokensFile,
    pagesProject:
      firstNonEmpty(flags.pagesProject, env.CLOUDFLARE_PAGES_PROJECT) ??
      DEFAULT_PAGES_PROJECT,
    workerName: firstNonEmpty(flags.workerName, env.CLOUDFLARE_WORKER_NAME),
    branch:
      firstNonEmpty(flags.branch, env.CLOUDFLARE_PAGES_BRANCH) ??
      DEFAULT_PRODUCTION_BRANCH,
    extraCorsOrigins: env.CLOUDFLARE_EXTRA_CORS_ORIGINS,
    extraSelfHosts: env.CLOUDFLARE_EXTRA_SELF_HOSTS,
    commitHash: firstNonEmpty(env.GITHUB_SHA),
    consoleRoot: path.join(roots.repoRoot, "apps", "console"),
    consoleDist: path.join(roots.repoRoot, "apps", "console", "dist"),
    consoleWrangler: path.join(roots.repoRoot, "apps", "console", "wrangler.toml"),
    workerRoot: roots.workerRoot,
  };
}

export function parsePagesProductionOrigin(text) {
  if (typeof text !== "string") {
    return null;
  }
  const matches = text.match(/https:\/\/[a-z0-9.-]+\.pages\.dev/gi) ?? [];
  const unique = [
    ...new Set(matches.map((url) => url.toLowerCase().replace(/\/+$/, ""))),
  ];
  return (
    unique.find((url) => {
      const host = new URL(url).hostname;
      const labels = host.slice(0, -".pages.dev".length).split(".");
      return labels.length === 1;
    }) ?? null
  );
}

export function resolveConsoleOrigin(text, projectName) {
  return (
    parsePagesProductionOrigin(text) ?? `https://${projectName}.pages.dev`
  );
}

export function parseWorkerOrigin(text) {
  if (typeof text !== "string") {
    return null;
  }
  const match = text.match(/https:\/\/[a-z0-9.-]+\.workers\.dev/i);
  return match ? match[0].toLowerCase().replace(/\/+$/, "") : null;
}

export function hostnameFromHttpsUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      return null;
    }
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function joinBindingList(values) {
  const out = [];
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0) {
      continue;
    }
    for (const part of value.split(/[,\n\r]/)) {
      const piece = part.replace(/^[ \t]+|[ \t]+$/g, "");
      if (piece.length === 0 || out.includes(piece)) {
        continue;
      }
      out.push(piece);
    }
  }
  return out.join(",");
}

export function workerVarArgs({ corsOrigins, selfHosts }) {
  const args = [];
  if (corsOrigins) {
    args.push("--var", `SUB_HUB_CORS_ORIGINS:${corsOrigins}`);
  }
  if (selfHosts) {
    args.push("--var", `SUB_HUB_SELF_HOSTS:${selfHosts}`);
  }
  return args;
}

export function interpretProjectCreate(status, stdout, stderr) {
  if (status === 0) {
    return "created";
  }
  const text = `${stdout ?? ""}\n${stderr ?? ""}`.toLowerCase();
  if (
    text.includes("already exists") ||
    text.includes("already taken") ||
    text.includes("duplicate")
  ) {
    return "exists";
  }
  return "failed";
}

export function pagesProjectExists(listOutput, projectName) {
  const parsed = parseLastJsonArray(listOutput);
  if (!Array.isArray(parsed)) {
    return false;
  }
  return parsed.some((item) => item && item.name === projectName);
}

export function needsSelfHostsFollowUp(appliedHosts, discoveredHostname) {
  if (!discoveredHostname) {
    return false;
  }
  const listed = joinBindingList([appliedHosts]);
  return !listed.split(",").includes(discoveredHostname);
}

export function ensureDeployArgv(config, { hasAccessToken }) {
  const args = ["--deploy"];
  if (config.replace) {
    args.push("--replace");
  }
  const sources = [
    config.tokens !== undefined,
    Boolean(config.tokensFile),
    Boolean(config.fromEnv),
  ].filter(Boolean).length;
  if (sources > 1) {
    throw new Error("use only one of --tokens, --tokens-file, or --from-env");
  }
  if (config.tokens !== undefined) {
    args.push("--tokens", config.tokens);
  } else if (config.tokensFile) {
    args.push("--tokens-file", config.tokensFile);
  } else if (config.fromEnv || hasAccessToken) {
    args.push("--from-env");
  }
  if (config.workerName) {
    args.push("--name", config.workerName);
  }
  return args;
}

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

function wranglerBin() {
  return path.join(workerRoot, "node_modules", "wrangler", "bin", "wrangler.js");
}

function runCaptured(command, args, options) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    windowsHide: true,
    ...options,
  });
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  return result;
}

function runWrangler(args, { cwd, env } = {}) {
  return runCaptured(process.execPath, [wranglerBin(), ...args], {
    cwd: cwd ?? workerRoot,
    env: { ...env, WRANGLER_LOG: "error" },
  });
}

function runPnpm(cwd, args) {
  return spawnSync(process.platform === "win32" ? "pnpm.cmd" : "pnpm", args, {
    cwd,
    stdio: "inherit",
    windowsHide: true,
    shell: process.platform === "win32",
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function writeSummary(env, lines) {
  const body = `${lines.join("\n")}\n`;
  process.stdout.write(`${body}`);
  if (env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(env.GITHUB_STEP_SUMMARY, `## Cloudflare stack\n\n${body}`);
  }
}

function ensureConsoleBuilt(config) {
  if (config.skipBuild) {
    if (!fs.existsSync(path.join(config.consoleDist, "index.html"))) {
      fail(`Console dist is missing at ${config.consoleDist}; omit --skip-build`);
    }
    return;
  }
  const install = runPnpm(config.consoleRoot, ["install", "--frozen-lockfile"]);
  if ((install.status ?? 1) !== 0) {
    fail("Console install failed");
  }
  const build = runPnpm(config.consoleRoot, ["run", "build"]);
  if ((build.status ?? 1) !== 0) {
    fail("Console build failed");
  }
}

function ensurePagesProject(config, env) {
  const listed = runWrangler(["pages", "project", "list", "--json"], { env });
  if (
    (listed.status ?? 1) === 0 &&
    pagesProjectExists(listed.stdout ?? "", config.pagesProject)
  ) {
    return;
  }
  const created = runWrangler(
    [
      "pages",
      "project",
      "create",
      config.pagesProject,
      "--production-branch",
      config.branch,
    ],
    { env },
  );
  const outcome = interpretProjectCreate(
    created.status ?? 1,
    created.stdout,
    created.stderr,
  );
  if (outcome === "failed") {
    process.stderr.write(
      `wrangler pages project create did not confirm ${config.pagesProject}; continuing to deploy\n`,
    );
  }
}

function deployPages(config, env) {
  const args = [
    "pages",
    "deploy",
    config.consoleDist,
    "--project-name",
    config.pagesProject,
    "--branch",
    config.branch,
    "--commit-dirty=true",
    "--config",
    config.consoleWrangler,
  ];
  if (config.commitHash) {
    args.push("--commit-hash", config.commitHash);
  }
  const result = runWrangler(args, { cwd: config.consoleRoot, env });
  if ((result.status ?? 1) !== 0) {
    fail("wrangler pages deploy failed");
  }
  return resolveConsoleOrigin(combinedOutput(result), config.pagesProject);
}

function deployWorker(config, env, vars) {
  const args = [
    ...ensureDeployArgv(config, {
      hasAccessToken: Boolean(env.SUB_HUB_ACCESS_TOKEN),
    }),
    ...workerVarArgs(vars),
  ];
  const result = runCaptured(process.execPath, [ensureScript, ...args], {
    cwd: config.workerRoot,
    env,
  });
  if ((result.status ?? 1) !== 0) {
    fail("Worker deploy failed", result.status ?? 1);
  }
  return parseWorkerOrigin(combinedOutput(result));
}

export function main(argv = process.argv.slice(2), env = process.env) {
  let flags;
  try {
    flags = parseStackArgv(argv);
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid arguments");
  }
  if (flags.skipConsole && flags.skipWorker) {
    fail("nothing to deploy; omit one of --skip-console or --skip-worker");
  }

  const config = resolveStackConfig({ flags, env });
  if (env.CI) {
    fail("deploy:stack refuses to run when CI is set", 2);
  }

  if (config.dryRun) {
    process.stdout.write(
      `${JSON.stringify(
        {
          pagesProject: config.pagesProject,
          workerName: config.workerName ?? "sub-hub",
          branch: config.branch,
          skipBuild: config.skipBuild,
          skipConsole: config.skipConsole,
          skipWorker: config.skipWorker,
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  let consoleOrigin;
  if (!config.skipConsole) {
    ensureConsoleBuilt(config);
    ensurePagesProject(config, env);
    consoleOrigin = deployPages(config, env);
  }

  let workerOrigin;
  if (!config.skipWorker) {
    const corsOrigins = joinBindingList([
      consoleOrigin,
      config.extraCorsOrigins,
    ]);
    let selfHosts = joinBindingList([config.extraSelfHosts]);
    workerOrigin = deployWorker(config, env, { corsOrigins, selfHosts });
    const hostname = hostnameFromHttpsUrl(workerOrigin ?? "");
    if (needsSelfHostsFollowUp(selfHosts, hostname)) {
      selfHosts = joinBindingList([selfHosts, hostname]);
      workerOrigin =
        deployWorker(config, env, { corsOrigins, selfHosts }) ?? workerOrigin;
    }
  }

  writeSummary(env, [
    consoleOrigin ? `Console: ${consoleOrigin}` : "Console: skipped",
    workerOrigin ? `Worker: ${workerOrigin}` : "Worker: published",
  ]);
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main();
}
