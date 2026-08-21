import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const VALUE_FLAGS = new Set([
  "--worker-name",
  "--name",
  "--tokens",
  "--tokens-file",
  "--layout",
  "--cors-origin",
  "--console-name",
]);

const LAYOUT_ALIASES = new Map([
  ["all", "all"],
  ["worker", "worker"],
  ["console", "console"],
]);

const workerRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.join(workerRoot, "..", "..");
const ensureScript = path.join(workerRoot, "scripts", "ensure-access-token.mjs");

export function parseLayout(raw) {
  const layout = LAYOUT_ALIASES.get(raw);
  if (!layout) {
    throw new Error("layout must be all, worker, or console");
  }
  return layout;
}

export function parseDeployArgv(argv) {
  const flags = {
    skipBuild: false,
    dryRun: false,
    fromEnv: false,
    replace: false,
    dev: false,
    preview: false,
    layout: undefined,
    workerName: undefined,
    consoleName: undefined,
    corsOrigin: undefined,
    tokens: undefined,
    tokensFile: undefined,
  };
  const forwarded = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") {
      continue;
    }
    if (arg === "--skip-build") {
      flags.skipBuild = true;
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
    if (arg === "--dev") {
      flags.dev = true;
      continue;
    }
    if (arg === "--preview") {
      flags.preview = true;
      continue;
    }
    if (arg === "--all" || arg === "--worker-only" || arg === "--console-only") {
      const alias =
        arg === "--all" ? "all" : arg === "--worker-only" ? "worker" : "console";
      if (flags.layout !== undefined && flags.layout !== alias) {
        throw new Error("use only one layout");
      }
      flags.layout = alias;
      continue;
    }
    if (VALUE_FLAGS.has(arg)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new Error(`missing value for ${arg}`);
      }
      index += 1;
      if (arg === "--worker-name" || arg === "--name") {
        flags.workerName = value;
      } else if (arg === "--console-name") {
        flags.consoleName = value;
      } else if (arg === "--layout") {
        const layout = parseLayout(value);
        if (flags.layout !== undefined && flags.layout !== layout) {
          throw new Error("use only one layout");
        }
        flags.layout = layout;
      } else if (arg === "--cors-origin") {
        flags.corsOrigin = value;
      } else if (arg === "--tokens") {
        flags.tokens = value;
      } else {
        flags.tokensFile = value;
      }
      continue;
    }
    forwarded.push(arg);
  }

  if (flags.dev && flags.preview) {
    throw new Error("use only one of --dev or --preview");
  }
  flags.layout ??= "all";
  if (flags.layout === "console" && flags.workerName && !flags.consoleName) {
    flags.consoleName = flags.workerName;
  }
  if (flags.corsOrigin && flags.layout !== "worker") {
    throw new Error("--cors-origin is only for --layout worker");
  }
  if (
    flags.layout === "console" &&
    (flags.tokens !== undefined || flags.tokensFile || flags.fromEnv || flags.replace)
  ) {
    throw new Error("access-token flags are only for the Conversion Worker");
  }
  return { flags, forwarded };
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

export function resolveDeployConfig({ flags, env, roots = { repoRoot, workerRoot } }) {
  const layout = flags.layout ?? "all";
  return {
    skipBuild: Boolean(flags.skipBuild),
    dryRun: Boolean(flags.dryRun),
    fromEnv: Boolean(flags.fromEnv),
    replace: Boolean(flags.replace),
    dev: Boolean(flags.dev),
    preview: Boolean(flags.preview),
    layout,
    tokens: flags.tokens,
    tokensFile: flags.tokensFile,
    corsOrigin: flags.corsOrigin,
    workerName: firstNonEmpty(flags.workerName, env.CLOUDFLARE_WORKER_NAME),
    consoleName: firstNonEmpty(flags.consoleName, env.CLOUDFLARE_CONSOLE_NAME),
    consoleRoot: path.join(roots.repoRoot, "apps", "console"),
    consoleDist: path.join(roots.repoRoot, "apps", "console", "dist"),
    consoleWrangler: path.join(roots.repoRoot, "apps", "console", "wrangler.toml"),
    workerRoot: roots.workerRoot,
    workerOnlyConfig: path.join(roots.workerRoot, "wrangler.worker.toml"),
  };
}

export function needsConsoleBuild(layout) {
  return layout !== "worker";
}

export function wranglerConfigArgs(config) {
  if (config.layout === "worker") {
    return ["--config", "wrangler.worker.toml"];
  }
  if (config.layout === "console") {
    return ["--config", config.consoleWrangler];
  }
  return [];
}

export function conversionVarArgs(config) {
  if (config.layout !== "worker" || !config.corsOrigin) {
    return [];
  }
  return ["--var", `SUB_HUB_CORS_ORIGINS:${config.corsOrigin}`];
}

export function parseWorkerOrigin(text) {
  if (typeof text !== "string") {
    return null;
  }
  const match = text.match(/https:\/\/[a-z0-9.-]+\.workers\.dev/i);
  return match ? match[0].toLowerCase().replace(/\/+$/, "") : null;
}

export function consoleIndexPath(config) {
  return path.join(config.consoleDist, "index.html");
}

export function ensureDeployArgv(config, forwarded = []) {
  if (config.layout === "console") {
    throw new Error("access-token ensure is only for the Conversion Worker");
  }
  const args = config.preview ? ["--preview"] : ["--deploy"];
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
  } else if (config.fromEnv) {
    args.push("--from-env");
  }
  if (config.workerName) {
    args.push("--name", config.workerName);
  }
  args.push(...wranglerConfigArgs(config), ...conversionVarArgs(config), ...forwarded);
  return args;
}

export function consoleDeployArgv(config) {
  const command = config.preview ? ["versions", "upload"] : ["deploy"];
  const args = [...command, "--keep-vars", ...wranglerConfigArgs(config)];
  if (config.consoleName) {
    args.push("--name", config.consoleName);
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

function ensureConsoleBuilt(config) {
  if (config.skipBuild) {
    if (!fs.existsSync(consoleIndexPath(config))) {
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
  if (!fs.existsSync(consoleIndexPath(config))) {
    fail(`Console dist is missing at ${config.consoleDist} after build`);
  }
}

function writeSummary(config, origin) {
  if (config.layout === "console") {
    const line = origin
      ? `Published Console: ${origin}`
      : "Published: Console Worker";
    process.stdout.write(`${line}\n`);
    if (origin) {
      process.stdout.write(
        `Set SUB_HUB_CORS_ORIGINS on the Conversion Worker to this origin:\n  pnpm run deploy:worker -- --cors-origin ${origin}\n`,
      );
    }
    return;
  }
  if (config.layout === "worker") {
    const line = origin
      ? `Published Conversion Service: ${origin}`
      : "Published: Conversion Worker";
    process.stdout.write(`${line}\n`);
    return;
  }
  const line = origin
    ? `Published: ${origin}  (Console and Conversion Service)`
    : "Published: Conversion Worker with same-origin Console";
  process.stdout.write(`${line}\n`);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  let parsed;
  try {
    parsed = parseDeployArgv(argv);
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid arguments");
  }
  const { flags, forwarded } = parsed;

  const config = resolveDeployConfig({ flags, env });
  if (env.CI) {
    fail("deploy refuses to run when CI is set", 2);
  }

  if (config.dryRun) {
    process.stdout.write(
      `${JSON.stringify(
        {
          layout: config.layout,
          workerName: config.workerName ?? "sub-hub",
          consoleName: config.consoleName ?? "sub-hub-console",
          skipBuild: config.skipBuild,
          needsConsoleBuild: needsConsoleBuild(config.layout),
          wranglerConfig: wranglerConfigArgs(config),
          dev: config.dev,
          preview: config.preview,
          consoleDist: config.consoleDist,
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  if (needsConsoleBuild(config.layout)) {
    ensureConsoleBuilt(config);
  }

  if (config.dev) {
    const result = spawnSync(
      process.execPath,
      [wranglerBin(), "dev", ...wranglerConfigArgs(config), ...forwarded],
      {
        cwd: config.layout === "console" ? config.consoleRoot : config.workerRoot,
        stdio: "inherit",
        env,
        windowsHide: true,
      },
    );
    if ((result.status ?? 1) !== 0) {
      fail("wrangler dev failed", result.status ?? 1);
    }
    return;
  }

  if (config.layout === "console") {
    const result = runCaptured(
      process.execPath,
      [wranglerBin(), ...consoleDeployArgv(config), ...forwarded],
      {
        cwd: config.consoleRoot,
        env,
      },
    );
    if ((result.status ?? 1) !== 0) {
      fail("Console deploy failed", result.status ?? 1);
    }
    writeSummary(config, parseWorkerOrigin(combinedOutput(result)));
    return;
  }

  let ensureArgv;
  try {
    ensureArgv = ensureDeployArgv(config, forwarded);
  } catch (error) {
    fail(error instanceof Error ? error.message : "invalid arguments");
  }

  const result = runCaptured(process.execPath, [ensureScript, ...ensureArgv], {
    cwd: config.workerRoot,
    env,
  });
  if ((result.status ?? 1) !== 0) {
    fail("Worker deploy failed", result.status ?? 1);
  }
  writeSummary(config, parseWorkerOrigin(combinedOutput(result)));
}

const invokedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main();
}
