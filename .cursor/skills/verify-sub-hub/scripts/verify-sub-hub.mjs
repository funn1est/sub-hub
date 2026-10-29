#!/usr/bin/env node
// Drive loopback Sub Hub Native and the same-origin Web Console.
// Command list: ../SKILL.md

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const consoleDir = path.join(repoRoot, 'apps', 'console');
const scratchRoot = path.join(repoRoot, '.scratch', 'verify-sub-hub');

const RUN_ID_RE = /^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$/;

function fail(message) {
  console.error(message);
  process.exit(1);
}

function assertNode() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 24 || (major === 24 && minor < 19)) {
    fail(
      `verify-sub-hub needs Node >= 24.19.0 from mise.toml. This process is ${process.version}.`,
    );
  }
}

function assertRepo() {
  if (!fs.existsSync(path.join(repoRoot, 'Cargo.toml'))) {
    fail(`repository root not found from ${scriptDir}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opts = {};
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (!arg.startsWith('--')) {
      fail(`unexpected argument ${arg}`);
    }
    const key = arg.slice(2);
    const next = rest[index + 1];
    if (next === undefined || next.startsWith('--')) {
      opts[key] = true;
    } else {
      opts[key] = next;
      index += 1;
    }
  }
  return { command, opts };
}

function runDir(id) {
  return path.join(scratchRoot, 'runs', id);
}

function evidenceDir(id) {
  return path.join(scratchRoot, 'evidence', id);
}

function currentFile() {
  return path.join(scratchRoot, 'current');
}

function readCurrent() {
  try {
    return fs.readFileSync(currentFile(), 'utf8').trim();
  } catch {
    return '';
  }
}

function workspaceVersion() {
  const text = fs.readFileSync(path.join(repoRoot, 'Cargo.toml'), 'utf8');
  const blocks = text.split(/^\[/m);
  for (const block of blocks) {
    if (!block.startsWith('workspace.package]')) {
      continue;
    }
    const match = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (match) {
      return match[1];
    }
  }
  fail('Cargo.toml is missing workspace.package.version');
}

function newRunId() {
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const suffix = Math.random().toString(16).slice(2, 6);
  return `${stamp}-${suffix}`;
}

function assertRunId(id) {
  if (!RUN_ID_RE.test(id)) {
    fail(`invalid run id ${id}`);
  }
}

function loadRun(opts) {
  const id = opts.run || readCurrent();
  if (!id) {
    fail('no verification run. Run launch, or pass --run.');
  }
  assertRunId(id);
  const file = path.join(runDir(id), 'run.json');
  if (!fs.existsSync(file)) {
    fail(`unknown run ${id}`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function saveRun(run) {
  fs.mkdirSync(runDir(run.id), { recursive: true });
  fs.writeFileSync(path.join(runDir(run.id), 'run.json'), `${JSON.stringify(run, null, 2)}\n`);
}

function printRun(run) {
  console.log(`run=${run.id}`);
  console.log(`pid=${run.pid}`);
  console.log(`origin=${run.origin}`);
  console.log(`version=${run.version}`);
  console.log(`versionBody=${run.versionBody}`);
  console.log('anonymous=yes');
  console.log(`evidence=${path.relative(repoRoot, evidenceDir(run.id))}`);
}

function alive(pid) {
  if (!pid) {
    return false;
  }
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const close = stat.lastIndexOf(')');
    const state = stat.slice(close + 2, close + 3);
    return state !== 'Z';
  } catch {
    return false;
  }
}

function tail(file) {
  try {
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    return lines.slice(-40).join('\n');
  } catch {
    return '';
  }
}

async function killPid(pid) {
  if (!alive(pid)) {
    return;
  }
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      // already gone
    }
  }
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (!alive(pid)) {
      return;
    }
    await sleep(100);
  }
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // already gone
    }
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

function runCommand(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', env: process.env });
  if (result.error) {
    fail(`${command} failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`${command} ${args.join(' ')} exited ${result.status}`);
  }
}

function which(command) {
  const result = spawnSync('which', [command], { encoding: 'utf8' });
  if (result.status !== 0) {
    return '';
  }
  return result.stdout.trim();
}

function buildArtifacts() {
  const corepack = path.join(path.dirname(process.execPath), 'corepack');
  if (!fs.existsSync(corepack)) {
    fail(`corepack is missing next to ${process.execPath}`);
  }
  if (!which('cargo')) {
    fail('cargo is not on PATH. Install Rust 1.97.1 from mise.toml and re-run.');
  }
  console.log('build console');
  runCommand(corepack, ['pnpm', 'install', '--frozen-lockfile'], consoleDir);
  runCommand(corepack, ['pnpm', 'run', 'build'], consoleDir);
  const index = path.join(consoleDir, 'dist', 'index.html');
  if (!fs.existsSync(index)) {
    fail('console build did not write apps/console/dist/index.html');
  }
  console.log('build native');
  runCommand('cargo', ['build', '--locked', '-p', 'sub-hub-native'], repoRoot);
  const binary = path.join(repoRoot, 'target', 'debug', 'sub-hub-native');
  if (!fs.existsSync(binary)) {
    fail('cargo build did not write target/debug/sub-hub-native');
  }
  return { consoleRoot: fs.realpathSync(path.join(consoleDir, 'dist')), binary: fs.realpathSync(binary) };
}

function readEnviron(pid) {
  const raw = fs.readFileSync(`/proc/${pid}/environ`);
  const map = new Map();
  for (const entry of raw.toString('utf8').split('\0')) {
    const splitAt = entry.indexOf('=');
    if (splitAt === -1) {
      continue;
    }
    map.set(entry.slice(0, splitAt), entry.slice(splitAt + 1));
  }
  return map;
}

function listeningInodes(port) {
  const needle = `0100007F:${port.toString(16).toUpperCase().padStart(4, '0')}`;
  const text = fs.readFileSync('/proc/net/tcp', 'utf8');
  const inodes = [];
  for (const line of text.split('\n').slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts[1]?.toUpperCase() === needle && parts[3] === '0A') {
      inodes.push(parts[9]);
    }
  }
  return inodes;
}

function processHasSocket(pid, inode) {
  let fds;
  try {
    fds = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  return fds.some((fd) => {
    try {
      return fs.readlinkSync(`/proc/${pid}/fd/${fd}`) === `socket:[${inode}]`;
    } catch {
      return false;
    }
  });
}

async function fetchText(url) {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
  const body = await response.text();
  return { status: response.status, body, headers: response.headers };
}

function doctor(run) {
  if (!alive(run.pid)) {
    throw new Error(`native process ${run.pid} is not running`);
  }
  const cmdline = fs.readFileSync(`/proc/${run.pid}/cmdline`).toString('utf8').split('\0');
  if (!cmdline.some((part) => part.endsWith('sub-hub-native'))) {
    throw new Error(`pid ${run.pid} is not sub-hub-native`);
  }
  const exe = fs.readlinkSync(`/proc/${run.pid}/exe`);
  if (exe.endsWith(' (deleted)')) {
    throw new Error('native binary was replaced after launch');
  }
  if (fs.realpathSync(exe) !== fs.realpathSync(run.binary)) {
    throw new Error('pid executable is not the binary recorded for this run');
  }
  const environ = readEnviron(run.pid);
  if (environ.has('SUB_HUB_ACCESS_TOKEN')) {
    throw new Error('this run has SUB_HUB_ACCESS_TOKEN set; verification stays anonymous');
  }
  if (environ.get('SUB_HUB_BIND') !== `127.0.0.1:${run.port}`) {
    throw new Error('SUB_HUB_BIND does not match this run');
  }
  if (environ.get('SUB_HUB_CONSOLE_ROOT') !== run.consoleRoot) {
    throw new Error('SUB_HUB_CONSOLE_ROOT does not match this run');
  }
  const inodes = listeningInodes(run.port);
  if (inodes.length === 0 || !inodes.some((inode) => processHasSocket(run.pid, inode))) {
    throw new Error(`127.0.0.1:${run.port} is not owned by pid ${run.pid}`);
  }
  const log = fs.readFileSync(run.log, 'utf8');
  for (const line of [
    'sub-hub-native: SUB_HUB_ACCESS_TOKEN is unset; GET /sub is anonymous',
    'sub-hub-native: serving Web Console from SUB_HUB_CONSOLE_ROOT',
  ]) {
    if (!log.includes(line)) {
      throw new Error(`native log is missing ${JSON.stringify(line)}`);
    }
  }
  const version = workspaceVersion();
  const versionBody = `sub-hub v${version} backend`;
  return { version, versionBody };
}

async function doctorHttp(run, expected) {
  let versionResponse;
  let pageResponse;
  let anonymousResponse;
  try {
    versionResponse = await fetchText(`${run.origin}/version`);
    pageResponse = await fetchText(`${run.origin}/`);
    anonymousResponse = await fetchText(`${run.origin}/sub`);
  } catch (error) {
    throw new Error(`loopback request failed: ${error instanceof Error ? error.message : error}`);
  }
  if (versionResponse.status !== 200 || versionResponse.body !== expected.versionBody) {
    throw new Error(
      `GET /version returned ${versionResponse.status} body ${JSON.stringify(versionResponse.body)}`,
    );
  }
  if (pageResponse.status !== 200 || !pageResponse.body.includes('<title>Sub Hub Console</title>')) {
    throw new Error(`GET / did not serve the Web Console title (status ${pageResponse.status})`);
  }
  if (pageResponse.headers.get('cache-control') !== 'no-store') {
    throw new Error('GET / did not return cache-control: no-store');
  }
  if (pageResponse.headers.get('referrer-policy') !== 'no-referrer') {
    throw new Error('GET / did not return referrer-policy: no-referrer');
  }
  if (anonymousResponse.status !== 400 || anonymousResponse.body !== 'Invalid target!') {
    throw new Error(
      `anonymous GET /sub returned ${anonymousResponse.status} body ${JSON.stringify(anonymousResponse.body)}`,
    );
  }
}

async function launch() {
  const built = buildArtifacts();
  const port = await freePort();
  const id = newRunId();
  const directory = runDir(id);
  fs.mkdirSync(directory, { recursive: true });
  const log = path.join(directory, 'native.log');
  const logFd = fs.openSync(log, 'a');
  const env = { ...process.env };
  for (const key of [
    'SUB_HUB_ACCESS_TOKEN',
    'SUB_HUB_CORS_ORIGINS',
    'SUB_HUB_SELF_HOSTS',
    'SUB_HUB_CONSOLE_ROOT',
    'SUB_HUB_BIND',
  ]) {
    delete env[key];
  }
  env.SUB_HUB_BIND = `127.0.0.1:${port}`;
  env.SUB_HUB_CONSOLE_ROOT = built.consoleRoot;
  const child = spawn(built.binary, [], {
    cwd: repoRoot,
    detached: true,
    env,
    stdio: ['ignore', logFd, logFd],
  });
  child.unref();
  fs.closeSync(logFd);
  const version = workspaceVersion();
  const run = {
    id,
    pid: child.pid,
    port,
    origin: `http://127.0.0.1:${port}`,
    version,
    versionBody: `sub-hub v${version} backend`,
    consoleRoot: built.consoleRoot,
    binary: built.binary,
    log,
    chromePid: null,
    debugPort: null,
    downloads: null,
    chromeLog: null,
    userDataDir: null,
  };
  saveRun(run);
  try {
    const started = Date.now();
    let ready = false;
    let lastError = 'native did not become ready';
    while (Date.now() - started < 30000) {
      if (!alive(run.pid)) {
        lastError = `native exited\n${tail(log)}`;
        break;
      }
      try {
        const expected = doctor(run);
        await doctorHttp(run, expected);
        run.version = expected.version;
        run.versionBody = expected.versionBody;
        ready = true;
        break;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        await sleep(200);
      }
    }
    if (!ready) {
      throw new Error(lastError);
    }
    saveRun(run);
    fs.writeFileSync(currentFile(), `${run.id}\n`);
    printRun(run);
    console.log('ready');
  } catch (error) {
    await killPid(run.pid);
    fs.rmSync(directory, { recursive: true, force: true });
    if (readCurrent() === id) {
      fs.rmSync(currentFile(), { force: true });
    }
    fail(error instanceof Error ? error.message : String(error));
  }
}

async function doctorCommand(opts) {
  const run = loadRun(opts);
  const expected = doctor(run);
  await doctorHttp(run, expected);
  run.version = expected.version;
  run.versionBody = expected.versionBody;
  saveRun(run);
  printRun(run);
}

function chromeBinary() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }
  for (const command of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    const found = which(command);
    if (found) {
      return found;
    }
  }
  fail('Google Chrome or Chromium is not on PATH. Set CHROME_PATH or install Chrome.');
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const pending = new Map();
    let next = 0;
    const rejectPending = (error) => {
      for (const item of pending.values()) {
        item.reject(error);
      }
      pending.clear();
    };
    ws.addEventListener('error', () => {
      rejectPending(new Error('CDP socket failed'));
      reject(new Error('CDP socket failed'));
    });
    ws.addEventListener('close', () => {
      rejectPending(new Error('CDP socket closed'));
    });
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(event.data);
      if (message.id === undefined || !pending.has(message.id)) {
        return;
      }
      const item = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) {
        item.reject(new Error(JSON.stringify(message.error)));
      } else {
        item.resolve(message.result ?? {});
      }
    });
    ws.addEventListener('open', () => {
      resolve({
        send(method, params = {}) {
          const id = next + 1;
          next = id;
          return new Promise((resolveSend, rejectSend) => {
            pending.set(id, { resolve: resolveSend, reject: rejectSend });
            ws.send(JSON.stringify({ id, method, params }));
          });
        },
        close() {
          ws.close();
        },
      });
    });
  });
}

async function evaluate(client, expression) {
  const result = await client.send('Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) {
    const details = result.exceptionDetails;
    throw new Error(details.exception?.description || details.text || 'evaluation failed');
  }
  return result.result?.value;
}

async function prepare(client, run) {
  await client.send('Page.enable');
  await client.send('Runtime.enable');
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 1280,
    height: 1800,
    deviceScaleFactor: 1,
    mobile: false,
  });
  if (run?.downloads) {
    try {
      await client.send('Page.setDownloadBehavior', {
        behavior: 'allow',
        downloadPath: run.downloads,
      });
    } catch (error) {
      if (run.chromeLog) {
        fs.appendFileSync(
          run.chromeLog,
          `Page.setDownloadBehavior: ${error instanceof Error ? error.message : error}\n`,
        );
      }
    }
  }
}

async function pageTarget(port) {
  const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const existing = list.find((item) => item.type === 'page' && item.webSocketDebuggerUrl);
  if (existing) {
    return existing;
  }
  const created = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' });
  if (!created.ok) {
    fail(`Chrome json/new returned ${created.status}`);
  }
  return created.json();
}

async function withPage(run, fn) {
  if (!run.chromePid || !alive(run.chromePid)) {
    fail('Chrome is not running. Run open first.');
  }
  const page = await pageTarget(run.debugPort);
  const client = await connect(page.webSocketDebuggerUrl);
  try {
    await prepare(client, run);
    return await fn(client);
  } finally {
    client.close();
  }
}

async function waitForDebug(port, pid, log) {
  const started = Date.now();
  while (Date.now() - started < 15000) {
    if (!alive(pid)) {
      throw new Error(`Chrome exited\n${tail(log)}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) {
        return;
      }
    } catch {
      // still starting
    }
    await sleep(100);
  }
  throw new Error(`Chrome DevTools did not open\n${tail(log)}`);
}

async function mouseClick(client, box) {
  if (!box.ok) {
    fail(box.detail || 'click target missing');
  }
  await client.send('Input.dispatchMouseEvent', {
    type: 'mousePressed',
    x: box.x,
    y: box.y,
    button: 'left',
    clickCount: 1,
  });
  await client.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased',
    x: box.x,
    y: box.y,
    button: 'left',
    clickCount: 1,
  });
}

function elementBoxExpression(finderSource) {
  return `(() => {
    const norm = (value) => (value || '').replace(/\\s+/g, ' ').trim();
    const target = (${finderSource});
    if (!target || !target.ok) {
      return target || { ok: false, detail: 'missing target' };
    }
    target.el.scrollIntoView({ block: 'center', inline: 'center' });
    const rect = target.el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) {
      return { ok: false, detail: 'target has no box' };
    }
    return { ok: true, x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
  })()`;
}

async function open(opts) {
  const run = loadRun(opts);
  doctor(run);
  if (!run.chromePid || !alive(run.chromePid)) {
    const debugPort = await freePort();
    const userDataDir = path.join(runDir(run.id), 'chrome-profile');
    const downloads = path.join(runDir(run.id), 'downloads');
    const chromeLog = path.join(runDir(run.id), 'chrome.log');
    fs.mkdirSync(userDataDir, { recursive: true });
    fs.mkdirSync(downloads, { recursive: true });
    const logFd = fs.openSync(chromeLog, 'a');
    const child = spawn(
      chromeBinary(),
      [
        '--headless=new',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-sync',
        '--disable-extensions',
        '--lang=en-US',
        '--accept-lang=en-US,en',
        '--window-size=1280,1800',
        '--remote-debugging-address=127.0.0.1',
        `--remote-debugging-port=${debugPort}`,
        '--remote-allow-origins=*',
        `--user-data-dir=${userDataDir}`,
        'about:blank',
      ],
      {
        detached: true,
        stdio: ['ignore', logFd, logFd],
      },
    );
    child.unref();
    fs.closeSync(logFd);
    try {
      await waitForDebug(debugPort, child.pid, chromeLog);
    } catch (error) {
      await killPid(child.pid);
      throw error;
    }
    run.chromePid = child.pid;
    run.debugPort = debugPort;
    run.downloads = downloads;
    run.chromeLog = chromeLog;
    run.userDataDir = userDataDir;
    saveRun(run);
    const version = await (await fetch(`http://127.0.0.1:${debugPort}/json/version`)).json();
    const browser = await connect(version.webSocketDebuggerUrl);
    try {
      try {
        await browser.send('Browser.setDownloadBehavior', {
          behavior: 'allow',
          downloadPath: downloads,
          eventsEnabled: true,
        });
      } catch (error) {
        fs.appendFileSync(
          chromeLog,
          `setDownloadBehavior: ${error instanceof Error ? error.message : error}\n`,
        );
      }
    } finally {
      browser.close();
    }
  }
  await withPage(run, async (client) => {
    await client.send('Page.addScriptToEvaluateOnNewDocument', {
      source: 'localStorage.clear();',
    });
    await client.send('Page.navigate', { url: `${run.origin}/` });
    const started = Date.now();
    let detail = '';
    while (Date.now() - started < 15000) {
      const state = await evaluate(
        client,
        `(() => {
          const origin = ${JSON.stringify(run.origin)};
          const versionBody = ${JSON.stringify(run.versionBody)};
          const buttons = [...document.querySelectorAll('button')].map((el) =>
            (el.innerText || '').replace(/\\s+/g, ' ').trim(),
          );
          const originField = document.getElementById('service-origin');
          const text = document.body ? document.body.innerText : '';
          const titleOk = document.title === 'Sub Hub Console';
          const english = buttons.includes('EN');
          const preview = buttons.includes('Preview');
          const originOk = originField !== null && originField.value === origin;
          const versionOk = text.includes(versionBody);
          return {
            ok: titleOk && english && preview && originOk && versionOk,
            detail: JSON.stringify({
              title: document.title,
              english,
              preview,
              origin: originField ? originField.value : null,
              versionOk,
            }),
          };
        })()`,
      );
      if (state?.ok) {
        console.log(`opened ${run.origin}`);
        return;
      }
      detail = state?.detail || '';
      await sleep(150);
    }
    const excerpt = await evaluate(
      client,
      'document.body ? document.body.innerText.slice(0, 700) : ""',
    ).catch(() => '');
    fail(`Console did not become ready (${detail})\n${excerpt}`);
  });
}

function requireId(opts, label) {
  const id = opts.id;
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]+$/.test(id)) {
    fail(`--id ${label} is missing or not an element id`);
  }
  if (id === 'access-token') {
    fail('refusing to read or fill the access token; verification stays anonymous');
  }
  return id;
}

function metaOf(opts) {
  const feature = opts.feature;
  const entry = opts.entry;
  if (typeof feature !== 'string' || typeof entry !== 'string') {
    fail('pass --feature and --entry');
  }
  if (!/^[a-z0-9-]+$/.test(feature) || !/^[a-z0-9-]+$/.test(entry)) {
    fail('--feature and --entry must be lowercase identifiers');
  }
  return { feature, entry };
}

function evidencePath(run, out) {
  if (typeof out !== 'string' || out.length === 0) {
    fail('missing evidence path');
  }
  const root = path.resolve(evidenceDir(run.id));
  const resolved = path.resolve(repoRoot, out);
  const relative = path.relative(root, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    fail(`path must stay under ${path.relative(repoRoot, root)}`);
  }
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  return resolved;
}

function writeMeta(file, run, meta, extra = '') {
  fs.writeFileSync(
    `${file}.meta`,
    `feature: ${meta.feature}\nentry: ${meta.entry}\nrun: ${run.id}\norigin: ${run.origin}\n${extra}`,
  );
}

function journal(run, line) {
  const file = path.join(evidenceDir(run.id), 'journal.log');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${new Date().toISOString()} ${line}\n`);
}

async function fill(opts) {
  const run = loadRun(opts);
  const id = requireId(opts, 'field');
  if (typeof opts.value !== 'string') {
    fail('pass --value');
  }
  const value = opts.value;
  await withPage(run, async (client) => {
    const box = await evaluate(
      client,
      elementBoxExpression(`(() => {
        const el = document.getElementById(${JSON.stringify(id)});
        if (!el) return { ok: false, detail: ${JSON.stringify(`missing #${id}`)} };
        return { ok: true, el };
      })()`),
    );
    await mouseClick(client, box);
    const filled = await evaluate(
      client,
      `(() => {
        const el = document.getElementById(${JSON.stringify(id)});
        const proto = el instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
        if (el._valueTracker) el._valueTracker.setValue('');
        setter.call(el, ${JSON.stringify(value)});
        el.dispatchEvent(new InputEvent('input', {
          bubbles: true,
          inputType: 'insertText',
          data: ${JSON.stringify(value)},
        }));
        return el.value;
      })()`,
    );
    if (filled !== value) {
      fail(`#${id} value did not stick`);
    }
  });
  console.log(`filled #${id}`);
}

async function click(opts) {
  const run = loadRun(opts);
  if (typeof opts.name !== 'string' || opts.name.length === 0) {
    fail('pass --name');
  }
  await withPage(run, async (client) => {
    const box = await evaluate(
      client,
      elementBoxExpression(`(() => {
        const want = ${JSON.stringify(opts.name)};
        const norm = (value) => (value || '').replace(/\\s+/g, ' ').trim();
        const candidates = [...document.querySelectorAll('button, a, summary')];
        const named = candidates.filter((el) =>
          norm(el.getAttribute('aria-label') || el.innerText || el.textContent) === want);
        const enabled = named.filter((el) => !el.disabled && el.getAttribute('aria-disabled') !== 'true');
        if (enabled.length !== 1) {
          return {
            ok: false,
            detail: 'matches=' + enabled.length + ' named=' + named.length + ' want=' + want,
          };
        }
        return { ok: true, el: enabled[0] };
      })()`),
    );
    await mouseClick(client, box);
  });
  console.log(`clicked ${opts.name}`);
}

async function key(opts) {
  const run = loadRun(opts);
  if (opts.key !== 'Enter') {
    fail('pass --key Enter');
  }
  const modifiers = (opts.ctrl ? 2 : 0) + (opts.meta ? 4 : 0);
  await withPage(run, async (client) => {
    const focused = await evaluate(
      client,
      `(() => {
        const el = document.activeElement;
        const main = document.querySelector('main');
        return { ok: !!(el && main && main.contains(el) && el !== main) };
      })()`,
    );
    if (!focused?.ok) {
      fail('focus is not inside a field in main. Fill a source first.');
    }
    const event = {
      key: 'Enter',
      code: 'Enter',
      windowsVirtualKeyCode: 13,
      modifiers,
    };
    await client.send('Input.dispatchKeyEvent', { type: 'keyDown', ...event });
    await client.send('Input.dispatchKeyEvent', { type: 'keyUp', ...event });
  });
  console.log(`pressed ${opts.ctrl ? 'Ctrl+' : ''}${opts.meta ? 'Meta+' : ''}Enter`);
}

async function waitText(opts) {
  const run = loadRun(opts);
  if (typeof opts.text !== 'string' || opts.text.length === 0) {
    fail('pass --text');
  }
  const timeout = Number(opts.timeout || 15000);
  await withPage(run, async (client) => {
    const started = Date.now();
    while (Date.now() - started < timeout) {
      const found = await evaluate(
        client,
        `document.body ? document.body.innerText.includes(${JSON.stringify(opts.text)}) : false`,
      );
      if (found) {
        console.log('ok');
        return;
      }
      await sleep(100);
    }
    const excerpt = await evaluate(
      client,
      'document.body ? document.body.innerText.slice(0, 700) : ""',
    ).catch(() => '');
    fail(`timed out waiting for ${JSON.stringify(opts.text)}\n${excerpt}`);
  });
}

async function waitValue(opts) {
  const run = loadRun(opts);
  const id = requireId(opts, 'field');
  if (typeof opts.value !== 'string') {
    fail('pass --value');
  }
  const timeout = Number(opts.timeout || 15000);
  await withPage(run, async (client) => {
    const started = Date.now();
    let actual = '';
    while (Date.now() - started < timeout) {
      actual = await evaluate(
        client,
        `(() => {
          const el = document.getElementById(${JSON.stringify(id)});
          return el ? el.value : '';
        })()`,
      );
      if (actual === opts.value) {
        console.log('ok');
        return;
      }
      await sleep(100);
    }
    fail(`timed out waiting for #${id} to equal the expected value (length ${String(actual).length})`);
  });
}

async function read(opts) {
  const run = loadRun(opts);
  const id = requireId(opts, 'field');
  await withPage(run, async (client) => {
    const value = await evaluate(
      client,
      `(() => {
        const el = document.getElementById(${JSON.stringify(id)});
        if (!el) return null;
        return el.value;
      })()`,
    );
    if (value === null) {
      fail(`missing #${id}`);
    }
    console.log(value);
  });
}

async function text(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  const file = evidencePath(run, opts.out);
  await withPage(run, async (client) => {
    const value = await evaluate(client, 'document.body ? document.body.innerText : ""');
    fs.writeFileSync(file, value);
  });
  writeMeta(file, run, meta);
  journal(run, `text feature=${meta.feature} entry=${meta.entry} out=${path.relative(repoRoot, file)}`);
  console.log(path.relative(repoRoot, file));
}

async function snapshot(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  const file = evidencePath(run, opts.out);
  await withPage(run, async (client) => {
    const value = await evaluate(
      client,
      `(() => {
        const norm = (item) => (item || '').replace(/\\s+/g, ' ').trim();
        const roleOf = (el) => {
          const explicit = el.getAttribute('role');
          if (explicit) return explicit;
          const tag = el.tagName;
          if (tag === 'BUTTON') return 'button';
          if (tag === 'A') return 'link';
          if (tag === 'SUMMARY') return 'summary';
          if (tag === 'TEXTAREA') return 'textbox';
          if (tag === 'INPUT') return el.type === 'password' ? 'password' : 'textbox';
          if (tag === 'H1') return 'heading';
          return tag.toLowerCase();
        };
        const lines = ['role\\tname\\tid\\tvalue\\tpressed'];
        for (const el of document.querySelectorAll('button, a, summary, input, textarea, h1, [role]')) {
          const name = norm(el.getAttribute('aria-label') || el.innerText || '');
          let value = '';
          if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
            value = el.type === 'password' || el.id === 'access-token'
              ? (el.value ? '[redacted]' : '')
              : el.value;
          }
          lines.push([
            roleOf(el),
            name,
            el.id || '',
            value,
            el.getAttribute('aria-pressed') || '',
          ].join('\\t'));
        }
        return lines.join('\\n');
      })()`,
    );
    fs.writeFileSync(file, `${value}\n`);
  });
  writeMeta(file, run, meta);
  journal(run, `snapshot feature=${meta.feature} entry=${meta.entry} out=${path.relative(repoRoot, file)}`);
  console.log(path.relative(repoRoot, file));
}

async function screenshot(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  const file = evidencePath(run, opts.out);
  if (opts.scroll !== undefined && !/^(pre|summary|#[A-Za-z0-9_-]+)$/.test(opts.scroll)) {
    fail('--scroll must be pre, summary, or an #id');
  }
  await withPage(run, async (client) => {
    if (typeof opts.scroll === 'string') {
      const scrolled = await evaluate(
        client,
        `(() => {
          const el = document.querySelector(${JSON.stringify(opts.scroll)});
          if (!el) return false;
          el.scrollIntoView({ block: 'start' });
          window.scrollBy(0, -96);
          return true;
        })()`,
      );
      if (!scrolled) {
        fail(`missing ${opts.scroll}`);
      }
    }
    const image = await client.send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(file, Buffer.from(image.data, 'base64'));
  });
  writeMeta(file, run, meta);
  journal(run, `screenshot feature=${meta.feature} entry=${meta.entry} out=${path.relative(repoRoot, file)}`);
  console.log(path.relative(repoRoot, file));
}

async function fetchShown(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  const bodyFile = evidencePath(run, opts.body);
  const headerFile = evidencePath(run, opts.headers);
  let url = '';
  await withPage(run, async (client) => {
    url = await evaluate(
      client,
      `(() => {
        const el = document.getElementById('subscription-url');
        return el ? el.value : '';
      })()`,
    );
  });
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail('Subscription URL textarea is empty or not a URL');
  }
  if (parsed.origin !== run.origin || parsed.pathname !== '/sub') {
    fail('fetch-shown only GETs this run origin at anonymous /sub');
  }
  const response = await fetchText(url);
  const headerLines = [`status: ${response.status}`];
  for (const name of [
    'content-type',
    'content-disposition',
    'profile-update-interval',
    'subscription-userinfo',
    'x-subconverter-result',
    'x-subconverter-skipped',
    'x-subconverter-omitted-rules',
  ]) {
    const value = response.headers.get(name);
    if (value) {
      headerLines.push(`${name}: ${value}`);
    }
  }
  fs.writeFileSync(bodyFile, response.body);
  fs.writeFileSync(headerFile, `${headerLines.join('\n')}\n`);
  writeMeta(bodyFile, run, meta, `status: ${response.status}\n`);
  journal(
    run,
    `fetch-shown feature=${meta.feature} entry=${meta.entry} status=${response.status} body=${path.relative(repoRoot, bodyFile)}`,
  );
  console.log(`status=${response.status}`);
  console.log(path.relative(repoRoot, bodyFile));
}

async function versionGet(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  const file = evidencePath(run, opts.out);
  const response = await fetchText(`${run.origin}/version`);
  fs.writeFileSync(file, response.body);
  writeMeta(file, run, meta, `status: ${response.status}\n`);
  journal(run, `version-get feature=${meta.feature} entry=${meta.entry} status=${response.status}`);
  console.log(`status=${response.status}`);
  if (response.status !== 200 || response.body !== run.versionBody) {
    fail(`GET /version returned ${response.status} body ${JSON.stringify(response.body)}`);
  }
  console.log(path.relative(repoRoot, file));
}

async function waitDownload(opts) {
  const run = loadRun(opts);
  const meta = metaOf(opts);
  if (typeof opts.name !== 'string' || !/^[A-Za-z0-9._-]+$/.test(opts.name)) {
    fail('pass --name as a file name');
  }
  if (!run.downloads) {
    fail('Chrome downloads directory is missing. Run open first.');
  }
  const file = evidencePath(run, opts.out);
  const timeout = Number(opts.timeout || 10000);
  const started = Date.now();
  let found = '';
  while (Date.now() - started < timeout) {
    const names = fs.readdirSync(run.downloads);
    found = names.find((name) => name === opts.name) || '';
    if (found && !names.some((name) => name.endsWith('.crdownload'))) {
      break;
    }
    found = '';
    await sleep(150);
  }
  if (!found) {
    fail(`download ${opts.name} did not appear in the Chrome download directory`);
  }
  fs.copyFileSync(path.join(run.downloads, found), file);
  writeMeta(file, run, meta);
  journal(run, `wait-download feature=${meta.feature} entry=${meta.entry} out=${path.relative(repoRoot, file)}`);
  console.log(path.relative(repoRoot, file));
}

async function cleanup(opts) {
  const id = opts.run || readCurrent();
  if (!id) {
    fail('no verification run to clean up');
  }
  assertRunId(id);
  const file = path.join(runDir(id), 'run.json');
  if (!fs.existsSync(file)) {
    fail(`unknown run ${id}`);
  }
  const run = JSON.parse(fs.readFileSync(file, 'utf8'));
  await killPid(run.chromePid);
  await killPid(run.pid);
  fs.rmSync(runDir(id), { recursive: true, force: true });
  if (readCurrent() === id) {
    fs.rmSync(currentFile(), { force: true });
  }
  console.log(`cleaned ${id}`);
  console.log(`evidence=${path.relative(repoRoot, evidenceDir(id))}`);
}

async function main() {
  assertNode();
  assertRepo();
  const { command, opts } = parseArgs(process.argv.slice(2));
  switch (command) {
    case 'launch':
      await launch();
      return;
    case 'doctor':
      await doctorCommand(opts);
      return;
    case 'open':
      await open(opts);
      return;
    case 'fill':
      await fill(opts);
      return;
    case 'click':
      await click(opts);
      return;
    case 'key':
      await key(opts);
      return;
    case 'wait':
      await waitText(opts);
      return;
    case 'wait-value':
      await waitValue(opts);
      return;
    case 'read':
      await read(opts);
      return;
    case 'text':
      await text(opts);
      return;
    case 'snapshot':
      await snapshot(opts);
      return;
    case 'screenshot':
      await screenshot(opts);
      return;
    case 'fetch-shown':
      await fetchShown(opts);
      return;
    case 'version-get':
      await versionGet(opts);
      return;
    case 'wait-download':
      await waitDownload(opts);
      return;
    case 'cleanup':
      await cleanup(opts);
      return;
    default:
      fail(
        'usage: verify-sub-hub.mjs launch|doctor|open|fill|click|key|wait|wait-value|read|text|snapshot|screenshot|fetch-shown|version-get|wait-download|cleanup',
      );
  }
}

try {
  await main();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
