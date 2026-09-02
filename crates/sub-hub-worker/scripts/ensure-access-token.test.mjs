import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  classifySecretList,
  decide,
  generateToken,
  parseLastJsonArray,
  parseList,
  putAndDeploy,
  secretsFileJson,
  splitArgv,
} from "./ensure-access-token.mjs";

test("parseList accepts S15 values and comma or newline lists", () => {
  assert.deepEqual(parseList("deployer-token"), ["deployer-token"]);
  assert.deepEqual(parseList("alpha,bravo"), ["alpha", "bravo"]);
  assert.deepEqual(parseList("alpha\nbravo\n"), ["alpha", "bravo"]);
  assert.deepEqual(parseList("alpha,\n,bravo"), ["alpha", "bravo"]);
  assert.deepEqual(parseList("alpha, alpha"), ["alpha"]);
});

test("parseList rejects empty present blobs, junk, and a ninth unique token", () => {
  assert.throws(() => parseList(""));
  assert.throws(() => parseList("   "));
  assert.throws(() => parseList(","));
  assert.throws(() => parseList("\n"));
  assert.throws(() => parseList("has space"));
  assert.throws(() => parseList("a".repeat(2049)));

  const atCap = `alpha${",".repeat(2043)}`;
  assert.equal(Buffer.byteLength(atCap, "utf8"), 2048);
  assert.deepEqual(parseList(atCap), ["alpha"]);
  assert.throws(() => parseList(`${atCap},`));

  const eight = Array.from({ length: 8 }, (_, index) => `token${index}`).join(",");
  assert.equal(parseList(eight).length, 8);
  assert.throws(() => parseList(`${eight},token8`));
});

test("secrets-file JSON round-trips a newline-separated blob", () => {
  const blob = "alpha\nbravo";
  const encoded = secretsFileJson(blob);
  assert.equal(JSON.parse(encoded).SUB_HUB_ACCESS_TOKEN, blob);
  assert.doesNotThrow(() => JSON.parse(encoded));
});

test("splitArgv copies targeting flags and keeps ensure flags out of wrangler argv", () => {
  const split = splitArgv([
    "--deploy",
    "--tokens-file",
    "tokens.txt",
    "--name",
    "other-worker",
    "--env",
    "staging",
    "--preview-alias",
    "foo",
  ]);
  assert.equal(split.flags.deploy, true);
  assert.equal(split.flags.tokensFile, "tokens.txt");
  assert.deepEqual(split.targeting, ["--name", "other-worker", "--env", "staging"]);
  assert.deepEqual(split.forwarded, ["--preview-alias", "foo"]);
  assert.throws(() => splitArgv(["--tokens", "alpha"]), /tokens-file or --from-env/);
  const ensureArgv = ["--deploy", "--tokens-file", "tokens.txt", "--name", "other-worker"];
  assert.ok(!ensureArgv.includes("alpha"));
  assert.ok(!ensureArgv.includes("bravo"));
  assert.ok(!ensureArgv.includes("deployer-token"));
});

test("decide refuses CI and ambient-less puts without an explicit blob", () => {
  assert.equal(
    decide({
      ci: true,
      listResult: "absent",
      flags: {},
    }),
    "refuse-ci",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: null,
      flags: { tokensFile: "tokens.txt" },
    }),
    "put-operator",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "indeterminate",
      flags: { fromEnv: true },
    }),
    "put-operator",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "indeterminate",
      flags: { deploy: true },
    }),
    "abort-indeterminate",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "present",
      flags: { deploy: true },
    }),
    "leave-existing",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "present",
      flags: { deploy: true, replace: true },
    }),
    "generate-and-put",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "absent",
      flags: { deploy: true },
    }),
    "generate-and-put",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: "present",
      flags: { replace: true },
    }),
    "abort-usage",
  );
  assert.equal(
    decide({
      ci: false,
      listResult: null,
      flags: { replace: true, preview: true },
    }),
    "abort-usage",
  );
});

test("classifySecretList is fail-closed unless a JSON array is parsed", () => {
  assert.equal(classifySecretList("", 0), "indeterminate");
  assert.equal(classifySecretList("[]", 1), "indeterminate");
  assert.equal(classifySecretList("[]", 0), "absent");
  assert.equal(
    classifySecretList('[{"name":"SUB_HUB_ACCESS_TOKEN","type":"secret_text"}]', 0),
    "present",
  );
  assert.equal(
    classifySecretList(
      'banner\n[{"name":"OTHER"}]\n[{"name":"SUB_HUB_ACCESS_TOKEN"}]\n',
      0,
    ),
    "present",
  );
  assert.deepEqual(parseLastJsonArray("not json"), null);
});

test("generateToken is 32 lowercase hex", () => {
  const token = generateToken();
  assert.match(token, /^[0-9a-f]{32}$/);
});

test("putAndDeploy writes a secrets-file then deletes it without echoing the blob", () => {
  const blob = "operator-secret-blob";
  let seenArgs;
  let secretsFile;
  const runWrangler = (args) => {
    seenArgs = args;
    const index = args.indexOf("--secrets-file");
    assert.ok(index >= 0);
    secretsFile = args[index + 1];
    assert.ok(secretsFile);
    assert.ok(fs.existsSync(secretsFile));
    assert.equal(
      JSON.parse(fs.readFileSync(secretsFile, "utf8")).SUB_HUB_ACCESS_TOKEN,
      blob,
    );
    assert.ok(!args.includes(blob));
    assert.ok(!JSON.stringify(args).includes(blob));
    return { status: 0, stdout: "Published https://sub-hub.example.workers.dev\n", stderr: "" };
  };
  const chunks = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, callback) => {
    chunks.push(String(chunk));
    if (typeof encoding === "function") {
      encoding();
      return true;
    }
    if (typeof callback === "function") {
      callback();
    }
    return true;
  };
  try {
    putAndDeploy("deploy", [], [], blob, runWrangler);
  } finally {
    process.stdout.write = write;
  }
  assert.ok(seenArgs.includes("--secrets-file"));
  assert.ok(!seenArgs.includes(blob));
  assert.ok(!fs.existsSync(secretsFile));
  assert.ok(!chunks.join("").includes(blob));
});
