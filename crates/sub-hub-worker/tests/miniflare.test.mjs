import assert from "node:assert/strict";
import test from "node:test";
import { Miniflare, createFetchMock } from "miniflare";

const VLESS = concat(
  "vless://01234567-89ab-cdef-0123-456789abcdef",
  "@example.com:443#Alpha",
);

const SINGLE_VLESS_YAML = concat(
  "mode: rule\n",
  "proxies:\n",
  "- name: Alpha\n",
  "  type: vless\n",
  "  server: example.com\n",
  "  port: 443\n",
  "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
  "  udp: true\n",
  "  encryption: none\n",
  "  network: tcp\n",
  "proxy-groups:\n",
  "- name: PROXY\n",
  "  type: select\n",
  "  proxies:\n",
  "  - AUTO\n",
  "  - Alpha\n",
  "  - DIRECT\n",
  "- name: AUTO\n",
  "  type: url-test\n",
  "  proxies:\n",
  "  - Alpha\n",
  "  url: https://www.gstatic.com/generate_204\n",
  "  interval: 300\n",
  "rules:\n",
  "- MATCH,PROXY\n",
);

function concat(...parts) {
  return parts.join("");
}

function runtime(bindings = {}, fetchMock) {
  const options = {
    // Miniflare 4.20260730.0 cannot accept a date later than its bundled workerd.
    compatibilityDate: "2026-07-30",
    compatibilityFlags: ["global_fetch_strictly_public"],
    modules: true,
    modulesRules: [
      { type: "CompiledWasm", include: ["**/*.wasm"], fallthrough: true },
      { type: "ESModule", include: ["**/*.js"], fallthrough: true },
    ],
    scriptPath: "build/worker/shim.mjs",
    bindings,
  };
  if (fetchMock !== undefined) options.fetchMock = fetchMock;
  return new Miniflare(options);
}

function mockedRemote(path, reply) {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const interceptor = fetchMock
    .get("https://example.com")
    .intercept({ path, method: "GET" });
  if (typeof reply === "function") {
    interceptor.reply(reply);
  } else {
    interceptor.reply(reply.statusCode, reply.data, reply.responseOptions);
  }
  return fetchMock;
}

function applicationHeaders(response) {
  const result = {};
  for (const name of [
    "allow",
    "cache-control",
    "content-type",
    "subscription-userinfo",
  ]) {
    const value = response.headers.get(name);
    if (value !== null) result[name] = value;
  }
  return result;
}

test("host-visible application contract is table driven", async (t) => {
  const mf = runtime();
  t.after(() => mf.dispose());

  const vectors = [
    {
      name: "version",
      url: "https://worker.example/version",
      method: "GET",
      status: 200,
      body: "sub-hub v0.1.0 backend",
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "invalid version query",
      url: "https://worker.example/version?x=1",
      method: "GET",
      status: 400,
      body: "Invalid request!",
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "unknown path",
      url: "https://worker.example/sub/",
      method: "GET",
      status: 404,
      body: "Not Found",
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "sub method",
      url: "https://worker.example/sub",
      method: "POST",
      status: 405,
      body: "Method Not Allowed",
      headers: {
        allow: "GET, HEAD",
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "version method",
      url: "https://worker.example/version",
      method: "HEAD",
      status: 405,
      body: "",
      headers: {
        allow: "GET",
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "uri too long before unknown path",
      url: `https://worker.example/${"x".repeat(8_192)}`,
      method: "GET",
      status: 414,
      body: "URI Too Long",
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
    {
      name: "head invalid request suppresses body",
      url: "https://worker.example/sub",
      method: "HEAD",
      status: 400,
      body: "",
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain;charset=utf-8",
      },
    },
  ];

  for (const vector of vectors) {
    const response = await mf.dispatchFetch(vector.url, {
      method: vector.method,
    });
    assert.equal(response.status, vector.status, `${vector.name} status`);
    assert.deepEqual(
      applicationHeaders(response),
      vector.headers,
      `${vector.name} application headers`,
    );
    assert.equal(await response.text(), vector.body, `${vector.name} body`);
  }
});

test("invalid self-host binding returns the fixed application 500", async (t) => {
  const mf = runtime({ SUB_HUB_SELF_HOSTS: "one.example,,two.example" });
  t.after(() => mf.dispose());

  const response = await mf.dispatchFetch("https://worker.example/version");

  assert.equal(response.status, 500);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), "text/plain;charset=utf-8");
  assert.equal(await response.text(), "Internal Server Error");
});

test("present non-string self-host binding returns the fixed application 500", async (t) => {
  const mf = runtime({ SUB_HUB_SELF_HOSTS: { invalid: true } });
  t.after(() => mf.dispose());

  const response = await mf.dispatchFetch("https://worker.example/version");

  assert.equal(response.status, 500);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), "text/plain;charset=utf-8");
  assert.equal(await response.text(), "Internal Server Error");
});

test("fixed configuration failure suppresses the HEAD body", async (t) => {
  const mf = runtime({ SUB_HUB_SELF_HOSTS: "one.example,,two.example" });
  t.after(() => mf.dispose());

  const response = await mf.dispatchFetch("https://worker.example/version", {
    method: "HEAD",
  });

  assert.equal(response.status, 500);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), "text/plain;charset=utf-8");
  assert.equal(await response.text(), "");
});

test("configured access token protects /sub and leaves /version public", async (t) => {
  const mf = runtime({ SUB_HUB_ACCESS_TOKEN: "deployer-token" });
  t.after(() => mf.dispose());

  const version = await mf.dispatchFetch("https://worker.example/version");
  assert.equal(version.status, 200);
  assert.equal(await version.text(), "sub-hub v0.1.0 backend");

  const missing = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${encodeURIComponent(VLESS)}`,
  );
  assert.equal(missing.status, 401);
  assert.equal(await missing.text(), "Unauthorized!");

  const wrong = await mf.dispatchFetch(
    `https://worker.example/sub/wrong-token?target=clash&url=${encodeURIComponent(VLESS)}`,
  );
  assert.equal(wrong.status, 401);
  assert.equal(await wrong.text(), "Unauthorized!");

  const ok = await mf.dispatchFetch(
    `https://worker.example/sub/deployer-token?target=clash&url=${encodeURIComponent(VLESS)}`,
  );
  assert.equal(ok.status, 200);
  assert.equal(await ok.text(), SINGLE_VLESS_YAML);
});

test("target=mihomo is a clash synonym and target=quanx renders Quantumult X", async (t) => {
  const mf = runtime();
  t.after(() => mf.dispose());

  const mihomo = await mf.dispatchFetch(
    `https://worker.example/sub?target=mihomo&url=${encodeURIComponent(VLESS)}`,
  );
  assert.equal(mihomo.status, 200);
  assert.equal(await mihomo.text(), SINGLE_VLESS_YAML);

  const quanx = await mf.dispatchFetch(
    `https://worker.example/sub?target=quanx&url=${encodeURIComponent(VLESS)}`,
  );
  assert.equal(quanx.status, 200);
  assert.equal(quanx.headers.get("content-disposition"), 'attachment; filename="sub-hub-quanx.conf"');
  assert.equal(
    await quanx.text(),
    [
      "[general]",
      "server_check_url=https://www.gstatic.com/generate_204",
      "",
      "[server_local]",
      "vless=example.com:443, method=none, password=01234567-89ab-cdef-0123-456789abcdef, udp-relay=true, fast-open=false, tag=Alpha",
      "",
      "[policy]",
      "static = PROXY, AUTO, Alpha, direct",
      "url-latency-benchmark = AUTO, Alpha, check-interval=300, alive-checking=true, tolerance=0",
      "",
      "[filter_local]",
      "final, PROXY",
      "",
    ].join("\n"),
  );
});

test("invalid access token binding returns the fixed application 500", async (t) => {
  const mf = runtime({ SUB_HUB_ACCESS_TOKEN: "has space" });
  t.after(() => mf.dispose());

  const response = await mf.dispatchFetch("https://worker.example/version");
  assert.equal(response.status, 500);
  assert.equal(await response.text(), "Internal Server Error");
});

test("non-443 remote source is rejected before fetch", async (t) => {
  const mf = runtime();
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com:8443/sub");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 400);
  assert.deepEqual(applicationHeaders(response), {
    "cache-control": "no-store",
    "content-type": "text/plain;charset=utf-8",
  });
  assert.equal(await response.text(), "Invalid request!");
});

test("remote fetch is constrained and preserves the shared response", async (t) => {
  let observed;
  const fetchMock = mockedRemote("/sub", (request) => {
    observed = request;
    return {
      statusCode: 200,
      data: VLESS,
      responseOptions: {
        headers: {
          "Content-Length": String(Buffer.byteLength(VLESS)),
          "Subscription-UserInfo": "total=3; upload=1; download=2",
        },
      },
    };
  });
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/sub");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
    {
      headers: {
        Authorization: "Bearer caller-secret",
        Cookie: "session=caller-secret",
        "X-Caller-Header": "must-not-forward",
      },
    },
  );

  assert.equal(
    response.status,
    200,
    `${await response.clone().text()} outbound=${observed?.url ?? "not-called"}`,
  );
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("subscription-userinfo"), "upload=1; download=2; total=3");
  assert.equal(await response.text(), SINGLE_VLESS_YAML);
  assert.equal(observed.method, "GET");
  assert.equal(observed.headers.accept, "*/*");
  assert.equal(observed.headers["accept-encoding"], "identity");
  assert.equal(observed.headers["cache-control"], "no-store");
  assert.equal(observed.headers.authorization, undefined);
  assert.equal(observed.headers.cookie, undefined);
  assert.equal(observed.headers["x-caller-header"], undefined);
});

test("remote ACL4SSR config and Rule Set render through the Worker host", async (t) => {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://config.example")
    .intercept({ path: "/acl.ini", method: "GET" })
    .reply(
      200,
      concat(
        "[custom]\n",
        "custom_proxy_group=PROXY`select`.*\n",
        "ruleset=PROXY,https://rules.example/list\n",
        "ruleset=PROXY,[]FINAL\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
      ),
    );
  fetchMock
    .get("https://rules.example")
    .intercept({ path: "/list", method: "GET" })
    .reply(200, "DOMAIN,example.org\n");
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const config = encodeURIComponent("https://config.example/acl.ini");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${encodeURIComponent(VLESS)}&config=${config}`,
  );

  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(applicationHeaders(response), {
    "cache-control": "no-store",
    "content-type": "text/plain;charset=utf-8",
  });
  const body = await response.text();
  assert.match(body, /- name: PROXY\n  type: select\n  proxies:\n  - Alpha/);
  assert.match(body, /- DOMAIN,example\.org,PROXY/);
  assert.match(body, /- MATCH,PROXY/);
  fetchMock.assertNoPendingInterceptors();
});

test("relative redirects are manual and each hop is constrained", async (t) => {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock.get("https://example.com")
    .intercept({ path: "/start", method: "GET" })
    .reply(302, "", { headers: { Location: "/final" } });
  fetchMock.get("https://example.com")
    .intercept({ path: "/final", method: "GET" })
    .reply(200, VLESS);
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/start");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 200);
  fetchMock.assertNoPendingInterceptors();
});

test("redirect Location may contain a legal comma", async (t) => {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock.get("https://example.com")
    .intercept({ path: "/start", method: "GET" })
    .reply(302, "", { headers: { Location: "/final,a" } });
  fetchMock.get("https://example.com")
    .intercept({ path: "/final,a", method: "GET" })
    .reply(200, VLESS);
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/start");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 200);
  fetchMock.assertNoPendingInterceptors();
});

test("combined metadata is ignored instead of forwarded", async (t) => {
  const fetchMock = mockedRemote("/sub", {
    statusCode: 200,
    data: VLESS,
    responseOptions: {
      headers: {
        "Subscription-UserInfo": [
          "upload=1; download=2; total=3",
          "upload=4; download=5; total=6",
        ],
      },
    },
  });
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/sub");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 200);
  assert.deepEqual(applicationHeaders(response), {
    "cache-control": "no-store",
    "content-type": "text/plain;charset=utf-8",
  });
  assert.equal(await response.text(), SINGLE_VLESS_YAML);
});

test("redirect to a non-443 port is a deterministic bad gateway", async (t) => {
  const fetchMock = mockedRemote("/start", {
    statusCode: 302,
    data: "",
    responseOptions: { headers: { Location: "https://example.com:8443/final" } },
  });
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/start");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 502);
  assert.deepEqual(applicationHeaders(response), {
    "cache-control": "no-store",
    "content-type": "text/plain;charset=utf-8",
  });
  assert.equal(await response.text(), "Bad Gateway");
  fetchMock.assertNoPendingInterceptors();
});

test("upstream failure maps to bad gateway", async (t) => {
  const fetchMock = mockedRemote("/sub", {
    statusCode: 500,
    data: "upstream failed",
  });
  const mf = runtime({}, fetchMock);
  t.after(() => mf.dispose());
  const remote = encodeURIComponent("https://example.com/sub");

  const response = await mf.dispatchFetch(
    `https://worker.example/sub?target=clash&url=${remote}`,
  );

  assert.equal(response.status, 502);
  assert.deepEqual(applicationHeaders(response), {
    "cache-control": "no-store",
    "content-type": "text/plain;charset=utf-8",
  });
  assert.equal(await response.text(), "Bad Gateway");
});
