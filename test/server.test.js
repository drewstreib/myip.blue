// Smoke tests for the things that are easy to inadvertently re-break:
// the path-traversal guard, HTML escaping of attacker-controlled headers, the
// loopback-only trust boundary for CF-* headers, and the response contract.
//
// Run: npm test     (node --test, no dependencies)

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import os from "node:os";

const PORT = 18080;
let server;

// A non-loopback address for this host, used to prove that CF-* headers are
// NOT trusted from off-box. Without it that half of the check is untested.
function lanAddress() {
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const i of ifaces ?? []) {
      if (i.family === "IPv4" && !i.internal) return i.address;
    }
  }
  return null;
}

before(async () => {
  server = spawn(process.execPath, ["index.js"], {
    env: { ...process.env, HTTP_PORT: String(PORT), TLS_KEY: "/nonexistent", TLS_CERT: "/nonexistent" },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(`http://127.0.0.1:${PORT}/ip`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error("server did not start");
});

after(() => server?.kill("SIGTERM"));

const get = (path, opts) => fetch(`http://127.0.0.1:${PORT}${path}`, opts);

test("/ip returns a bare IP", async () => {
  const res = await get("/ip");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /text\/plain/);
  assert.equal((await res.text()).trim(), "127.0.0.1");
});

test("/ip and /ip/ both resolve", async () => {
  assert.equal((await get("/ip")).status, 200);
  assert.equal((await get("/ip/")).status, 200);
});

test("curl and wget user-agents get plain text at /", async () => {
  for (const ua of ["curl/8.7.1", "Wget/1.21"]) {
    const res = await get("/", { headers: { "user-agent": ua } });
    assert.match(res.headers.get("content-type"), /text\/plain/, ua);
    assert.equal((await res.text()).trim(), "127.0.0.1", ua);
  }
});

test("a browser user-agent gets HTML at /", async () => {
  const res = await get("/", { headers: { "user-agent": "Mozilla/5.0 Chrome/120" } });
  assert.match(res.headers.get("content-type"), /text\/html/);
  assert.match(await res.text(), /Your public IP address/);
});

test("/json reports the connection", async () => {
  const body = await (await get("/json")).json();
  assert.equal(body.clientIp, "127.0.0.1");
  assert.equal(body.connection.protocol, "http");
  assert.equal(body.connection.remoteFamily, "IPv4");
  assert.equal(typeof body.connection.remotePort, "number");
});

test("unknown paths return the 404 string", async () => {
  const res = await get("/nope");
  assert.equal(res.status, 404);
  assert.equal(await res.text(), "Sorry! Blue can't find that!");
});

test("responses are not cacheable", async () => {
  assert.match((await get("/ip")).headers.get("cache-control"), /no-store/);
});

test("static files are served", async () => {
  const res = await get("/static/blue.jpg");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "image/jpeg");
});

test("🛑 path traversal out of static/ is refused", async () => {
  const attempts = [
    "/static/../package.json",
    "/static/../../etc/passwd",
    "/static/%2e%2e/package.json",
    "/static/..%2fpackage.json",
    "/static/....//package.json",
  ];
  for (const path of attempts) {
    const res = await get(path);
    assert.equal(res.status, 404, `${path} should not be served`);
    assert.doesNotMatch(await res.text(), /myip\.blue|root:/, `${path} leaked content`);
  }
});

test("🛑 header values are HTML-escaped in the page", async () => {
  const res = await get("/", {
    headers: { "user-agent": "Mozilla/5.0", "x-evil": "<script>alert(1)</script>" },
  });
  const body = await res.text();
  assert.ok(body.includes("&lt;script&gt;"), "payload should be escaped");
  assert.ok(!body.includes("<script>alert(1)</script>"), "raw script tag must not appear");
});

test("🛑 CF-Connecting-IP is honoured from loopback (the tunnel path)", async () => {
  const body = await (await get("/json", {
    headers: { "cf-connecting-ip": "203.0.113.7", "cf-ipcountry": "US", "cf-ray": "abc123-SJC" },
  })).json();
  assert.equal(body.clientIp, "203.0.113.7");
  assert.equal(body.connection.via, "cloudflare");
  assert.equal(body.connection.country, "US");
  assert.equal(body.connection.colo, "SJC");
});

test("🛑 CF-Connecting-IP is IGNORED from a non-loopback address (no spoofing)", async (t) => {
  const lan = lanAddress();
  if (!lan) return t.skip("no non-loopback interface available");
  const res = await fetch(`http://${lan}:${PORT}/json`, {
    headers: { "cf-connecting-ip": "203.0.113.7" },
  });
  const body = await res.json();
  assert.notEqual(body.clientIp, "203.0.113.7", "spoofed CF header must not set clientIp");
  assert.equal(body.connection.via, undefined, "must not be treated as an edge request");
});

test("non-GET methods are rejected", async () => {
  const res = await get("/", { method: "POST" });
  assert.equal(res.status, 405);
});
