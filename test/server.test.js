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

test("/ defaults to JSON for machines (curl, wget, libraries)", async () => {
  // Changed 2026-08-02: this used to return a bare IP. /ip is now the only
  // bare-string endpoint.
  for (const ua of ["curl/8.7.1", "Wget/1.21", "python-requests/2.32", "Go-http-client/2.0"]) {
    const res = await get("/", { headers: { "user-agent": ua, accept: "*/*" } });
    assert.match(res.headers.get("content-type"), /application\/json/, ua);
    const body = await res.json();
    assert.equal(body.clientIp, "127.0.0.1", ua);
  }
});

test("/ returns HTML when the client asks for text/html", async () => {
  const res = await get("/", { headers: { accept: "text/html,application/xhtml+xml,*/*;q=0.8" } });
  assert.match(res.headers.get("content-type"), /text\/html/);
  assert.match(await res.text(), /Your public IP address/);
});

test("/ returns HTML for a Mozilla user-agent even without an Accept header", async () => {
  const res = await get("/", { headers: { "user-agent": "Mozilla/5.0 Chrome/120", accept: "*/*" } });
  assert.match(res.headers.get("content-type"), /text\/html/);
});

test("Accept: application/json beats a browser user-agent", async () => {
  const res = await get("/", {
    headers: { "user-agent": "Mozilla/5.0 Chrome/120", accept: "application/json" },
  });
  assert.match(res.headers.get("content-type"), /application\/json/);
});

test("Accept: text/plain gets the bare IP (the scripting escape hatch)", async () => {
  const res = await get("/", { headers: { accept: "text/plain", "user-agent": "curl/8.7.1" } });
  assert.match(res.headers.get("content-type"), /text\/plain/);
  assert.equal((await res.text()).trim(), "127.0.0.1");
});

test("a real browser Accept header still wins over text/plain in the same list", async () => {
  // Browsers send text/html AND other types; html must win.
  const res = await get("/", {
    headers: { accept: "text/html,text/plain;q=0.9,*/*;q=0.8" },
  });
  assert.match(res.headers.get("content-type"), /text\/html/);
});

test("/html forces the page even for a machine client", async () => {
  for (const p of ["/html", "/html/"]) {
    const res = await get(p, { headers: { "user-agent": "curl/8.7.1", accept: "application/json" } });
    assert.equal(res.status, 200, p);
    assert.match(res.headers.get("content-type"), /text\/html/, p);
    assert.match(await res.text(), /Your public IP address/, p);
  }
});

test("/docs and /llms.txt serve the same plain-text document", async () => {
  const docs = await get("/docs");
  assert.equal(docs.status, 200);
  assert.match(docs.headers.get("content-type"), /text\/plain/);
  const a = await docs.text();
  assert.match(a, /^# myip\.blue/);

  for (const p of ["/docs/", "/llms.txt"]) {
    const r = await get(p);
    assert.equal(r.status, 200, p);
    assert.equal(await r.text(), a, `${p} must match /docs byte-for-byte`);
  }
});

test("the docs describe the endpoints that actually exist", async () => {
  const docs = await (await get("/docs")).text();
  for (const ep of ["/ip", "/json", "/html", "/docs", "/llms.txt", "/static/"]) {
    assert.ok(docs.includes(ep), `docs should mention ${ep}`);
  }
  // The removed endpoint must not reappear in the docs.
  assert.ok(!docs.includes("/test/"), "docs must not advertise the removed SSRF endpoint");
});

test("/json reports the connection", async () => {
  const body = await (await get("/json")).json();
  assert.equal(body.clientIp, "127.0.0.1");
  assert.equal(body.connection.protocol, "http");
  assert.equal(body.connection.remoteFamily, "IPv4");
  assert.equal(typeof body.connection.remotePort, "number");
});

test("/json carries a live ISO timestamp, directly under clientIp", async () => {
  const before = Date.now();
  const res = await get("/json");
  const text = await res.text();
  const body = JSON.parse(text);

  assert.ok(body.timestamp, "timestamp must be present");
  const t = Date.parse(body.timestamp);
  assert.ok(!Number.isNaN(t), `timestamp must parse as a date: ${body.timestamp}`);
  // It is the point of the field that this is generated per request, not baked
  // into the image or cached upstream.
  assert.ok(t >= before - 5000 && t <= Date.now() + 5000, "timestamp must be current");

  // Key ORDER matters: timestamp directly below clientIp, docs last.
  assert.deepEqual(Object.keys(body), ["clientIp", "timestamp", "headers", "connection", "docs"]);
  assert.equal(body.docs, "https://myip.blue/docs");

  // Two calls must not return the same instant-for-free (i.e. not a constant).
  await new Promise((r) => setTimeout(r, 5));
  const second = await (await get("/json")).json();
  assert.notEqual(second.timestamp, body.timestamp, "timestamp must change between requests");
});

test("the HTML page does NOT carry the timestamp (json-only by design)", async () => {
  const res = await get("/", { headers: { "user-agent": "Mozilla/5.0 Chrome/120" } });
  assert.doesNotMatch(await res.text(), /timestamp/i);
});

test("usage links are real anchors and keep the code styling", async () => {
  const body = await (await get("/", { headers: { "user-agent": "Mozilla/5.0 Chrome/120" } })).text();
  for (const href of [
    "https://myip.blue/",
    "https://v4.myip.blue/",
    "https://v6.myip.blue/",
    "https://myip.blue/json",
    "https://myip.blue/ip",
    "https://cf.myip.blue/",
  ]) {
    assert.ok(body.includes(`href="${href}"`), `missing link: ${href}`);
  }
  // The anchors must sit INSIDE span.code, or they lose the monospace styling.
  assert.match(body, /<span class="code"><a href="https:\/\/myip\.blue\/">myip\.blue<\/a><\/span>/);
  assert.match(body, /\.code a \{[^}]*text-decoration: none/);
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

test("every response's Content-Type matches its body", async () => {
  const cases = [
    ["/", {}, /application\/json; charset=utf-8/],
    ["/", { accept: "text/plain" }, /text\/plain; charset=utf-8/],
    ["/", { accept: "text/html" }, /text\/html; charset=utf-8/],
    ["/ip", {}, /text\/plain; charset=utf-8/],
    ["/json", {}, /application\/json; charset=utf-8/],
    ["/html", {}, /text\/html; charset=utf-8/],
    ["/docs", {}, /text\/plain; charset=utf-8/],
    ["/llms.txt", {}, /text\/plain; charset=utf-8/],
    ["/static/blue.jpg", {}, /^image\/jpeg$/],
    ["/nope", {}, /text\/plain; charset=utf-8/],
  ];
  for (const [path, headers, want] of cases) {
    const res = await get(path, { headers });
    assert.match(res.headers.get("content-type"), want, `${path} ${JSON.stringify(headers)}`);
  }

  // Binary must NOT claim a charset.
  const jpg = await get("/static/blue.jpg");
  assert.ok(!/charset/i.test(jpg.headers.get("content-type")), "binary must not declare a charset");

  // And the bodies must actually BE what the header claims.
  JSON.parse(await (await get("/json")).text());
  assert.match(await (await get("/html")).text(), /^<!DOCTYPE html>/);
  assert.match((await (await get("/ip")).text()).trim(), /^[0-9a-f.:]+$/i);
});

test("405 also declares text/plain", async () => {
  const res = await get("/", { method: "POST" });
  assert.equal(res.status, 405);
  assert.match(res.headers.get("content-type"), /text\/plain; charset=utf-8/);
});

test("real browsers all get HTML — including IE8, whose Accept lacks text/html", async () => {
  const browsers = [
    ["Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"],
    ["Firefox", "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8"],
    ["Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
    ["Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "text/html,application/xhtml+xml,*/*;q=0.8"],
    ["IE11", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", "text/html, application/xhtml+xml, image/jxr, */*"],
    // IE8 sends NO text/html at all — only the Mozilla/ fallback saves it.
    ["IE8", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)", "image/gif, image/jpeg, image/pjpeg, */*"],
    ["MobileSafari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "text/html,application/xhtml+xml,*/*;q=0.8"],
  ];
  for (const [name, ua, accept] of browsers) {
    const res = await get("/", { headers: { "user-agent": ua, accept } });
    assert.match(res.headers.get("content-type"), /text\/html/, `${name} must get HTML`);
  }
});

test("scripting clients get JSON, including ones that impersonate Mozilla", async () => {
  const machines = [
    ["curl", "curl/8.7.1"],
    ["wget", "Wget/1.21.4"],
    ["python-requests", "python-requests/2.32.3"],
    ["Go", "Go-http-client/2.0"],
    ["undici", "undici"],
    // Invoke-WebRequest claims to be Mozilla; it still wants data.
    ["PowerShell", "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1"],
  ];
  for (const [name, ua] of machines) {
    const res = await get("/", { headers: { "user-agent": ua, accept: "*/*" } });
    assert.match(res.headers.get("content-type"), /application\/json/, `${name} must get JSON`);
  }
});

test("CORS is open on every response", async () => {
  for (const path of ["/", "/ip", "/json", "/html", "/docs", "/llms.txt", "/robots.txt", "/nope"]) {
    const res = await get(path);
    assert.equal(res.headers.get("access-control-allow-origin"), "*", path);
  }
});

test("OPTIONS preflight succeeds instead of 405", async () => {
  const res = await get("/", { method: "OPTIONS" });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
  assert.match(res.headers.get("access-control-allow-methods"), /GET/);
  assert.match(res.headers.get("allow"), /GET, HEAD, OPTIONS/);
});

test("/robots.txt is permissive and points at the machine-readable docs", async () => {
  const res = await get("/robots.txt");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /text\/plain/);
  const body = await res.text();
  assert.match(body, /User-agent: \*/);
  assert.match(body, /Allow: \//);
  assert.match(body, /llms\.txt/);
  assert.ok(!/Disallow: \/\s*$/m.test(body), "must not disallow everything");
});

test("paths are case-sensitive — no lenient aliases", async () => {
  // Deliberate (Drew, 2026-08-02): case-insensitive matching was implemented and
  // then reverted, because an undocumented leniency becomes a contract as soon
  // as something depends on it, and then it cannot be removed.
  for (const p of ["/JSON", "/Json", "/IP", "/Docs", "/LLMS.TXT", "/HTML", "/Robots.txt", "/STATIC/blue.jpg"]) {
    assert.equal((await get(p)).status, 404, `${p} must NOT resolve`);
  }
  // The correctly-cased forms still work.
  for (const p of ["/json", "/ip", "/docs", "/llms.txt", "/html", "/robots.txt", "/static/blue.jpg"]) {
    assert.equal((await get(p)).status, 200, p);
  }
});

test("slow/incomplete requests are cut off quickly (DoS timeouts)", async () => {
  // Open a socket, send a partial request line and then nothing. Node must give
  // up on headersTimeout (4s) rather than holding the socket for its 60s
  // default. Budget 8s so the test is not flaky on a loaded machine.
  const net = await import("node:net");
  const started = Date.now();
  const closed = await new Promise((resolve) => {
    const sock = net.connect(PORT, "127.0.0.1", () => sock.write("GET /ip HTTP/1.1\r\n"));
    sock.on("close", () => resolve(true));
    sock.on("error", () => resolve(true));
    setTimeout(() => { sock.destroy(); resolve(false); }, 8000);
  });
  const elapsed = Date.now() - started;
  assert.ok(closed, "server must close an incomplete request");
  // ~5s expected. Budget 8s so it is not flaky on a loaded machine, but this
  // WILL catch a regression to Node's 60s+ defaults.
  assert.ok(elapsed < 8000, `must close promptly (took ${elapsed}ms)`);
});

test("the container healthcheck script passes against a live server, fails without one", async () => {
  const { execFile } = await import("node:child_process");
  const run = (env) =>
    new Promise((resolve) => {
      execFile(process.execPath, ["lib/healthcheck.js"], { env: { ...process.env, ...env } }, (err) =>
        resolve(err ? err.code ?? 1 : 0),
      );
    });
  assert.equal(await run({ HTTP_PORT: String(PORT) }), 0, "must pass against the running server");
  // Nothing listening here -> must fail, or the healthcheck is decorative.
  assert.notEqual(await run({ HTTP_PORT: "1" }), 0, "must fail when nothing is listening");
});
