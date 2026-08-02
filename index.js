// myip.blue — a connection diagnostic service.
//
// Zero runtime dependencies: Node stdlib only. See CLAUDE.md for the
// functional contract this must preserve.
//
// TWO VIEWS OF THE SAME SERVICE, and the difference is the whole point:
//   · NATIVE  — myip.blue / v4. / v6. terminate TLS here, so the real client
//               socket is visible: source port, negotiated cipher, TLS version.
//               🛑 This path is the CONTROL: keep it the cleanest possible
//               network route, no proxy and no CDN, or it stops being a
//               reference measurement.
//   · EDGE    — cf.myip.blue arrives via a cloudflared tunnel on loopback. The
//               socket is then cloudflared's, not the client's, so client facts
//               come from CF-* headers and the edge's own view is reported.
// Comparing the two is the diagnostic.

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderPage } from "./lib/page.js";
import { DOCS, DOCS_URL, ROBOTS } from "./lib/docs.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const HTTP_PORT = Number(process.env.HTTP_PORT ?? 80);
const HTTPS_PORT = Number(process.env.HTTPS_PORT ?? 443);
const TLS_KEY = process.env.TLS_KEY ?? "/key.pem";
const TLS_CERT = process.env.TLS_CERT ?? "/chain.pem";
const STATIC_DIR = path.resolve(process.env.STATIC_DIR ?? path.join(HERE, "static"));

// Clients that claim to be Mozilla but are scripting tools. See preferredForm().
const NOT_REALLY_A_BROWSER =
  /PowerShell|curl|wget|python|java|okhttp|Go-http|libwww|httpie|postman|insomnia|axios|node-fetch/i;

const CONTENT_TYPES = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

// ── client identity ──────────────────────────────────────────────────────────

// IPv4 arrives as ::ffff:a.b.c.d on a dual-stack listener. Normalise, and use
// the mapping itself to report the family the client actually used.
function normaliseIp(raw) {
  if (typeof raw !== "string") return { ip: "unknown", family: "unknown" };
  if (raw.startsWith("::ffff:")) return { ip: raw.slice(7), family: "IPv4" };
  return { ip: raw, family: raw.includes(":") ? "IPv6" : "IPv4" };
}

function isLoopback(addr) {
  if (!addr) return false;
  const { ip } = normaliseIp(addr);
  return ip === "::1" || ip.startsWith("127.");
}

// 🛑 CF-* headers are only trusted from loopback — i.e. from cloudflared running
// beside us. A direct request carrying a forged CF-Connecting-IP arrives from a
// real remote address and is treated as native, so it cannot spoof its own IP.
function isEdgeRequest(req) {
  return isLoopback(req.socket.remoteAddress) && Boolean(req.headers["cf-connecting-ip"]);
}

function describe(req, isTls) {
  if (isEdgeRequest(req)) {
    const { ip, family } = normaliseIp(req.headers["cf-connecting-ip"]);
    const ray = req.headers["cf-ray"] ?? "";
    const connection = {
      via: "cloudflare",
      protocol: (req.headers["x-forwarded-proto"] ?? "https").toLowerCase(),
      remoteFamily: family,
    };
    // Populated by Cloudflare managed transforms; omitted rather than shown
    // empty when a given header is not configured.
    const edge = {
      country: req.headers["cf-ipcountry"],
      colo: ray.includes("-") ? ray.split("-").pop() : undefined,
      ray: ray || undefined,
      tlsVersion: req.headers["cf-tls-version"],
      tlsCipher: req.headers["cf-tls-cipher"],
    };
    for (const [k, v] of Object.entries(edge)) if (v !== undefined) connection[k] = v;
    return { clientIp: ip, connection };
  }

  const { ip, family } = normaliseIp(req.socket.remoteAddress);
  const connection = {
    protocol: isTls ? "https" : "http",
    remotePort: req.socket.remotePort,
  };
  if (isTls) {
    const cipher = req.socket.getCipher?.() ?? {};
    connection.tlsProtocol = req.socket.getProtocol?.() ?? null;
    connection.cipherName = cipher.name ?? null;
    connection.cipherStandardName = cipher.standardName ?? null;
  }
  connection.remoteFamily = family;
  return { clientIp: ip, connection };
}

// ── responses ────────────────────────────────────────────────────────────────

function send(res, status, type, body, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": type,
    // Every response is a point-in-time measurement; caching one is always wrong.
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    Pragma: "no-cache",
    Expires: "0",
    "Surrogate-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    // Everything here describes the caller and is already known to them, and no
    // credentials or cookies are involved — so "*" gives up nothing and lets
    // browser-based tooling actually read the response. Without it the
    // same-origin policy blocks every in-page caller.
    "Access-Control-Allow-Origin": "*",
    ...extraHeaders,
  });
  res.end(body);
}

// What form should `/` take for this client?
//
// 🛑 THE DEFAULT IS JSON (changed 2026-08-02, deliberately breaking the old
// `curl myip.blue` -> bare IP behaviour). This is a diagnostic tool: machines
// are the common caller, so they get structured data unless something asks for
// a page. `/ip` is still the bare-string endpoint.
//
// The browser test is the ACCEPT HEADER, not the user-agent. Every real browser
// sends `text/html`; curl, wget, python-requests, Go and undici send `*/*` or
// nothing. UA `Mozilla/` is a cheap second opinion, not the primary signal —
// which is why there is no list of client names to maintain here.
function preferredForm(req) {
  const accept = req.headers.accept ?? "";
  const ua = req.headers["user-agent"] ?? "";
  const asksHtml = /text\/html/i.test(accept);

  // An explicit machine ask wins outright.
  if (!asksHtml && /application\/json/i.test(accept)) return "json";
  if (!asksHtml && /text\/plain/i.test(accept)) return "text";

  if (asksHtml) return "html";

  // UA fallback, needed for exactly one real case: older IE sends an Accept
  // header with NO text/html in it (IE8: "image/gif, image/jpeg, ..., */*").
  // ⚠️ But some scripting clients deliberately impersonate a browser — notably
  // PowerShell's Invoke-WebRequest, whose UA is
  // "Mozilla/5.0 (Windows NT; ...) WindowsPowerShell/5.1". Those want data, not
  // a page, so the Mozilla/ check is qualified by a short deny list. Keep this
  // list SMALL: it is a patch on a heuristic, not the mechanism. Accept is.
  if (/^Mozilla\//i.test(ua) && !NOT_REALLY_A_BROWSER.test(ua)) return "html";

  return "json";
}

async function serveStatic(req, res, urlPath) {
  let rel;
  try {
    rel = decodeURIComponent(urlPath.slice("/static/".length));
  } catch {
    return notFound(res); // malformed percent-encoding
  }
  const target = path.resolve(STATIC_DIR, rel);

  // Path traversal guard: resolve first, then require containment. Checking the
  // raw string for ".." is not equivalent — encoding defeats it.
  if (target !== STATIC_DIR && !target.startsWith(STATIC_DIR + path.sep)) {
    return notFound(res);
  }

  try {
    const stat = await fsp.stat(target);
    if (!stat.isFile()) return notFound(res);
    const type = CONTENT_TYPES[path.extname(target).toLowerCase()] ?? "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": stat.size,
      "X-Content-Type-Options": "nosniff",
    });
    fs.createReadStream(target).pipe(res);
    return 200;
  } catch {
    return notFound(res);
  }
}

function notFound(res) {
  send(res, 404, "text/plain; charset=utf-8", "Sorry! Blue can't find that!");
  return 404;
}

// ── routing ──────────────────────────────────────────────────────────────────

async function route(req, res, isTls) {
  const { clientIp, connection } = describe(req, isTls);
  const urlPath = new URL(req.url, "http://placeholder").pathname;
  const payload = { clientIp, headers: req.headers, connection };

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      Allow: "GET, HEAD, OPTIONS",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
      "Access-Control-Allow-Headers": "Accept, Content-Type",
      "Access-Control-Max-Age": "86400",
    });
    res.end();
    return { status: 204, clientIp, connection };
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "text/plain; charset=utf-8", "Sorry! Blue can't find that!", {
      Allow: "GET, HEAD",
    });
    return { status: 405, clientIp, connection };
  }

  // One JSON body, used by both `/` and `/json`. `timestamp` sits directly under
  // clientIp so a caller — an LLM agent especially — can tell a live answer from
  // a cached or pasted one; `docs` makes the response self-describing.
  const jsonBody = () =>
    JSON.stringify(
      {
        clientIp,
        timestamp: new Date().toISOString(),
        headers: req.headers,
        connection,
        docs: DOCS_URL,
      },
      null,
      2,
    ) + "\n";

  let status;
  if (urlPath === "/" || urlPath === "") {
    const form = preferredForm(req);
    if (form === "html") {
      send(res, 200, "text/html; charset=utf-8", renderPage(payload));
    } else if (form === "text") {
      send(res, 200, "text/plain; charset=utf-8", clientIp + "\n");
    } else {
      send(res, 200, "application/json; charset=utf-8", jsonBody());
    }
    status = 200;
  } else if (urlPath === "/ip" || urlPath === "/ip/") {
    send(res, 200, "text/plain; charset=utf-8", clientIp + "\n");
    status = 200;
  } else if (urlPath === "/json" || urlPath === "/json/") {
    send(res, 200, "application/json; charset=utf-8", jsonBody());
    status = 200;
  } else if (urlPath === "/html" || urlPath === "/html/") {
    // Forces the page regardless of what the client asked for. Completes the
    // set: /ip, /json and /html each pin one form, and `/` negotiates.
    send(res, 200, "text/html; charset=utf-8", renderPage(payload));
    status = 200;
  } else if (urlPath === "/docs" || urlPath === "/docs/" || urlPath === "/llms.txt") {
    // Markdown served as text/plain on purpose: it renders readably raw, and a
    // machine gets the whole contract in one cheap request with no HTML to strip.
    send(res, 200, "text/plain; charset=utf-8", DOCS);
    status = 200;
  } else if (urlPath === "/robots.txt") {
    send(res, 200, "text/plain; charset=utf-8", ROBOTS);
    status = 200;
  } else if (urlPath.startsWith("/static/")) {
    status = await serveStatic(req, res, urlPath);
  } else {
    status = notFound(res);
  }

  return { status, clientIp, connection };
}

// Static is served through the same handler as everything else so that static
// hits are logged — the original mounted it after the logger deliberately.
function handler(isTls) {
  return async (req, res) => {
    const started = process.hrtime.bigint();
    let status = 500;
    let clientIp = "-";
    let connection = {};
    try {
      ({ status, clientIp, connection } = await route(req, res, isTls));
    } catch (err) {
      if (!res.headersSent) send(res, 500, "text/plain; charset=utf-8", "Blue broke!");
      console.error(`${new Date().toISOString()} - error ${req.method} ${req.url}:`, err);
    } finally {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      const proto = connection.protocol ?? (isTls ? "https" : "http");
      console.log(
        `${new Date().toISOString()} - ${clientIp} ${proto} ${req.headers.host ?? "-"} ${req.url} ` +
          `"${req.headers["user-agent"] ?? "-"}" ${status} ${ms.toFixed(1)}ms`,
      );
    }
  };
}

// ── startup ──────────────────────────────────────────────────────────────────

// TLS is optional so the service runs locally. The original read the cert at
// module load from an absolute path and died with ENOENT before Express was
// even constructed, which is why it could never be tested outside a container.
function loadTls() {
  try {
    return { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) };
  } catch (err) {
    console.warn(
      `${new Date().toISOString()} - TLS disabled: cannot read ${TLS_KEY} / ${TLS_CERT} (${err.code}). ` +
        `HTTP only on :${HTTP_PORT}.`,
    );
    return null;
  }
}

// 🛑 Aggressive on purpose. This service answers in well under a millisecond, so
// 5s is already catastrophic-failure territory, not a slow client. Node's
// defaults (headersTimeout 60s, requestTimeout 5min, keepAliveTimeout 65s) are
// sized for a server behind a reverse proxy — there is none here, node faces the
// internet directly on a 405MB box, and Node's own docs say both timeouts must
// be non-zero in exactly that situation.
function tune(server) {
  // 🛑 server.timeout IS THE ONE THAT ACTUALLY WORKS. Measured on the production
  // host with the production node (v22.22.0, 2026-08-02): a socket that opens
  // and sends only "GET /ip HTTP/1.1\r\n" is held **indefinitely** with
  // requestTimeout and headersTimeout set and server.timeout unset — still open
  // at 15s. With server.timeout it closes on the dot. Same result in a Linux
  // container on macOS, so it is not a Docker-networking artifact.
  // Setting only the two documented "DoS" timeouts would be decorative.
  server.timeout = 5000; // socket inactivity — the effective protection
  server.requestTimeout = 5000; // defence in depth: whole request must complete
  server.headersTimeout = 4000; // defence in depth; MUST be < requestTimeout
  server.keepAliveTimeout = 5000; // idle between keep-alive requests (default 65s)
  return server;
}

const servers = [];

const httpServer = tune(http.createServer(handler(false)));
httpServer.listen(HTTP_PORT, () =>
  console.log(`${new Date().toISOString()} - http listening on ${HTTP_PORT}`),
);
servers.push(httpServer);

const tls = loadTls();
if (tls) {
  // Certs are read once here. A renewal needs a restart — there is no reverse
  // proxy in front, so that restart is user-visible downtime.
  const httpsServer = tune(https.createServer(tls, handler(true)));
  httpsServer.listen(HTTPS_PORT, () =>
    console.log(`${new Date().toISOString()} - https listening on ${HTTPS_PORT}`),
  );
  servers.push(httpsServer);
}

// Exit cleanly on signals. The old image ran `npm run start` as PID 1, which
// swallowed signals: stops took ~2.1s and exited 1, so a normal stop was
// indistinguishable from a crash.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    console.log(`${new Date().toISOString()} - ${signal} received, shutting down`);
    let pending = servers.length;
    const done = () => --pending === 0 && process.exit(0);
    for (const s of servers) s.close(done);
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
