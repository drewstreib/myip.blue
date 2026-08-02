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

const HERE = path.dirname(fileURLToPath(import.meta.url));

const HTTP_PORT = Number(process.env.HTTP_PORT ?? 80);
const HTTPS_PORT = Number(process.env.HTTPS_PORT ?? 443);
const TLS_KEY = process.env.TLS_KEY ?? "/key.pem";
const TLS_CERT = process.env.TLS_CERT ?? "/chain.pem";
const STATIC_DIR = path.resolve(process.env.STATIC_DIR ?? path.join(HERE, "static"));

// Agents whose default at / is a bare IP rather than the HTML page. Matched on
// the first 4 characters, preserving the original behaviour exactly.
const PLAIN_AGENTS = ["curl", "wget"];

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
    ...extraHeaders,
  });
  res.end(body);
}

function wantsPlain(req) {
  const ua = req.headers["user-agent"];
  return typeof ua === "string" && PLAIN_AGENTS.includes(ua.slice(0, 4).toLowerCase());
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

  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "text/plain; charset=utf-8", "Sorry! Blue can't find that!", {
      Allow: "GET, HEAD",
    });
    return { status: 405, clientIp, connection };
  }

  let status;
  if (urlPath === "/" || urlPath === "") {
    if (wantsPlain(req)) {
      send(res, 200, "text/plain; charset=utf-8", clientIp + "\n");
    } else {
      send(res, 200, "text/html; charset=utf-8", renderPage(payload));
    }
    status = 200;
  } else if (urlPath === "/ip" || urlPath === "/ip/") {
    send(res, 200, "text/plain; charset=utf-8", clientIp + "\n");
    status = 200;
  } else if (urlPath === "/json" || urlPath === "/json/") {
    // `timestamp` is generated per-request and sits directly under clientIp so a
    // caller — an LLM agent especially — can tell a live answer from a cached or
    // pasted one at a glance. Deliberately JSON-only: the HTML page does not
    // carry it.
    const json = {
      clientIp,
      timestamp: new Date().toISOString(),
      headers: req.headers,
      connection,
    };
    send(res, 200, "application/json; charset=utf-8", JSON.stringify(json, null, 2) + "\n");
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

const servers = [];

const httpServer = http.createServer(handler(false));
httpServer.listen(HTTP_PORT, () =>
  console.log(`${new Date().toISOString()} - http listening on ${HTTP_PORT}`),
);
servers.push(httpServer);

const tls = loadTls();
if (tls) {
  // Certs are read once here. A renewal needs a restart — there is no reverse
  // proxy in front, so that restart is user-visible downtime.
  const httpsServer = https.createServer(tls, handler(true));
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
