# myip.blue

Small zero-dependency Node service: tells you your public IP, plus the headers and TLS details of how you connected. Live at **myip.blue** (+ `v4.` / `v6.` / `cf.`), hosted by alt.org.

**This file is the signpost.** Loaded every session in this subtree. Keep it terse and current.

---

## 🛑 RULE ZERO — THIS REPO IS PUBLIC

`github.com/drewstreib/myip.blue` is a **public** repo. Everything here — this file included — is world-readable the moment it is pushed.

**Never write here:** hostnames or IPs of the origin fleet · SSH users, key paths, container/user IDs · registry or cloud credentials, even redacted · log destinations, monitoring endpoints, account numbers · anything about *other* alt.org services · vulnerability detail for an unfixed bug in this app.

**That material lives in `DrewHome/docs/myip.blue.md` (the single ops home) and `DrewHome/docs/hosts/myip.md`** — the private control repo. Write host/deploy/security-posture facts *there*, and reference them here only as "see the control repo", never by content.

⚠️ The rule is not "don't write secrets" — it is **don't write operational detail**. A hostname is not a secret and is still a gift to someone probing the box. When unsure which repo a fact belongs in: **it goes in the private one.**

---

## ✍️ By Claude, for Claude — and this repo is yours

**Every doc here is written by Claude, for a future Claude session.** Drew handed this repo over on **2026-08-02**: *"you can own that myip.blue repo and start its own CLAUDE.md, etc."* Same terms as DrewHome:

- **You don't need permission to fix your own repo.** Restructure, rename, correct, delete stale content — do it, commit, push.
- **Policy and direction are Drew's.** Ordinary work inside an agreed decision is yours. Changing what the service *does*, its public surface, or its deploy model is his call. **Recommend and wait.**
- **A stale or wrong doc is your bug.** Nobody else reviews these.

**How to write:** address future-you, not Drew — 1–2 lines per rule, no essays · assume full technical fluency · **record the mistakes and dead ends**, they're the highest-value content · prune aggressively, delete superseded lines rather than annotating them · absolute dates (`YYYY-MM-DD`), attribute standing instructions · optimise for `grep` and a cold reload.

Doc conventions in full → **`/d:docs`**, which also runs the end-of-session pass. Don't load it for routine edits — the working rules are here.

---

## 🚦 Guardrails

- ✅ **Pushing `main` is safe — it publishes an image, it does NOT deploy** (Drew, 2026-08-02: *"you own the tree… you're not affecting prod myip.blue by changing it now"*). The origin runs a **locally-built image it never pulls**, so nothing reaches production until someone deliberately changes that. Commit and push freely.
- 🛑 **Deploying IS the separate, gated step** — that's when the origin starts pulling this image. Drew's go, and the procedure is in the control repo.
- 🛑 **The running production service is the rollback.** It runs from that locally-built image, predating all of this. Do not delete, retag or prune it — until a new deploy is proven, it is the only way back.
- ⚠️ **Never edit the tree on the production host.** The host's copy had drifted from git for years (captured 2026-08-02, `163ed2f`). This checkout is the working tree; the host is a deploy target.
- ⚠️ **Two front doors, one service.** `myip.blue` is served **direct from the origin** — that is deliberate and load-bearing, because reporting the client's *real* TLS cipher/protocol and source port only works on a direct connection. `cf.myip.blue` is the *through-Cloudflare* view on purpose. **Never put the apex behind a proxy** — it silently guts the app's whole point: every client would see Cloudflare's TLS and Cloudflare's address.

---

## What it does — the functional contract

**This is a DIAGNOSTIC tool** (Drew, 2026-08-02) — including for LLM agents, which is why the JSON matters as much as the page. The contract below is preserved from the original and must stay preserved.

| Route | Behaviour |
|---|---|
| `GET /` , `/ip` , `/ip/` , `/json` , `/json/` | See below. Trailing-slash variants of `/ip` and `/json` both resolve. |
| `GET /` | HTML page: client IP, full request headers, connection details. **If `User-Agent` starts with `curl` or `wget` (first 4 chars, case-insensitive), returns `text/plain` with the bare IP instead.** |
| `GET /ip` | `text/plain`, bare client IP, nothing else. |
| `GET /json` | `application/json`: `{clientIp, headers, connection}`. |
| `GET /static/*` | Static files. Currently just `blue.jpg`, linked from the page footer. |
| anything else | `404` with the body `Sorry! Blue can't find that!` (non-GET/HEAD → `405`, same body) |

**The `connection` object is the differentiator, not incidental** — and it differs by front door:

- **Native** (`myip.blue`, `v4.`, `v6.` — direct, TLS terminated here): `protocol` · `remotePort` (client source port) · `remoteFamily` (`IPv4`/`IPv6`, from the `::ffff:` v4-mapped prefix, which is also stripped for display) · and on https, `tlsProtocol` / `cipherName` / `cipherStandardName` **read off the live socket**.
- **Edge** (`cf.myip.blue` — arrives via the tunnel on loopback): `via: "cloudflare"` · `remoteFamily` · plus whatever Cloudflare supplies — `country`, `colo`, `ray`, `tlsVersion`, `tlsCipher`. Absent headers are **omitted rather than reported empty**, so what you see is what the edge actually sent.

**Also contractual:** no-store cache headers on every response · one access-log line per request to stdout, `<ISO8601> - <ip> <proto> <host> <url> "<ua>" <status> <ms>` — **including `/static` hits**, so keep static going through the same handler · `v4.` resolves A only, `v6.` AAAA only, apex both.

---

## 🔴 Security — the invariants

Four things hold the line. Each has a test that **fails when only that protection is broken** (verified by deliberately breaking each one, 2026-08-02) — if you change any of them, run `npm test` and believe it.

1. **`escapeHtml` in `lib/page.js`.** Request headers are attacker-controlled and are echoed into the page. Dropping pug moved auto-escaping into our code; this is the only thing standing between a header and stored XSS.
2. **The `/static` traversal guard** — resolve the path, *then* require containment under `STATIC_DIR`. String-matching `..` is not equivalent; percent-encoding defeats it.
3. **CF-* headers are trusted ONLY from loopback.** That is what makes the edge view safe: a direct request forging `CF-Connecting-IP` arrives from a real remote address and is treated as native, so it cannot claim to be someone else.
4. **Zero dependencies.** No supply chain, nothing to audit. Keep it that way — the bar for adding a runtime dep is very high. (The old tree listed **`fs`** and **`https`** as npm dependencies: real packages squatting Node core module names, pulled in for imports that always resolved to core.)

✅ **`GET /test/:host` was REMOVED (Drew, 2026-08-02).** It was an unauthenticated server-side fetch — a textbook SSRF primitive reachable at internal addresses and cloud metadata endpoints — whose only mitigation was a *host-level* setting. **Do not reintroduce a fetch-on-behalf endpoint** without deny-listing private/link-local/metadata ranges **after DNS resolution**, restricting schemes, refusing redirects, and rate limiting.

---

## Layout

| Path | What it is |
|---|---|
| `index.js` | The whole service — routing, connection description, both listeners. |
| `lib/page.js` | The entire view layer — one template literal. 🛑 `escapeHtml` is load-bearing (see above). |
| `test/` | `node --test`, zero test deps. `npm test`. |
| `static/` | `blue.jpg`. |
| `Dockerfile` | Single stage on **distroless** (`nodejs22-debian12:nonroot`), 155MB. **Not alpine** — reasoning is in the file. |
| `.github/workflows/` | Test, then build + publish a multi-arch image to **GHCR** on push to `main` / `v*`. |

Canonical doc files, when this repo needs them: **`TODO.md`** (active work, `## P1` / `## P2`, `- [ ] (due YYYY-MM-DD) desc — context`) · **`TODO-EVENTUALLY.md`** (someday) · **`done/YYYY-MM-DD-task.md`** (one file per finished item; a decision *not* to do something is also a `done/` entry) · **`logs/YYYY-MM-DD-slug.md`** (session journal, grep fodder). **None exist yet** — create on first need, and remember Rule Zero applies to all of them.

---

## Gotchas

- 🛑 **The Mac's `node` is v20; this project targets 22. Verify on 22 before trusting a green run:** `docker run --rm -v "$PWD:/app" -w /app node:22-slim npm test`. **This already bit once** — `"test": "node --test test/"` passed on Node 20 and failed on 22, which resolves the directory as a *module path* (`Cannot find module …/test`). `node --test` with no argument auto-discovers and works on both.
- **Run it locally: `npm run dev`** (8080/8443) or `node index.js`. **TLS is optional** — if the cert files are unreadable it logs a warning and serves HTTP only. That is deliberate: the previous version read certs by absolute path at *module load* and died with `ENOENT` before the server existed, so it could never be run outside a container.
- ⚠️ **Certs are still read once at startup**, so a renewal needs a restart — and with no reverse proxy in front, that restart is user-visible downtime. Unavoidable in-process; it is a deploy-shape problem, handled in the control repo.
- ⚠️ **Routes must accept both `/ip` and `/ip/`.** Express matched both by default; this implementation matches them explicitly. Drop one and you silently break existing callers.
- ⚠️ **Static is served through the same handler as everything else, on purpose**, so static hits appear in the access log. The original achieved this by mounting `express.static` *after* the logger — same intent, don't "tidy" it away.
- **Binding 80/443 as non-root needs `NET_BIND_SERVICE`** from the runtime, or ports above 1024. The image no longer runs as root.
- **`package-lock.json` is gitignored** and there is nothing to lock — dependencies are empty. If a dep is ever added, revisit that ignore: the Dockerfile's `COPY package*.json` glob matches a lockfile.
- **Distroless has no shell**, so `docker exec sh` fails by design. To debug interactively, rebuild temporarily on `node:22-slim`.

---

## Deploy

**Direction agreed 2026-08-02 (Drew):** functional-equivalent rewrite on a current Node with the security cleaned up → publish a **public** image to **GHCR** → deploy to the origin → and serve the `cf.` variant from that same deployment over a **Cloudflare Tunnel**, retiring the separate edge reimplementation so there is one codebase instead of two.

Everything operational about that — origin details, compose, cert wiring, tunnel config, rollback, verification — lives in the **control repo** (`docs/myip.blue.md`), per Rule Zero. **This tree is just source.** Don't re-document ops here; a second copy in a public repo is both a leak and a drift.
