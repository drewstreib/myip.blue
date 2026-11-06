# myip.blue

Small Go service (stdlib + `golang.org/x/net/netutil`): tells you your public IP, plus the headers and TLS details of how you connected. Live at **myip.blue** (+ `v4.` / `v6.` / `cf.`), hosted by alt.org.

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

- ✅ **Pushing `main` publishes an image; it does NOT deploy.** CI builds and pushes to GHCR, but the origin only takes it on an explicit, reviewed rollout (control repo). Commit and push freely.
- 🛑 **Deploying is the separate, gated step** — Drew's go, procedure in the control repo.
- 🛑 **Rollback = the previous CI image digest** — the control repo's rollout script prints it on every deploy. The pre-2026-08-02 image survives on the origin as a tag *and* a tarball as a last resort (a plain `docker image prune -af` reaps unused tags). Details in the control repo.
- ⚠️ **There is NO source tree on the origin any more** (deleted 2026-08-02). It is a pull target. The old on-host checkout had drifted from git for years — building there is *how* it drifted. **This checkout is the working tree.**
- ⚠️ **Two front doors, one service.** `myip.blue` is served **direct from the origin** — that is deliberate and load-bearing, because reporting the client's *real* TLS cipher/protocol and source port only works on a direct connection. `cf.myip.blue` is the *through-Cloudflare* view on purpose. **Never put the apex behind a proxy** — it silently guts the app's whole point: every client would see Cloudflare's TLS and Cloudflare's address.

---

## What it does — the functional contract

**This is a DIAGNOSTIC tool** (Drew, 2026-08-02) — including for LLM agents, which is why the JSON matters as much as the page. The contract below is preserved from the original and must stay preserved.

| Route | Behaviour |
|---|---|
| `GET /` | **JSON by default.** HTML only if the client looks like a browser — see the negotiation rule below. |
| `GET /ip` | `text/plain`, bare client IP, nothing else. |
| `GET /json` | `application/json`: `{clientIp, timestamp, headers, connection, docs}`. |
| `GET /html` | The HTML page, forced, whatever the client asked for. |
| `GET /docs` , `/llms.txt` | The docs as markdown served `text/plain`. Byte-identical at both paths. |
| `GET /robots.txt` | Permissive (`Allow: /`), with a comment pointing crawlers at `/llms.txt`. |
| `GET /.well-known/security.txt` | RFC 9116, compiled in (`securityTxt`). ⚠️ **`Expires` is a live obligation** — a test fails the build once it passes, and the same date is published by 33 other zones out-of-band, so renew both together. |
| `GET /static/*` | Static files. Currently just `blue.jpg`, linked from the page footer. |
| anything else | `404` with the body `Sorry! Blue can't find that!` (non-GET/HEAD → `405`, same body) |

Trailing slashes resolve on `/ip`, `/json`, `/html`, `/docs`. **`OPTIONS` → `204`** with CORS preflight headers.

**CORS is open (`Access-Control-Allow-Origin: *`) on every response, including errors.** Safe here — every byte describes the caller and is already known to them, and no credentials are involved. Without it the same-origin policy blocks all browser-based callers, which was a whole class of user shut out.

**Paths are CASE-SENSITIVE and there are no lenient aliases.** Case-insensitive matching was built and then reverted the same day (Drew, 2026-08-02: *"i don't want /JSON. might make people rely on a wrong behavior… let's just make it work correctly"*). The reasoning generalises: **an undocumented leniency becomes a contract the moment something depends on it**, and then it cannot be removed. A test asserts `/JSON` and friends 404.

Static files are embedded, so their case-sensitivity no longer depends on the filesystem (under Node, macOS served `/static/BLUE.JPG`).

🛑 **`/` DEFAULTS TO JSON since 2026-08-02 — this deliberately broke `curl myip.blue` → bare IP** (Drew: *"i'm ok breaking the contract… i'd rather go the long term best way and break now than later"*). `/ip` is the stable plain-text endpoint. Order of the rule, in `preferredForm()`:

```
Accept: application/json  (without text/html)  -> JSON
Accept: text/plain        (without text/html)  -> bare IP
Accept contains text/html                      -> HTML
User-Agent starts with Mozilla/                -> HTML
otherwise                                      -> JSON
```

⚠️ **Verified against real browser headers (2026-08-02):** Chrome, Firefox, Safari, Edge, IE11, IE8, Mobile Safari and Lynx all get HTML; curl, wget, python-requests, Go, undici and **PowerShell** all get JSON. **IE8 is the reason the `Mozilla/` fallback exists** — its `Accept` contains no `text/html` at all. **PowerShell's `Invoke-WebRequest` is why that fallback is qualified** by `NOT_REALLY_A_BROWSER`: it impersonates Mozilla but wants data. Keep that deny-list SMALL; it patches a heuristic, it is not the mechanism.

⚠️ **The browser test is the ACCEPT HEADER, not the user-agent.** Every real browser sends `text/html`; curl, wget, python-requests, Go and undici send `*/*` or nothing. UA `Mozilla/` is a second opinion only — so there is **no list of client names to maintain**, which is the whole point. Don't "improve" this into UA sniffing.

**`timestamp`** (ISO 8601 UTC) is generated **per request** and sits **directly under `clientIp`**; **`docs`** is last. Both positions are asserted by tests. The timestamp exists so a caller — an LLM agent especially — can tell a live answer from a cached or pasted one; `docs` makes the response self-describing. ⚠️ **The HTML page carries neither**; a test asserts the timestamp does not appear there.

✅ **The two doc surfaces have DIFFERENT AUDIENCES and are allowed to read differently** (Drew, 2026-08-02: *"it is ok to me if /docs /llms.txt reads LLM friendly while HTML is designed for human audience… didn't mean to force those to match"*). The page says "gets **this HTML page**" because a human is looking at it; `/docs` says "gets **HTML**" because it is plain text being parsed. **Don't homogenise them.**

⚠️ **`docs.go` and the page's Usage list state the same CONTRACT twice — the routes and behaviour, not the wording.** Change a route and you change both. Do **not** sync the prose; that was tried and reverted the same day. Tests check the docs mention every live endpoint and never mention the removed `/test/`.

**The `connection` object is the differentiator, not incidental** — and it differs by front door:

- **Native** (`myip.blue`, `v4.`, `v6.` — direct, TLS terminated here): `protocol` · `remotePort` (client source port) · `remoteFamily` (`IPv4`/`IPv6`; a v4 client on the dual-stack listener arrives v4-mapped and prints as plain v4) · and on https, `tlsProtocol` / `cipherName` / `cipherStandardName` **read off the live connection**. `tlsProtocol` keeps the Node-era strings (`TLSv1` … `TLSv1.3`); `cipherName` is OpenSSL's name from the table in `tls.go` (Go knows only IANA names), `cipherStandardName` the IANA one.
- **Edge** (`cf.myip.blue` — arrives via the tunnel on loopback): `via: "cloudflare"` · `remoteFamily` · plus whatever Cloudflare supplies — `country`, `colo`, `ray`, `tlsVersion`, `tlsCipher`. Absent headers are **omitted rather than reported empty**, so what you see is what the edge actually sent.

**`headers` come out name-sorted, lowercased** — net/http keeps no wire order (Node echoed wire order; changed with the Go rewrite, 2026-11-06). Duplicate fields are joined `, `.

🛑 **TLS: AS LOW AS GO GOES, ON PURPOSE** (Drew, 2026-11-06: *"one of the points of myip.blue is to be able to show old clients what they're doing"*). `MinVersion` TLS 1.0 and every suite `tls.CipherSuites()` + `tls.InsecureCipherSuites()` returns — RC4 and 3DES included; a test negotiates each at each version. **Never "harden" this.** The floor is crypto/tls's: no SSLv3, DHE, export or NULL. RSA key exchange and ECDHE_RSA need the optional RSA pair (`TLS_RSA_CERT`/`TLS_RSA_KEY`); Go serves each client the first cert it supports, **and matches SNI first — an RSA cert lacking a name the ECDSA one has is never chosen for that name.** HTTP/2 is off (HTTP/1.1 only, as under Node); enabling it is its own change.

**Also contractual:** no-store cache headers on every response · one access-log line per request to stdout, `<ISO8601> - <ip> <proto> <host> <url> "<ua>" <status> <ms>` — **including `/static` hits**, so keep static going through the same handler · `v4.` resolves A only, `v6.` AAAA only, apex both.

---

## 🔴 Security — the invariants

Five things hold the line. Each has a test that **fails when only that protection is broken** (verified by breaking each one: Node 2026-08-02, Go 2026-11-06) — change any of them and believe `go test`.

1. **`html/template` in `page.go`.** Request headers are attacker-controlled and are echoed into the page; contextual escaping is the only thing between a header and stored XSS. Never pass it a `template.HTML` built from request data. The page's CSP (`pageCSP`) is a second line, never instead.
2. **`/static` can name only the embedded files** — `static/` is compiled in (`embed`), and the decoded path must pass `fs.ValidPath` (refuses `..`, `.`, empty elements). String-matching `..` is not equivalent; percent-encoding defeats it.
3. **CF-* headers are trusted ONLY from loopback.** That is what makes the edge view safe: a direct request forging `CF-Connecting-IP` arrives from a real remote address and is treated as native, so it cannot claim to be someone else. The value must also parse as an IP.
4. **`logField` in `handler.go`** — the User-Agent is caller-written and net/http passes spaces and `"` through; raw, a UA of `x" 200 1.0ms` forged a status field (2026-11-06). Escaped nginx-style; ordinary lines are byte-identical. (Host cannot carry those bytes: net/http 400s an invalid Host.)
5. **Dependencies: stdlib + `golang.org/x/net` only** (for `netutil.LimitListener`). The bar for anything more is very high. (The Node tree once listed **`fs`** and **`https`** as npm dependencies: real packages squatting core module names.)

✅ **`GET /test/:host` was REMOVED (Drew, 2026-08-02).** It was an unauthenticated server-side fetch — a textbook SSRF primitive reachable at internal addresses and cloud metadata endpoints — whose only mitigation was a *host-level* setting. **Do not reintroduce a fetch-on-behalf endpoint** without deny-listing private/link-local/metadata ranges **after DNS resolution**, restricting schemes, refusing redirects, and rate limiting.

---

## Layout

| Path | What it is |
|---|---|
| `main.go` | Config from env, the three listeners, timeouts, connection caps, signals, the `healthcheck` subcommand. |
| `handler.go` | Routing, connection description, responses, the access log. |
| `tls.go` | 🛑 The TLS range (see above), cert loading, the OpenSSL-name table. |
| `page.go` / `docs.go` | The HTML page (html/template); `/docs`, `robots.txt`, `security.txt` text. |
| `server_test.go` | Black-box tests over real sockets, ported from the Node suite. `go test ./...`. |
| `testdata/` | Throwaway self-signed localhost pairs (ECDSA + RSA), test-only. |
| `static/` | `blue.jpg`, embedded in the binary. |
| `Dockerfile` | `golang` build stage cross-compiling a static binary → **distroless/static**, ~16MB. |
| `.github/workflows/` | `go vet`, `go test -race`, govulncheck, then build + publish a multi-arch image to **GHCR** on push to `main` / `v*`. Token read-only by default; actions pinned to commit SHAs. |
| `.github/workflows/dependabot-auto-merge.yml` | Auto-merge on EVERY Dependabot PR, majors included — the required `test` + `build` checks are the gate, the manual rollout is the review (Drew, 2026-11-06). 🪤 A `GITHUB_TOKEN` merge starts no `push` run: the image workflow's Tuesday `schedule` (or `workflow_dispatch`) builds it. Direct pushes to `main` pass the checks ruleset by admin bypass. |
| `.github/dependabot.yml` | Weekly bumps of the action SHAs, both Dockerfile base digests (the `golang` one is how Go point releases arrive) and Go modules. |

**Tag `node-final`** = the last Node version (`758911e`); its CI image is the rollback past the rewrite.

Canonical doc files, when this repo needs them: **`TODO.md`** (active work, `## P1` / `## P2`, `- [ ] (due YYYY-MM-DD) desc — context`) · **`TODO-EVENTUALLY.md`** (someday) · **`done/YYYY-MM-DD-task.md`** (one file per finished item; a decision *not* to do something is also a `done/` entry) · **`logs/YYYY-MM-DD-slug.md`** (session journal, grep fodder). **None exist yet** — create on first need, and remember Rule Zero applies to all of them.

---

## Gotchas

- 🛑 **Timeouts — zero means NO LIMIT in net/http.** `ReadHeaderTimeout` and `ReadTimeout` each bound the request head (either alone passes the tests; neither, and a silent socket is held forever); the TLS handshake runs under the smallest of the three read/write timeouts; `IdleTimeout` bounds keep-alive. Deadlines are absolute, so a dripped header is cut too.
- 🛑 **`netutil.LimitListener` on every listener is the only bound on a connection FLOOD.** A full listener ACCEPTS NOTHING: the excess waits in the kernel backlog (Node refused it) — so the healthcheck fails while :80 is full. Measured 2026-11-06 in a 128MB test container, both caps full, keep-alive every 3s: **~77MB with `GOMEMLIMIT=64MiB`, 112–120MB without** — Go does not read the cgroup limit, so the deployment must set `GOMEMLIMIT` beside its memory limit. A per-source limit belongs in the host firewall (control repo).
- ⚠️ **`EDGE_PORT` = cloudflared's own listener, `127.0.0.1` only, own cap** — so a flood that fills the public :80's slots cannot take `cf.` down with it. Unset/0 = none (local dev). CF-* trust still rests on the loopback SOURCE, not on the listener.
- ⚠️ **net/http answers malformed requests itself — none reach the handler or the access log.** No Host on HTTP/1.1, two Hosts, an invalid Host, a bad header line → its own 400; oversized head → 431 (`MaxHeaderBytes` + 4KB slack); a timeout → close, no 408. The Node version logged these and sent the 408 — dropped with the rewrite (no hook exists). TLS handshake failures go to stderr (`http: TLS handshake error … client offered: [..]`) — the record of which old clients we could not serve.
- ⚠️ **Never put a `ServeMux` in front of `route()`.** It cleans paths and 301-redirects `//x`, `/a/../b`; routes match `r.URL.EscapedPath()` as sent, deliberately. `DisableGeneralOptionsHandler` sends `OPTIONS *` to `route()` too.
- 🛑 **Never `new URL(req.url, base)`-style resolution** — the Node bug: it read a leading `//` as a host and threw → 500 (a scanner's `//interactsh.com%2f..`, 2026-11). net/http's request-URI parse keeps `//x` a path; a test asserts the 404.
- ⚠️ **Routes must accept both `/ip` and `/ip/`.** Drop one and you silently break existing callers.
- ⚠️ **Static is served through the same handler as everything else, on purpose**, so static hits appear in the access log.
- ⚠️ **`HEALTHCHECK` is exec-form `["/myip", "healthcheck"]`** — distroless has no shell. It checks plain HTTP on loopback, deliberately not the cert.
- **Run it locally: `go run .` with `HTTP_PORT=8080 HTTPS_PORT=8443`**. TLS is optional — unreadable cert files → a warning and HTTP only. 🪤 **In the DrewHome checkout prefix `GOWORK=off`** (a parent `go.work` covers other modules and `go test` fails setup otherwise).
- ⚠️ **Certs are read once at startup**, so a renewal needs a restart — user-visible downtime with no proxy in front. Handled in the control repo.
- **Binding 80/443 as non-root needs `NET_BIND_SERVICE`** from the runtime, or ports above 1024. The image runs as non-root.
- **Distroless has no shell**, so `docker exec sh` fails by design.

---

## Deploy

**Direction agreed 2026-08-02 (Drew):** functional-equivalent rewrite on a current Node (then rewritten in Go, decided 2026-11-06) with the security cleaned up → publish a **public** image to **GHCR** → deploy to the origin → and serve the `cf.` variant from that same deployment over a **Cloudflare Tunnel**, retiring the separate edge reimplementation so there is one codebase instead of two.

Everything operational about that — origin details, compose, cert wiring, tunnel config, rollback, verification — lives in the **control repo** (`docs/myip.blue.md`), per Rule Zero. **This tree is just source.** Don't re-document ops here; a second copy in a public repo is both a leak and a drift.
