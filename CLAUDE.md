# myip.blue

Small Express service: tells you your public IP, plus the headers and TLS details of how you connected. Live at **myip.blue** (+ `v4.` / `v6.` / `cf.`), hosted by alt.org.

**This file is the signpost.** Loaded every session in this subtree. Keep it terse and current.

---

## 🛑 RULE ZERO — THIS REPO IS PUBLIC

`github.com/drewstreib/myip.blue` is a **public** repo. Everything here — this file included — is world-readable the moment it is pushed.

**Never write here:** hostnames or IPs of the origin fleet · SSH users, key paths, container/user IDs · registry or cloud credentials, even redacted · log destinations, monitoring endpoints, account numbers · anything about *other* alt.org services · vulnerability detail for an unfixed bug in this app.

**That material lives in `DrewHome/docs/myip-blue-app.md` and `DrewHome/docs/hosts/myip.md`** — the private control repo. Write host/deploy/security-posture facts *there*, and reference them here only as "see the control repo", never by content.

⚠️ The rule is not "don't write secrets" — it is **don't write operational detail**. A hostname is not a secret and is still a gift to someone probing the box. When unsure which repo a fact belongs in: **it goes in the private one.**

---

## ✍️ By Claude, for Claude — and this repo is yours

**Every doc here is written by Claude, for a future Claude session.** Drew handed this repo over on **2026-08-02**: *"you can own that myip.blue repo and start its own CLAUDE.md, etc."* Same terms as DrewHome:

- **You don't need permission to fix your own repo.** Restructure, rename, correct, delete stale content — do it, commit, push (but see the push guardrail below — pushing here is a *deploy*, not a save).
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

The revamp must preserve **all** of this. Verified by reading the source 2026-08-02.

| Route | Behaviour |
|---|---|
| `GET /` | HTML page (pug): client IP, full request headers, connection details. **If `User-Agent` starts with `curl` or `wget` (first 4 chars), returns `text/plain` with the bare IP instead.** |
| `GET /ip/` | `text/plain`, bare client IP, nothing else. |
| `GET /json/` | `application/json`: `{clientIp, headers, connection}`. |
| `GET /static/*` | Static files. Currently just `blue.jpg`, linked from the page footer. |
| `GET /test/:host` | ⚠️ Server-side fetch of an arbitrary URL — see the security section. |
| anything else | `404` with the body `Sorry! Blue can't find that!` |

**The `connection` object** — this is the differentiator, not incidental:
- `protocol` — `http` / `https`
- `remotePort` — client source port
- `remoteFamily` — `IPv4` / `IPv6`, derived by detecting the `::ffff:` v4-mapped prefix and stripping it (the IP is normalised the same way for display)
- **https only:** `tlsProtocol`, `cipherName`, `cipherStandardName` — read off the live socket

**Also contractual:** `nocache` headers on every response · one access-log line per request to stdout, `<ISO8601> - <ip> <proto> <host> <url> "<user-agent>"` (**including** `/static` hits — the static handler is mounted *after* the logger deliberately) · `v4.` resolves A only, `v6.` AAAA only, apex both.

---

## 🔴 Security — the known issue

**`GET /test/:host` takes a user-supplied URL and fetches it server-side, returning status, final URL, resolved IP and timing.** That is a textbook **SSRF** primitive: unauthenticated, public, and it will happily be pointed at internal addresses and cloud metadata endpoints. Its only real mitigation today is a host-level setting recorded in the control repo.

- **Do not quietly redesign or drop it — ask Drew what it is for first** (standing instruction). It looks like a deliberate connectivity-probe tool, not an accident.
- Whatever replaces it needs, at minimum: a deny-list for private/link-local/metadata ranges **enforced after DNS resolution** (pre-resolution checks are trivially bypassed by a hostname that resolves inward), scheme restricted to http/https, redirects not followed, and rate limiting.

---

## Layout

| Path | What it is |
|---|---|
| `index.js` | The whole service. |
| `views/index.pug` | The HTML page — inline `<style>`, no build step, no framework. |
| `static/` | `blue.jpg`. |
| `Dockerfile` | Two stages: deps in `node:16`, runtime `node:16-alpine`. |
| `.dockerignore` | Excludes `node_modules` — so a local install can't contaminate the image. |
| `.github/workflows/` | Build + publish on push to `main` / `v*` tags. |
| `*.sh` | `build.sh` (dev image), `prod-build.sh` (build + compose up), `run.sh` (local run, host cert paths), `prettier.sh`. All predate the revamp; expect them to be replaced. |

Canonical doc files, when this repo needs them: **`TODO.md`** (active work, `## P1` / `## P2`, `- [ ] (due YYYY-MM-DD) desc — context`) · **`TODO-EVENTUALLY.md`** (someday) · **`done/YYYY-MM-DD-task.md`** (one file per finished item; a decision *not* to do something is also a `done/` entry) · **`logs/YYYY-MM-DD-slug.md`** (session journal, grep fodder). **None exist yet** — create on first need, and remember Rule Zero applies to all of them.

---

## Gotchas

- 🛑 **`node index.js` does not run locally, and fails at *module load*.** `index.js` does `fs.readFileSync("/key.pem")` / `/chain.pem` at top level (absolute paths, filesystem root), so it throws `ENOENT` before Express is even constructed. **Verified 2026-08-02.** Ports are hardcoded `80`/`443` too, which need root on macOS — you never get that far. **Making the service locally runnable is a goal of the revamp**, not a nice-to-have: today there is no way to test a change short of building a container.
- ⚠️ **Certs are read once at startup**, so a renewal does not take effect until the process restarts — and there is no reverse proxy in front, so **a restart is full downtime for the apex**. Drives the deploy/renewal design; detail in the control repo.
- ⚠️ **Every dependency in `package.json` is pinned to `"*"`** and there is no committed lockfile — so two builds a minute apart can resolve differently. `.gitignore` explains why the lockfile isn't committed *yet*: `COPY package*.json ./` in the Dockerfile matches a lockfile, so adding one changes what the image resolves. Deliberate decision, not an oversight.
- ⚠️ **`node:16` has been EOL since 2023-09.** Both stages. Replacing it is a headline goal of the revamp.
- **`out` and `response` are assigned without `var`/`let`/`const`** in several handlers — implicit globals, shared across concurrent requests. Not currently exploitable because each is written before use in the same tick, but it is a real race waiting for an `await` in the wrong place. `/test/:host` already has the `await`.
- **`express.static` is mounted after the logging middleware on purpose.** Reordering it silently stops static hits being logged.
- **`/ip/` and `/json/` are written with trailing slashes.** Express default routing matches both with and without, so `/ip` works — don't "fix" the routes and assume nothing changed.

---

## Deploy

**Direction agreed 2026-08-02 (Drew):** functional-equivalent rewrite on a current Node with the security cleaned up → publish a **public** image to **GHCR** → deploy to the origin → and serve the `cf.` variant from that same deployment over a **Cloudflare Tunnel**, retiring the separate edge reimplementation so there is one codebase instead of two.

Everything operational about that — origin details, compose, cert wiring, tunnel config, rollback, verification — lives in the **control repo** (`docs/myip.blue.md`), per Rule Zero. **This tree is just source.** Don't re-document ops here; a second copy in a public repo is both a leak and a drift.
