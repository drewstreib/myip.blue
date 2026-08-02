# Zero runtime dependencies, so there is no install stage and no node_modules.
#
# ⚠️ NOT alpine. Node classifies linux-musl as support tier "Experimental" —
# "may not compile or test suite may not pass", and the core team does not
# create releases for it (nodejs/node BUILDING.md). nodejs/docker-node
# recommends the Debian variants for production.
#
# Distroless over node:22-slim, measured 2026-08-02: 155MB vs 247MB, both
# glibc/Debian 12, and this one ships no shell and no package manager.
# ⚠️ The trade: you cannot `docker exec sh` into it. Acceptable here — one
# process, no deps, logs go off-box. To debug interactively, rebuild
# temporarily on node:22-slim rather than adding a shell to this image.
#
# The base image's ENTRYPOINT is already `node`, so CMD is just the script.
FROM gcr.io/distroless/nodejs22-debian12:nonroot

WORKDIR /app

# Copy explicitly rather than `COPY . .` — nothing enters the image that is not
# named here, so a stray file in the working tree cannot be shipped by accident.
COPY package.json ./
COPY index.js ./
COPY lib ./lib
COPY static ./static

# The base image's USER is 65532 (nonroot). ⚠️ In production compose overrides
# this to uid 0 with `cap_drop: ALL` + `cap_add: NET_BIND_SERVICE`, because
# Docker grants no AMBIENT capabilities — a non-root process never gets the cap
# in its effective set and binding 80/443 fails EACCES. Running here as non-root
# is fine only on ports above 1024.
EXPOSE 80 443

# Exec form is required: distroless has no shell, so the usual
# `HEALTHCHECK CMD curl ...` is impossible. HEALTHCHECK does not inherit
# ENTRYPOINT, hence the absolute path to node.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "/app/lib/healthcheck.js"]

CMD ["index.js"]
