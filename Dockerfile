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

# ⚠️ Runs as non-root. Binding 80/443 therefore needs NET_BIND_SERVICE granted
# by the runtime (compose: cap_add), or HTTP_PORT/HTTPS_PORT set above 1024.
# The old image ran as root purely to bind those ports.
EXPOSE 80 443

CMD ["index.js"]
