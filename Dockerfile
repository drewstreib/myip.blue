# Two stages: build a static binary, ship it alone on distroless/static (no
# shell, no package manager, no libc — CGO is off, so none is needed).
#
# The build stage runs on the BUILD platform and cross-compiles for the target
# (Docker's documented multi-platform Go pattern), so the arm64 image needs no
# emulation. Both bases are pinned by digest; Dependabot
# (`.github/dependabot.yml`) bumps them, which is how Go point releases reach
# the image.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# Copy explicitly rather than `COPY . .` — nothing enters the binary that is not
# named here. static/ is compiled in (embed).
COPY *.go ./
COPY static ./static
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /myip .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /myip /myip

# The base image's USER is 65532 (nonroot). ⚠️ In production compose overrides
# this to uid 0 with `cap_drop: ALL` + `cap_add: NET_BIND_SERVICE`, because
# Docker grants no AMBIENT capabilities — a non-root process never gets the cap
# in its effective set and binding 80/443 fails EACCES. Running here as non-root
# is fine only on ports above 1024.
EXPOSE 80 443

# Exec form is required: distroless has no shell. The binary is its own check
# (plain HTTP on loopback — see healthcheck() in main.go).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/myip", "healthcheck"]

ENTRYPOINT ["/myip"]
