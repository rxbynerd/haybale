# Multi-stage build: a static Go binary compiled in a full Go toolchain
# image, copied into a distroless final stage with no shell, package
# manager, or other tooling an attacker could use if they ever got a
# foothold in the running container — haybale's own attack surface (a
# credential-handling network proxy) makes a minimal runtime image worth
# the extra build stage.
#
# The build stage always runs on the builder's native architecture and
# cross-compiles to TARGETOS/TARGETARCH, so multi-platform builds need no
# emulation. Both are unset for a plain `docker build`/`podman build`, in
# which case `go build` targets the builder's own platform.

FROM --platform=${BUILDPLATFORM:-} golang:1.26-alpine AS build

WORKDIR /src

# Dependencies are downloaded in their own layer, cached across builds
# that only change haybale's own source, not go.mod/go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# CGO_ENABLED=0 produces a fully static binary — required for the
# distroless "static" base image below, which has no libc at all.
# -trimpath removes local filesystem paths from the binary; -s -w strip
# the symbol table and DWARF debug info, shrinking the binary since
# nothing in the final image can attach a debugger anyway.
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/haybale ./cmd/haybale

# gcr.io/distroless/static-debian12 has no shell, no package manager, and
# no libc — just enough (a minimal /etc/passwd, ca-certificates, tzdata)
# to run a static Go binary. The :nonroot variant additionally runs as
# uid/gid 65532 ("nonroot") rather than root by default; USER below
# makes that explicit rather than relying solely on the base image's own
# default.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/haybale /usr/local/bin/haybale

# Matches internal/config's defaultListen (":8466") — purely
# documentation for whoever runs the image; the actual bind address is
# still controlled by the mounted config file's "listen" field (or
# --config pointing elsewhere).
EXPOSE 8466

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/haybale"]
CMD ["serve", "--config", "/etc/haybale/haybale.yaml"]
