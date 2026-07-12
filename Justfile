# container is the CLI used by the image-build recipe below — configurable
# so both docker and podman work, defaulting to podman: set
# HAYBALE_CONTAINER_RUNTIME=docker to use `docker build ...` instead.
container := env_var_or_default("HAYBALE_CONTAINER_RUNTIME", "podman")

# image is the tag image-build applies; override with HAYBALE_IMAGE if a
# registry-qualified tag is needed for a push.
image := env_var_or_default("HAYBALE_IMAGE", "haybale:dev")

default: build test

build:
    go build -o haybale ./cmd/haybale

# Builds the distroless haybale image described in Dockerfile. Uses
# {{container}} (docker or podman) rather than hardcoding one, since a
# Justfile recipe should work the same way regardless of which the
# operator has installed.
image-build:
    {{container}} build -t {{image}} .

test:
    go test ./...

# Race-detector pass over the full module. haybale is small enough
# (single module, no goroutine-heavy subsystems yet beyond the proxy and
# e2e harness) that sweeping ./... under -race is cheap — unlike
# Stirrup's targeted package list, there's no need to scope this down.
test-race:
    go test -race ./...

lint:
    golangci-lint run ./...

# e2e-github runs the M6 acceptance: a credential-less container clones
# and pushes a real private GitHub repo through a locally-running
# haybale, using a real GitHub App — see
# docs/runbook-github-acceptance.md and scripts/e2e-github.sh for the
# full detail. Requires HAYBALE_APP_KEY_PATH (path to the GitHub App's
# PEM private key) in the environment. Uses {{container}} (docker or
# podman) exactly like image-build above. Not part of `just test`/CI:
# it needs a real GitHub App private key, a real private repo, and a
# container runtime that can reach back out to the host.
e2e-github: build
    HAYBALE_CONTAINER_RUNTIME={{container}} ./scripts/e2e-github.sh

clean:
    rm -f haybale
