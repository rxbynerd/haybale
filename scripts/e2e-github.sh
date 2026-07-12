#!/usr/bin/env bash
# e2e-github.sh — M6 acceptance: a credential-less container clones and
# pushes a real private GitHub repo through a locally-running haybale,
# using a real GitHub App. See docs/runbook-github-acceptance.md for the
# full runbook this recipe is evidence for, including how to create the
# GitHub App it depends on.
#
# Invoked via `just e2e-github`; deliberately not wired into CI (it needs
# a real GitHub App private key, a real private repo, and a container
# runtime that can reach back out to the host — none of which CI has).
#
# What it does:
#   1. Mints a run-scoped haybale identity token and writes scratch
#      identities.yaml/policy.yaml/haybale.yaml granting that identity
#      read+write on exactly HAYBALE_E2E_REPO — nothing else.
#   2. Starts `haybale serve` on the host, waits for /healthz.
#   3. Runs a container with ONLY HAYBALE_URL/HAYBALE_TOKEN as env vars.
#      Entirely from inside that container: configures git via
#      GIT_CONFIG_COUNT/KEY/VALUE env vars (no file ever written to
#      disk — see docs/stirrup-integration.md's "Sandbox wiring"), then
#      clones, commits, and pushes HAYBALE_E2E_REPO — all rewritten
#      through haybale — before checking its own filesystem and
#      environment for git-host credential material.
#   4. Confirms the pushed commit landed on the real repo via `gh api`,
#      a channel entirely independent of haybale.
#   5. Tears down haybale and the scratch config either way.
#
# Required env:
#   HAYBALE_APP_KEY_PATH   path to the GitHub App's PEM private key.
#
# Optional env:
#   HAYBALE_CONTAINER_RUNTIME   docker or podman (default: podman).
#   HAYBALE_APP_ID              GitHub App ID (default: 4278664, "haybale dev").
#   HAYBALE_E2E_REPO            owner/repo on github.com to round-trip
#                               against (default: rxbynerd/haybale-e2e —
#                               see docs/runbook-github-acceptance.md for
#                               how that repo was created).
#   HAYBALE_BIN                 path to the haybale binary (default: ./haybale).
#   HAYBALE_E2E_PORT            port haybale listens on for this run
#                               (default: 8466).
#
# Run from the repo root after `just build`:
#   HAYBALE_APP_KEY_PATH=/path/to/key.pem just e2e-github

set -euo pipefail

# ---- configuration ---------------------------------------------------

HAYBALE_BIN="${HAYBALE_BIN:-./haybale}"
CONTAINER_RUNTIME="${HAYBALE_CONTAINER_RUNTIME:-podman}"
APP_ID="${HAYBALE_APP_ID:-4278664}"
E2E_REPO="${HAYBALE_E2E_REPO:-rxbynerd/haybale-e2e}"
E2E_PORT="${HAYBALE_E2E_PORT:-8466}"
SCRATCH_DIR="${HAYBALE_E2E_SCRATCH:-.e2e-github}"
CONTAINER_IMAGE="docker.io/alpine/git"

if [[ -z "${HAYBALE_APP_KEY_PATH:-}" ]]; then
  echo "e2e-github: HAYBALE_APP_KEY_PATH must be set (path to the GitHub App's PEM private key)" >&2
  exit 1
fi
if [[ ! -f "$HAYBALE_APP_KEY_PATH" ]]; then
  echo "e2e-github: HAYBALE_APP_KEY_PATH=$HAYBALE_APP_KEY_PATH does not exist" >&2
  exit 1
fi
# Resolve to an absolute path: haybale.yaml below is written once and
# read by a haybale process that (like every other command here) runs
# with the repo root as its working directory, so a relative
# HAYBALE_APP_KEY_PATH would otherwise resolve against the wrong
# directory the moment either assumption changes.
HAYBALE_APP_KEY_PATH="$(cd "$(dirname "$HAYBALE_APP_KEY_PATH")" && pwd)/$(basename "$HAYBALE_APP_KEY_PATH")"

if [[ ! -x "$HAYBALE_BIN" ]]; then
  echo "e2e-github: $HAYBALE_BIN not found or not executable; run 'just build' first" >&2
  exit 1
fi

# Resolve the container runtime binary: honour an already-on-PATH
# docker/podman, falling back to podman's known install location on this
# dev machine (podman ships as a standalone binary under /opt/podman/bin,
# which isn't always exported to a login shell's PATH).
runtime_bin=""
if command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1; then
  runtime_bin="$CONTAINER_RUNTIME"
elif [[ "$CONTAINER_RUNTIME" == "podman" && -x /opt/podman/bin/podman ]]; then
  runtime_bin=/opt/podman/bin/podman
else
  echo "e2e-github: container runtime '$CONTAINER_RUNTIME' not found on PATH (set HAYBALE_CONTAINER_RUNTIME)" >&2
  exit 1
fi
echo "e2e-github: using container runtime: $runtime_bin"

repo_owner="${E2E_REPO%%/*}"
repo_name="${E2E_REPO##*/}"
if [[ -z "$repo_owner" || -z "$repo_name" || "$repo_owner" == "$E2E_REPO" ]]; then
  echo "e2e-github: HAYBALE_E2E_REPO=$E2E_REPO must be \"owner/repo\"" >&2
  exit 1
fi

# ---- scratch dir + cleanup ---------------------------------------------
#
# Everything this script generates — the minted raw token, both YAML
# configs, and haybale's own log for this run — lives under SCRATCH_DIR,
# which is .gitignore'd (see .gitignore) and removed on every exit path
# (success, failure, or interrupt) so nothing it contains ever has a
# chance to end up committed.

rm -rf "$SCRATCH_DIR"
mkdir -p "$SCRATCH_DIR"
SCRATCH_ABS="$(cd "$SCRATCH_DIR" && pwd)"

HAYBALE_PID=""
cleanup() {
  local status=$?
  if [[ -n "$HAYBALE_PID" ]] && kill -0 "$HAYBALE_PID" 2>/dev/null; then
    kill "$HAYBALE_PID" 2>/dev/null || true
    wait "$HAYBALE_PID" 2>/dev/null || true
  fi
  rm -rf "$SCRATCH_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

# ---- 1. mint identity + write scratch config ---------------------------

run_id="run-e2e-$(date +%s)-$$"
echo "e2e-github: minting identity token for $run_id"
mint_output="$("$HAYBALE_BIN" token new --id "$run_id")"

raw_token="$(printf '%s\n' "$mint_output" | awk '/^token \(save this now/{getline; print; exit}')"
token_digest="$(printf '%s\n' "$mint_output" | awk -F'tokenDigest: ' '/tokenDigest:/{print $2; exit}')"
if [[ -z "$raw_token" || -z "$token_digest" ]]; then
  echo "e2e-github: failed to parse 'haybale token new' output" >&2
  exit 1
fi

cat > "$SCRATCH_ABS/identities.yaml" <<EOF
identities:
  - id: $run_id
    tokenDigest: $token_digest
EOF

cat > "$SCRATCH_ABS/policy.yaml" <<EOF
rules:
  - identities: ["$run_id"]
    repos: ["github.com/$repo_owner/$repo_name"]
    permissions: [read, write]
EOF

cat > "$SCRATCH_ABS/haybale.yaml" <<EOF
listen: ":$E2E_PORT"
logLevel: info
identity: { type: static-token-file, path: $SCRATCH_ABS/identities.yaml }
policy: { path: $SCRATCH_ABS/policy.yaml }
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential:
      type: github-app
      appID: $APP_ID
      privateKeyPath: $HAYBALE_APP_KEY_PATH
      apiBaseURL: https://api.github.com
EOF

# ---- 2. start haybale, wait for /healthz -------------------------------

echo "e2e-github: starting haybale serve on :$E2E_PORT"
"$HAYBALE_BIN" serve --config "$SCRATCH_ABS/haybale.yaml" > "$SCRATCH_ABS/haybale.log" 2>&1 &
HAYBALE_PID=$!

healthy=""
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$E2E_PORT/healthz" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  if ! kill -0 "$HAYBALE_PID" 2>/dev/null; then
    echo "e2e-github: haybale exited before becoming healthy; log follows:" >&2
    cat "$SCRATCH_ABS/haybale.log" >&2
    exit 1
  fi
  sleep 0.2
done
if [[ -z "$healthy" ]]; then
  echo "e2e-github: haybale never became healthy on :$E2E_PORT" >&2
  cat "$SCRATCH_ABS/haybale.log" >&2
  exit 1
fi
echo "e2e-github: haybale is healthy (pid $HAYBALE_PID)"

# ---- 3. credential-less container: clone, commit, push, self-check ----
#
# host.containers.internal is podman's host-gateway alias (rootless
# podman machine on macOS runs the container inside a VM, so
# 127.0.0.1/localhost from inside the container means the container
# itself, not the host); docker for Mac/Linux resolves the same name via
# its own host-gateway support (--add-host=host.containers.internal:host-gateway
# on older Docker versions that don't wire it up by default — Docker
# Desktop ships this out of the box).
haybale_url="http://host.containers.internal:$E2E_PORT"

# container_script is passed to the container as a single `sh -c`
# argument — nothing is ever mounted or written to the container's disk
# beyond the repo clone itself and this ephemeral command line. Git is
# configured entirely via GIT_CONFIG_COUNT/KEY/VALUE (exported here, not
# passed in via `podman run --env`), mirroring
# docs/stirrup-integration.md's "Sandbox wiring" exactly: the only
# externally injected env is HAYBALE_URL/HAYBALE_TOKEN, and everything
# else is derived from those two inside the container's own shell.
container_script=$(cat <<'INNER'
set -euo pipefail

echo "== container: git version =="
git --version

echo "== container: configuring git via env only (nothing written to disk) =="
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0="url.${HAYBALE_URL}/github.com/.insteadOf"
export GIT_CONFIG_VALUE_0="https://github.com/"
export GIT_CONFIG_KEY_1="credential.${HAYBALE_URL}/.helper"
export GIT_CONFIG_VALUE_1='!f() { echo username=x-access-token; echo "password=$HAYBALE_TOKEN"; }; f'

REPO_URL="https://github.com/__OWNER__/__REPO__.git"
WORKDIR=/tmp/work

# Baseline scan, before any of the above config or any network activity
# touches disk: the base alpine/git image's own binaries (ssh, mostly)
# contain string constants that coincidentally match the PEM-header
# pattern below (format-detection code, not credential material), so
# only a *newly introduced* match after the clone/push below counts as
# a finding — see the final credential-less check.
FORBIDDEN_REGEX='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]|github_pat_[A-Za-z0-9_]|-----BEGIN[[:space:][:alnum:]]*PRIVATE KEY-----'
scan_forbidden() {
  find / -xdev -type f 2>/dev/null | xargs grep -lE "$FORBIDDEN_REGEX" 2>/dev/null | sort
}
scan_forbidden > /tmp/.baseline_matches || true

echo "== container: git clone $REPO_URL (rewritten through haybale) =="
git clone "$REPO_URL" "$WORKDIR"
cd "$WORKDIR"

git config user.name "haybale e2e container"
git config user.email "haybale-e2e@rxbynerd.example"

MARKER="haybale e2e run at $(date -u +%Y-%m-%dT%H:%M:%SZ) from container $(hostname)"
echo "$MARKER" >> e2e-log.txt
git add e2e-log.txt
git commit -q -m "haybale e2e: credential-less container push ($MARKER)"
COMMIT_SHA=$(git rev-parse HEAD)
echo "== container: pushing commit $COMMIT_SHA =="
git push origin HEAD:main
echo "PUSHED_SHA:$COMMIT_SHA"

echo "== container: credential-less check =="
check_failed=0

for f in "$HOME/.netrc" "$HOME/.git-credentials"; do
  if [[ -f "$f" ]]; then
    echo "CREDENTIAL_CHECK: FAIL: $f exists"
    check_failed=1
  fi
done

scan_forbidden > /tmp/.after_matches || true
new_matches="$(grep -vxFf /tmp/.baseline_matches /tmp/.after_matches 2>/dev/null || true)"
if [[ -n "$new_matches" ]]; then
  echo "CREDENTIAL_CHECK: FAIL: forbidden credential pattern newly present in:"
  echo "$new_matches"
  check_failed=1
fi

if env | grep -qE "$FORBIDDEN_REGEX"; then
  echo "CREDENTIAL_CHECK: FAIL: forbidden credential pattern found in environment"
  check_failed=1
fi

if [[ "$check_failed" -eq 0 ]]; then
  echo "CREDENTIAL_CHECK: PASS"
else
  exit 1
fi
INNER
)
container_script="${container_script//__OWNER__/$repo_owner}"
container_script="${container_script//__REPO__/$repo_name}"

echo "e2e-github: running credential-less container ($runtime_bin, image $CONTAINER_IMAGE)"
container_log="$SCRATCH_ABS/container.log"
set +e
"$runtime_bin" run --rm \
  --env "HAYBALE_URL=$haybale_url" \
  --env "HAYBALE_TOKEN=$raw_token" \
  --entrypoint sh \
  "$CONTAINER_IMAGE" \
  -c "$container_script" > "$container_log" 2>&1
container_status=$?
set -e

cat "$container_log"

if [[ $container_status -ne 0 ]]; then
  echo "e2e-github: container run failed (exit $container_status)" >&2
  exit 1
fi
if ! grep -q "^CREDENTIAL_CHECK: PASS$" "$container_log"; then
  echo "e2e-github: credential-less assertion did not pass" >&2
  exit 1
fi

pushed_sha="$(grep '^PUSHED_SHA:' "$container_log" | tail -1 | cut -d: -f2)"
if [[ -z "$pushed_sha" ]]; then
  echo "e2e-github: could not determine pushed commit SHA from container output" >&2
  exit 1
fi
echo "e2e-github: container pushed commit $pushed_sha"

# ---- 4. round-trip confirmation via gh (independent of haybale) -------

echo "e2e-github: confirming round-trip via gh api (bypasses haybale entirely)"
remote_sha="$(gh api "repos/$repo_owner/$repo_name/commits/main" --jq .sha)"
echo "e2e-github: github.com HEAD of $E2E_REPO@main is $remote_sha"

if [[ "$remote_sha" != "$pushed_sha" ]]; then
  echo "e2e-github: round-trip FAILED: pushed $pushed_sha but github.com main is $remote_sha" >&2
  exit 1
fi
echo "e2e-github: round-trip CONFIRMED: $pushed_sha is HEAD of $E2E_REPO@main"

# ---- 5. haybale log evidence (mint -> cache -> inject) -----------------

echo "e2e-github: haybale security/audit log excerpt for this run:"
grep -E 'event=token_minted|msg="proxied request"' "$SCRATCH_ABS/haybale.log" || true

echo "e2e-github: ALL CHECKS PASSED"
