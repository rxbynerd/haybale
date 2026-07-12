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
#   5. Tears down: escalates SIGTERM -> SIGKILL (bounded) for both the
#      haybale process and the container run, and unconditionally
#      removes the scratch config either way.
#
# Preconditions (checked upfront, before any side effect — minting a
# token, starting haybale, or running the container): `just build` has
# produced HAYBALE_BIN, a container runtime is on PATH (or podman's
# known install location), and `gh` is on PATH and authenticated (used
# only at step 4, but checked here so a missing/unauthenticated `gh`
# fails fast instead of being discovered after a real commit has
# already been pushed).
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
#                               (default: derived from this script's own
#                               PID, so two concurrent runs don't race on
#                               the same port).
#   HAYBALE_E2E_SCRATCH         scratch dir for this run's generated
#                               token/config/log (default: .e2e-github.$$,
#                               $$ being this script's PID, so concurrent
#                               runs don't clobber each other's in-flight
#                               files — see .gitignore's `.e2e-github*/`).
#
# Run from the repo root after `just build`:
#   HAYBALE_APP_KEY_PATH=/path/to/key.pem just e2e-github

set -euo pipefail

# ---- configuration ---------------------------------------------------

HAYBALE_BIN="${HAYBALE_BIN:-./haybale}"
CONTAINER_RUNTIME="${HAYBALE_CONTAINER_RUNTIME:-podman}"
APP_ID="${HAYBALE_APP_ID:-4278664}"
E2E_REPO="${HAYBALE_E2E_REPO:-rxbynerd/haybale-e2e}"
# Both defaults below fold in this script's own PID so two concurrent
# invocations don't race on the same scratch dir (whose rm -rf could
# delete an in-flight sibling run's identities/token files) or the same
# listen port (a same-port collision fails loudly; the scratch-dir one
# fails confusingly, mid-run, in whichever run loses the race).
E2E_PORT="${HAYBALE_E2E_PORT:-$((8400 + ($$ % 500)))}"
SCRATCH_DIR="${HAYBALE_E2E_SCRATCH:-.e2e-github.$$}"
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

# gh is only actually used at the very end (step 4, the round-trip
# confirmation independent of haybale), but checking it upfront, before
# any side effect, means a missing/unauthenticated gh fails fast here
# rather than being discovered only after a real commit has already
# been minted-for and pushed to the real scratch repo.
if ! command -v gh >/dev/null 2>&1; then
  echo "e2e-github: 'gh' not found on PATH (needed for the round-trip confirmation in step 4)" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "e2e-github: 'gh' is not authenticated (run 'gh auth login'); needed for the round-trip confirmation in step 4" >&2
  exit 1
fi

repo_owner="${E2E_REPO%%/*}"
repo_name="${E2E_REPO##*/}"
if [[ -z "$repo_owner" || -z "$repo_name" || "$repo_owner" == "$E2E_REPO" ]]; then
  echo "e2e-github: HAYBALE_E2E_REPO=$E2E_REPO must be \"owner/repo\"" >&2
  exit 1
fi

# ---- scratch dir + cleanup ---------------------------------------------
#
# Everything this script generates — the minted raw token, both YAML
# configs, and haybale's own log for this run — lives under SCRATCH_DIR
# (default includes this script's PID — see the header comment), which
# is .gitignore'd (see .gitignore's `.e2e-github*/`) and removed on
# every exit path (success, failure, or interrupt) so nothing it
# contains ever has a chance to end up committed or leak past this run.

rm -rf "$SCRATCH_DIR"
mkdir -p "$SCRATCH_DIR"
SCRATCH_ABS="$(cd "$SCRATCH_DIR" && pwd)"

HAYBALE_PID=""
CONTAINER_PID=""
# Run-scoped name for the container step (see step 3 below), so cleanup()
# can ask the runtime to kill it directly by name. Verified empirically
# on this dev machine's rootless podman-machine setup: the container
# process runs inside podman's VM, decoupled from the `podman run`
# client on the host, so signaling (even SIGKILL-ing) the client PID
# alone does *not* stop the container early — it keeps running until
# its own command finishes. `podman kill <name>` (or `docker kill`),
# which asks the runtime itself to stop the named container, does.
CONTAINER_NAME="haybale-e2e-$$"

# terminate_pid escalates SIGTERM -> a short bounded poll -> SIGKILL, so
# cleanup() below can never block indefinitely on a stuck child — e.g. a
# connection genuinely wedged at teardown time — regardless of why it
# won't exit on its own. Idempotent/safe to call on an already-dead pid.
terminate_pid() {
  local pid="$1" label="$2" waited=0
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null && ((waited < 5)); do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "e2e-github: $label (pid $pid) still alive ${waited}s after SIGTERM; sending SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

# cleanup is bounded by construction (terminate_pid above never blocks
# indefinitely, and killing the container by name is near-instant), so
# the scratch-dir removal below always runs — it is never gated behind
# a hang. Covers EXIT/INT/TERM: a normal exit, an interactive Ctrl-C,
# and an external `kill -TERM` all reach it.
cleanup() {
  local status=$?
  if [[ -n "$CONTAINER_NAME" ]]; then
    "$runtime_bin" kill "$CONTAINER_NAME" >/dev/null 2>&1 || true
    "$runtime_bin" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  terminate_pid "$CONTAINER_PID" "container run"
  terminate_pid "$HAYBALE_PID" "haybale serve"
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
#
# --drain-timeout bounds how long haybale itself waits, on its own
# SIGTERM handling, for in-flight requests to finish draining. This is a
# test harness, not production — production's own default (0, wait
# indefinitely — see cmd/haybale/cmd/serve.go) is the deliberately
# correct choice there, but a bounded value here means teardown can't
# hang on this process even before cleanup()'s own SIGTERM/SIGKILL
# escalation ever gets involved.

echo "e2e-github: starting haybale serve on :$E2E_PORT"
"$HAYBALE_BIN" serve --config "$SCRATCH_ABS/haybale.yaml" --drain-timeout 5s > "$SCRATCH_ABS/haybale.log" 2>&1 &
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

FORBIDDEN_REGEX='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]|github_pat_[A-Za-z0-9_]|-----BEGIN[[:space:][:alnum:]]*PRIVATE KEY-----'

# scan_forbidden scans every regular file reachable from / for
# FORBIDDEN_REGEX, writing the sorted list of matching paths to $1.
# Deliberately NOT `find -xdev`: -xdev excludes anything on a different
# device than /, which silently drops real mounted volumes -- notably
# alpine/git's own anonymous /git volume (confirmed via /proc/mounts: a
# separate xfs mount, not part of the root overlay), and would also
# silently drop /tmp itself (where the clone/push below actually
# happens) under any runtime that mounts it separately. Pseudo-
# filesystems (/proc, /sys, /dev) are pruned by NAME instead, so they're
# excluded without excluding real storage that happens to live on its
# own mount.
#
# Each candidate file is scanned individually (names NUL-delimited from
# find -print0, one grep call per file) rather than batched through a
# single `xargs grep`: batching makes "zero matches in this batch" and
# "a real failure partway through this batch" both surface as the same
# nonzero xargs exit code, which is exactly the silent-failure shape a
# credential check must not have. Scanning file-by-file lets the
# overwhelmingly common "no match in this one file" (grep exit 1) be
# told apart from a genuine per-file error (any other nonzero).
#
# Returns 0 once the scan itself has completed -- zero matches is a
# legitimate, successful outcome -- or 2 if the scan pipeline itself
# broke, so a broken scan can never be indistinguishable from a
# genuinely clean pass.
scan_forbidden() {
  outfile="$1"
  names_tmp="$(mktemp)"

  set +e
  find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -print0 \
    > "$names_tmp" 2>/tmp/.scan_find_err
  find_rc=$?
  set -e
  if [ "$find_rc" -ne 0 ]; then
    echo "scan_forbidden: find failed (exit $find_rc):" >&2
    cat /tmp/.scan_find_err >&2
    rm -f "$names_tmp"
    return 2
  fi

  : > "$outfile"
  scan_errors=0
  while IFS= read -r -d '' f; do
    [ -n "$f" ] || continue
    set +e
    grep -qE "$FORBIDDEN_REGEX" "$f" 2>/tmp/.scan_grep_err
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      echo "$f" >> "$outfile"
    elif [ "$rc" -ne 1 ]; then
      scan_errors=$((scan_errors + 1))
      echo "scan_forbidden: grep failed on $f (exit $rc):" >&2
      cat /tmp/.scan_grep_err >&2
    fi
  done < "$names_tmp"
  rm -f "$names_tmp"

  if [ "$scan_errors" -gt 0 ]; then
    echo "scan_forbidden: $scan_errors file(s) could not be scanned" >&2
    return 2
  fi
  sort -o "$outfile" "$outfile"
  return 0
}

# hash_matches writes a "sha256sum  path" line for every path listed
# (one per line) in $1 to $2. Lets an already-flagged path (e.g. the
# stock ssh binaries' own PEM-format-detection string literals, treated
# as a known baseline below) be re-checked for *content* changes rather
# than treated as permanently cleared once its path is known -- a real
# secret appended into one of those same paths would otherwise never
# register as "new" under a path-only comparison.
hash_matches() {
  list="$1"
  outfile="$2"
  : > "$outfile"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    sha256sum "$f" >> "$outfile" 2>/dev/null || true
  done < "$list"
}

# lookup_hash prints the hash recorded for an exact path in a
# hash_matches-produced file ($1), or nothing if that path isn't in it.
# An exact per-line comparison rather than `grep -F` substring matching,
# since a plain substring search could false-positive when one baseline
# path happens to be a suffix of another line in the file.
lookup_hash() {
  file="$1" target="$2"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    lpath="${line#*  }"
    if [ "$lpath" = "$target" ]; then
      printf '%s\n' "${line%%  *}"
      return 0
    fi
  done < "$file"
  return 1
}

# Baseline scan, before any of the above config or any network activity
# touches disk: the base alpine/git image's own binaries (ssh, mostly)
# contain string constants that coincidentally match the PEM-header
# pattern below (format-detection code, not credential material), so
# only material newly introduced or changed after the clone/push below
# counts as a finding — see the final credential-less check.
if ! scan_forbidden /tmp/.baseline_matches; then
  echo "e2e-github(container): baseline credential scan itself failed -- aborting before any network activity" >&2
  exit 1
fi
hash_matches /tmp/.baseline_matches /tmp/.baseline_hashes

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

if ! scan_forbidden /tmp/.after_matches; then
  echo "CREDENTIAL_CHECK: FAIL: after-run credential scan itself failed (see above) -- cannot assert credential-less"
  check_failed=1
else
  # Brand-new matches: a path that matches now but didn't even appear in
  # the baseline scan's match list at all.
  new_matches="$(grep -vxFf /tmp/.baseline_matches /tmp/.after_matches 2>/dev/null || true)"
  if [[ -n "$new_matches" ]]; then
    echo "CREDENTIAL_CHECK: FAIL: forbidden credential pattern newly present in:"
    echo "$new_matches"
    check_failed=1
  fi

  # Content-changed matches: a path that already matched at baseline
  # (e.g. one of the stock ssh binaries' own PEM-detection strings,
  # intentionally excluded above as a known false positive) whose
  # *content* has since changed -- catches a secret appended into an
  # already-excluded path, which the new-path check above cannot, since
  # the path itself isn't new.
  hash_matches /tmp/.after_matches /tmp/.after_hashes
  changed_matches=""
  while IFS= read -r hashline; do
    [[ -n "$hashline" ]] || continue
    fhash="${hashline%%  *}"
    fpath="${hashline#*  }"
    baseline_hash="$(lookup_hash /tmp/.baseline_hashes "$fpath" || true)"
    if [[ -n "$baseline_hash" && "$fhash" != "$baseline_hash" ]]; then
      changed_matches="$changed_matches$fpath
"
    fi
  done < /tmp/.after_hashes
  if [[ -n "$changed_matches" ]]; then
    echo "CREDENTIAL_CHECK: FAIL: forbidden credential pattern content changed in already-flagged path(s):"
    echo "$changed_matches"
    check_failed=1
  fi
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

# Backgrounded and waited on, rather than run as a single blocking
# foreground command: bash only checks for a trapped signal between
# commands, and a foreground child is one long uninterruptible "command"
# from the trap's point of view for as long as it runs -- an external
# `kill -TERM` followed by a `kill -KILL` (the common CI-cancellation
# shape) can land entirely inside that window and skip cleanup()
# altogether. `wait` on a background job, by contrast, is interruptible:
# bash's own docs are explicit that a trapped signal received while
# waiting causes `wait` to return immediately so the trap can run, which
# is exactly the promptness this step needs during the long clone/push.
"$runtime_bin" run --rm \
  --name "$CONTAINER_NAME" \
  --env "HAYBALE_URL=$haybale_url" \
  --env "HAYBALE_TOKEN=$raw_token" \
  --entrypoint sh \
  "$CONTAINER_IMAGE" \
  -c "$container_script" > "$container_log" 2>&1 &
CONTAINER_PID=$!

container_status=0
wait "$CONTAINER_PID" || container_status=$?
CONTAINER_PID=""
CONTAINER_NAME=""

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
