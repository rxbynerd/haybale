# Runbook: real-GitHub acceptance (M6)

This is haybale's final acceptance test: a **credential-less container**
(only `HAYBALE_URL`/`HAYBALE_TOKEN` in its environment — no GitHub
credential anywhere) clones and pushes a **real private GitHub
repository** entirely through a locally-running haybale, using a **real
GitHub App** to mint the upstream credential. It is the end-to-end proof
that every other milestone's unit/integration tests only approximated
against fakes.

`just e2e-github` (`scripts/e2e-github.sh`) runs it. It is deliberately
**not** wired into CI — it needs a real GitHub App private key, a real
private repo, and a container runtime that can reach back out to the
host, none of which CI has.

## 1. Creating a GitHub App for this (skip if reusing "haybale dev")

haybale's own repo already has a live App for this purpose — see
["Using the existing App"](#2-using-the-existing-app-haybale-dev) below.
A different operator repeating this acceptance elsewhere creates their
own:

1. GitHub → Settings → Developer settings → GitHub Apps → **New GitHub App**.
2. **GitHub App name**: anything unique (e.g. `haybale dev`). **Homepage
   URL**: anything valid (unused) — e.g. the haybale repo's URL.
   **Callback URL**: leave blank. **Webhook**: **uncheck "Active"** —
   this App only ever mints installation tokens; it has no use for
   webhook deliveries.
3. **Repository permissions**: set **Contents: Read and write**,
   **Metadata: Read-only** (Metadata is implicitly required and
   auto-selected). Grant nothing else — this is the least-privilege set
   `internal/upstream.GitHubAppSource` actually asks for (see
   `docs/security.md`'s "Least-privilege GitHub App token minting").
4. **Where can this GitHub App be installed?**: "Only on this account"
   is sufficient for a personal test.
5. Create the App, note its **App ID** (shown at the top of the App's
   settings page).
6. Scroll to **Private keys** → **Generate a private key**. This
   downloads a `.pem` file **once** — save it somewhere outside any git
   repository and `chmod 600` it immediately:

   ```
   chmod 600 ~/Downloads/your-app.private-key.pem
   ```

   haybale's own `internal/config.Validate()` refuses to start if this
   file is group- or world-readable (CWE-732) — see
   `docs/configuration.md`'s "Upstreams" section.
7. **Install the App**: from the App's settings page, "Install App" →
   pick the account/org → **"Only select repositories"** → choose the
   private repo(s) this acceptance test should touch (or "All
   repositories" if you'll create new scratch repos over time, as this
   project does — see step 2 below).
8. Create a **private** scratch repository dedicated to this test (never
   reuse a repo with real content):

   ```
   gh repo create <owner>/haybale-e2e --private --description "haybale acceptance test scratch repo"
   ```

   Seed it with an initial commit so there's a `HEAD` to clone from —
   any commit works; `scripts/e2e-github.sh` doesn't care what's in the
   repo beyond a `main` branch existing.

## 2. Using the existing App ("haybale dev")

This project already has a live App: **"haybale dev"**, **App ID
`4278664`**, installed on the `rxbynerd` (installation `146047506`) and
`ghostworks` (installation `146047537`) accounts with
`repository_selection=all` and `contents:write`+`metadata:read` — so any
repo under either account is reachable, including a freshly created one.
The private key lives outside this repository; it is referenced **only**
via the `HAYBALE_APP_KEY_PATH` environment variable, never checked in and
never printed by anything in this codebase.

The acceptance target is the dedicated private scratch repo
`rxbynerd/haybale-e2e` (`docs/runbook-github-acceptance.md`'s own
existence is the reason it exists — nothing else touches it). Traffic
from `just e2e-github` only ever reads/writes that one repo: the
generated `policy.yaml` grants the run's identity `read`+`write` on
exactly `github.com/rxbynerd/haybale-e2e` and nothing else — default deny
covers every other repo the App could technically reach.

## 3. Running it

Prerequisites: `just build` succeeds, `gh` is authenticated (`gh auth
status`), and a container runtime is installed — this dev environment
uses **podman** (docker is not installed), at `/opt/podman/bin/podman`.

```
HAYBALE_APP_KEY_PATH=/path/to/haybale-dev.private-key.pem just e2e-github
```

Optional environment variables (all have working defaults for this
project's own App/repo — see `scripts/e2e-github.sh`'s header comment
for the full list):

| Variable                     | Default                    | Purpose |
|-------------------------------|-----------------------------|---------|
| `HAYBALE_APP_KEY_PATH`         | *(required)*                | Path to the GitHub App's PEM private key. |
| `HAYBALE_CONTAINER_RUNTIME`    | `podman`                    | `docker` or `podman`. |
| `HAYBALE_APP_ID`               | `4278664` ("haybale dev")   | GitHub App ID. |
| `HAYBALE_E2E_REPO`             | `rxbynerd/haybale-e2e`      | `owner/repo` on `github.com` to round-trip against. |
| `HAYBALE_E2E_PORT`             | `8466`                      | Port haybale listens on for this run. |

### What it does

1. Mints a run-scoped haybale identity token (`haybale token new`) and
   writes a scratch `identities.yaml`/`policy.yaml`/`haybale.yaml` — the
   policy grants that one identity `read`+`write` on exactly
   `HAYBALE_E2E_REPO`, nothing else. All three files (and the raw token)
   live under `.e2e-github/` (`.gitignore`'d) and are deleted on every
   exit path, success or failure.
2. Starts `haybale serve` on the host, in the background, and polls
   `/healthz` until it's up.
3. Runs a single `podman run --rm` (or `docker run --rm`) container of
   `alpine/git`, passing **only** `HAYBALE_URL` (haybale's address, as
   `http://host.containers.internal:$PORT` — see "Container→host
   networking" below) and `HAYBALE_TOKEN` (the raw minted token) as
   `--env`. Entirely from inside that container's own shell:
   - configures git via `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
     `GIT_CONFIG_VALUE_n` — an `insteadOf` rewrite from
     `https://github.com/` to haybale's URL, and a credential helper
     that echoes `HAYBALE_TOKEN` as the Basic-auth password — mirroring
     `docs/stirrup-integration.md`'s "Sandbox wiring" exactly. **Nothing
     is written to disk for this**: no `~/.gitconfig`, no credential
     file, purely environment variables the container's own shell
     exports for itself, derived from the two it was given;
   - clones `HAYBALE_E2E_REPO` (rewritten through haybale), commits a
     marker line, and pushes back — both legs going through haybale,
     which mints and injects the real GitHub credential on the egress
     hop only;
   - checks its own filesystem and environment for git-host credential
     material (see "Credential-less assertion" below) and prints
     `CREDENTIAL_CHECK: PASS` or `FAIL`.
4. Confirms the pushed commit SHA is actually `HEAD` of the repo's
   `main` branch via `gh api` — a channel entirely independent of
   haybale, run from the host with the operator's own `gh` credentials,
   not anything haybale minted.
5. Tears down: kills the `haybale serve` process and removes the scratch
   dir, via a `trap` that fires on success, failure, or interruption —
   safely re-runnable any number of times.

### Credential-less assertion

The container checks, before it exits:

- `~/.netrc` and `~/.git-credentials` do not exist (the `GIT_CONFIG_*`
  approach never creates either).
- No file on the container's filesystem (`find / -xdev`, i.e. the
  container's own root filesystem — this naturally excludes `/proc`,
  `/sys`, `/dev`, which are separate mounted filesystems) newly contains
  a GitHub token shape (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/
  `github_pat_`) or a PEM private-key header, compared against a
  baseline scan taken before the container touches the network at all.
  (The baseline exists because the stock `alpine/git` image's own `ssh`
  binaries contain PEM-format-detection string literals that otherwise
  false-positive on the PEM pattern — diffing against that baseline
  means only material introduced by *this run* counts as a finding.)
- No environment variable's value matches any of the same patterns.

The minted upstream credential — a real `ghs_…` GitHub App installation
token — is exactly the shape this check would catch, and it is never
handed to the container: haybale injects it only on the egress hop to
GitHub, entirely inside the haybale process. The one secret the
container does hold, `HAYBALE_TOKEN`, is deliberately not in this
checklist: it's a haybale-scoped bearer token whose blast radius is this
run's one `policy.yaml` rule, not a credential that works against
GitHub — precisely the distinction this whole project exists to enforce.

### Container→host networking

`podman` (like Docker Desktop, but unlike Linux Docker's default bridge)
runs containers inside a VM, so `127.0.0.1`/`localhost` from inside the
container refers to the container itself, not the host running
`haybale serve`. The fix is `host.containers.internal` — podman's own
host-gateway DNS alias, confirmed by resolving it from inside an
`alpine/git` container:

```
$ podman run --rm --entrypoint sh alpine/git -c 'getent hosts host.containers.internal'
192.168.127.254   host.containers.internal  host.containers.internal
```

and confirmed end-to-end against a real listener on the host:

```
$ podman run --rm --entrypoint sh alpine/git -c 'wget -S -O- http://host.containers.internal:18470/healthz'
Connecting to host.containers.internal:18470 (192.168.127.254:18470)
  HTTP/1.1 200 OK
  ...
```

`scripts/e2e-github.sh` therefore sets `HAYBALE_URL=http://host.containers.internal:$PORT`
rather than `127.0.0.1`. Docker Desktop resolves the same hostname
out of the box; plain Linux Docker needs `--add-host
host.containers.internal:host-gateway` on older versions (Docker
≥20.10 wires this up automatically for `host-gateway`, but under the
literal name `host.docker.internal` unless configured otherwise) — if a
future operator hits `HAYBALE_CONTAINER_RUNTIME=docker` and the resolve
fails, point `HAYBALE_URL` at `host.docker.internal` instead, or add the
explicit `--add-host` mapping.

## 4. Captured evidence: a real successful run

The transcript below is `just e2e-github`'s actual, unedited stdout from
a real run against the live "haybale dev" App and the real
`rxbynerd/haybale-e2e` repo (only the leading `go build`/recipe-echo
lines from `just` are trimmed). No redaction was needed — nothing
secret is ever printed by the script itself, since `HAYBALE_TOKEN` is
only ever handed to the container as an environment variable, never
echoed, and the upstream GitHub App token never leaves haybale's own
process.

```
e2e-github: using container runtime: podman
e2e-github: minting identity token for run-e2e-1783866764-70240
e2e-github: starting haybale serve on :8466
e2e-github: haybale is healthy (pid 70271)
e2e-github: running credential-less container (podman, image docker.io/alpine/git)
== container: git version ==
git version 2.54.0
== container: configuring git via env only (nothing written to disk) ==
== container: git clone https://github.com/rxbynerd/haybale-e2e.git (rewritten through haybale) ==
Cloning into '/tmp/work'...
== container: pushing commit 3ea35ae81cffe9fe74531c9070ec149b0a9431c9 ==
To http://host.containers.internal:8466/github.com/rxbynerd/haybale-e2e.git
   b82e7a6..3ea35ae  HEAD -> main
PUSHED_SHA:3ea35ae81cffe9fe74531c9070ec149b0a9431c9
== container: credential-less check ==
CREDENTIAL_CHECK: PASS
e2e-github: container pushed commit 3ea35ae81cffe9fe74531c9070ec149b0a9431c9
e2e-github: confirming round-trip via gh api (bypasses haybale entirely)
e2e-github: github.com HEAD of rxbynerd/haybale-e2e@main is 3ea35ae81cffe9fe74531c9070ec149b0a9431c9
e2e-github: round-trip CONFIRMED: 3ea35ae81cffe9fe74531c9070ec149b0a9431c9 is HEAD of rxbynerd/haybale-e2e@main
e2e-github: haybale security/audit log excerpt for this run:
time=2026-07-12T15:32:52.307+01:00 level=WARN msg="security event" event=token_minted host=github.com owner=rxbynerd repo=haybale-e2e verb=read appID=4278664 installationID=146047506
time=2026-07-12T15:32:52.580+01:00 level=INFO msg="proxied request" identity=run-e2e-1783866764-70240 host=github.com owner=rxbynerd repo=haybale-e2e verb=read status=200 bytesIn=0 bytesOut=191 durationMs=273
time=2026-07-12T15:32:52.734+01:00 level=INFO msg="proxied request" identity=run-e2e-1783866764-70240 host=github.com owner=rxbynerd repo=haybale-e2e verb=read status=200 bytesIn=181 bytesOut=145 durationMs=151
time=2026-07-12T15:32:52.884+01:00 level=INFO msg="proxied request" identity=run-e2e-1783866764-70240 host=github.com owner=rxbynerd repo=haybale-e2e verb=read status=200 bytesIn=223 bytesOut=1320 durationMs=147
time=2026-07-12T15:32:53.100+01:00 level=WARN msg="security event" event=token_minted host=github.com owner=rxbynerd repo=haybale-e2e verb=write appID=4278664 installationID=146047506
time=2026-07-12T15:32:53.318+01:00 level=INFO msg="proxied request" identity=run-e2e-1783866764-70240 host=github.com owner=rxbynerd repo=haybale-e2e verb=write status=200 bytesIn=0 bytesOut=334 durationMs=217
time=2026-07-12T15:32:53.969+01:00 level=INFO msg="proxied request" identity=run-e2e-1783866764-70240 host=github.com owner=rxbynerd repo=haybale-e2e verb=write status=200 bytesIn=590 bytesOut=66 durationMs=646
e2e-github: ALL CHECKS PASSED
```

### Reading the credential lifecycle out of this log

- **mint**: the two `event=token_minted` lines are `GitHubAppSource.mint`
  (`internal/upstream/githubapp.go`) actually calling
  `POST /app/installations/146047506/access_tokens` against the real
  GitHub API — once for the clone's `read` scope, once for the push's
  `write` scope — each scoped to exactly `rxbynerd/haybale-e2e` and
  nothing else (see `docs/security.md`'s "Least-privilege GitHub App
  token minting"). The minted `ghs_…` token itself never appears in this
  log, by construction — `mint`'s own doc comment is explicit that it's
  never included in the event or in any error.
- **cache**: three `verb=read` "proxied request" lines follow the single
  `read` mint — `GET info/refs?service=git-upload-pack`, then the pack
  negotiation round-trip(s) `git`'s protocol v2 makes for a clone — but
  only **one** mint. The second and third read requests reused the
  cached token (`internal/upstream/tokencache.go`) rather than minting
  again; the same pattern repeats for the two `verb=write` requests (the
  push handshake's `GET info/refs?service=git-receive-pack` — itself
  classified `write`, see `docs/security.md` — and the `POST
  git-receive-pack` that follows) sharing the single `write` mint.
- **inject**: every "proxied request" line reports `status=200` — the
  real GitHub upstream accepted the credential haybale injected on each
  request's egress hop (`internal/proxy/proxy.go`'s `rewrite`). Had
  injection failed or the upstream rejected the credential, this would
  instead be a `502` via an `upstream_auth_failed` security event (see
  `docs/security.md`), never a `401` reaching back to the container.

This same run's independent `gh api` check (bypassing haybale entirely,
using the operator's own `gh` credentials) confirmed
`3ea35ae81cffe9fe74531c9070ec149b0a9431c9` — the exact SHA the container
reported pushing — as `HEAD` of `rxbynerd/haybale-e2e`'s `main` branch,
closing the loop: the commit that left the credential-less container
really did land on the real, private GitHub repository, having never
carried a GitHub credential of its own at any point.
