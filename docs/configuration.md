# Configuration

haybale is configured by a single YAML file, plus a small number of
`haybale serve` flags that override specific fields in it:

```
haybale serve --config haybale.yaml
```

`--config` defaults to `haybale.yaml` in the current directory. The file is
loaded once, at startup: `haybale serve` fails fast (refuses to start,
exit code 1) if the config — including the identity and policy files it
points at — is missing, malformed, or otherwise invalid, rather than
starting up and failing unpredictably on the first request.

This document describes every field haybale's config package
(`internal/config`) actually parses and validates. If a field isn't
listed here, haybale doesn't read it.

## Top-level fields

```yaml
listen: ":8466"          # optional, default shown
logLevel: info            # optional, default shown: debug|info|warn|error
drainTimeout: 2m           # optional, default shown
tls: { ... }               # optional, see "TLS" below
identity: { ... }          # required, see "Identity" below
policy: { ... }            # required, see "Policy" below
upstreams: [ ... ]         # required, at least one entry, see "Upstreams" below
```

| Field          | Default  | Notes                                                                                 |
|----------------|----------|----------------------------------------------------------------------------------------|
| `listen`       | `:8466`  | Address `net/http.Server` binds to.                                                     |
| `logLevel`     | `info`   | One of `debug`, `info`, `warn`, `error` (case-insensitive).                             |
| `drainTimeout` | `2m`     | Go duration string bounding graceful shutdown. `0s` explicitly means wait indefinitely. |

`logLevel` controls the `log/slog` level haybale logs at. Every log line
— including request logs and security events — passes through a
scrubbing handler that redacts token/credential material before it
reaches the log sink, regardless of level (see `docs/security.md`).

## Flags that override config

| Flag              | Overrides            | Effect when left unset |
|-------------------|-----------------------|-------------------------|
| `--config`        | (selects the file)   | Defaults to `haybale.yaml`. |
| `--tls-cert-path` | `tls.certPath`        | Value from the config file is used as-is. |
| `--tls-key-path`  | `tls.keyPath`         | Value from the config file is used as-is. |
| `--drain-timeout` | `drainTimeout`        | Value from the config file (or its own default) is used as-is. |

A flag only overrides its corresponding field when the flag is actually
set to a non-empty value — an unset flag never clobbers a value the
config file set. Overrides are applied *before* validation, so an
override participates in exactly the same fail-fast checks as a value
written directly into the YAML file (an override that points
`--tls-cert-path` at a missing file fails startup the same way a bad
`tls.certPath` in the file would).

## TLS

```yaml
tls:
  certPath: /etc/haybale/tls/tls.crt   # PEM certificate (chain OK)
  keyPath: /etc/haybale/tls/tls.key    # PEM private key matching certPath
```

Leaving the entire `tls` block empty serves plain HTTP. Setting exactly
one of `certPath`/`keyPath` fails startup — a half-configured TLS block
is treated as a mistake, not a valid state.

When both are set, haybale loads and parses the certificate/key pair
once, at startup (via `tls.LoadX509KeyPair`), and fails fast if the file
is missing, unreadable, or the pair doesn't match. It then serves HTTPS
(`http.Server.ListenAndServeTLS`) with `tls.Config.MinVersion` pinned to
TLS 1.2.

TLS (or its absence) never changes the server's read/write timeout
behaviour: haybale sets `ReadHeaderTimeout: 10s` (bounding only how long
the server waits to read a request's headers) and deliberately no
read/write/idle timeout at all, with or without TLS — pack transfers can
run to gigabytes and take arbitrarily long. See `docs/security.md` for
when plain HTTP is (and isn't) an acceptable choice.

## Graceful drain

`drainTimeout` bounds how long `haybale serve` waits, on `SIGTERM` or
`SIGINT`, for in-flight requests to finish before the process exits.
On either signal, haybale:

1. Stops advertising itself as healthy: `/healthz` starts returning `503`
   instead of `200` (still auth-exempt, still served on the same
   listener), so a load balancer's health check stops routing new
   traffic to this instance.
2. Calls `http.Server.Shutdown`, which stops accepting new connections
   but lets any request already in flight — a large `git clone`/`push`
   still streaming in particular — finish completely, rather than
   cutting it off mid-transfer.

`drainTimeout` bounds step 2 only. The default, `2m`, is generous for
even a large clone/push to finish once shutdown begins while still
giving a backstop against a connection that never completes on its own.
Set `drainTimeout: 0s` explicitly to wait indefinitely instead (no
backstop at all — Shutdown blocks until every in-flight request finishes
on its own).

## Identity

```yaml
identity:
  type: static-token-file
  path: identities.yaml
```

`static-token-file` is the only supported `type` today. `path` points at
a YAML file of identity IDs and their token digests:

```yaml
# identities.yaml
identities:
  - id: run-9f2c1a
    tokenDigest: sha256:3f9c...  # SHA-256 hex digest, "sha256:" prefix required
```

Only the digest is ever persisted — haybale never stores or logs a raw
token. To provision a new identity:

```
haybale token new --id run-9f2c1a
```

This prints the raw token once (to hand to the caller — e.g. as an
environment variable inside a sandbox) and the `identities.yaml` stanza
to add in its place. The raw token is never itself stored anywhere;
losing it means minting a new one.

A request authenticates by presenting the token as either the HTTP Basic
password (the username is ignored — this is what `git` itself sends) or
an `Authorization: Bearer <token>` header. haybale hashes whatever was
presented with SHA-256 and compares it, in constant time, against every
configured identity's digest.

## Policy

```yaml
policy:
  path: policy.yaml
```

`path` points at a YAML file of ordered, first-match-wins rules,
evaluated against every authenticated request:

```yaml
# policy.yaml
rules:
  - identities: ["run-*"]
    repos: ["github.com/acme/*"]
    permissions: [read, write]
  - identities: ["run-readonly-*"]
    repos: ["github.com/acme/public-docs"]
    permissions: [read]
```

- `identities`: glob patterns (Go's `path.Match` syntax) matched against
  the authenticated identity's ID.
- `repos`: glob patterns matched against `{host}/{owner}/{repo}` — the
  same three segments as the request's `/{host}/{owner}/{repo}.git/...`
  path, joined with `/`. `*` never crosses a `/` boundary, so a pattern
  must always specify all three segments (`github.com/acme/*`, not
  `acme/*`) — a pattern with the wrong segment count simply never
  matches, which is a configuration mistake rather than a security hole
  (default-deny means an always-false rule grants nothing).
- `permissions`: any combination of `read` and `write`. `write` does
  *not* implicitly grant `read` — list both explicitly if a rule should
  cover both.

Rules are evaluated in order; the **first** rule whose `identities` and
`repos` patterns both match decides the outcome (`Allowed` iff that
rule's `permissions` includes the verb the request needs), even if a
later rule would also have matched. A request that matches no rule at
all is denied — **default deny**.

`GET .../info/refs?service=git-receive-pack` (the push handshake) is
classified as a `write`, same as the `POST .../git-receive-pack` that
follows it — a `read`-only identity can fetch but the push handshake
itself is rejected before any data is exchanged.

Every denial — whether no rule matched at all, or a rule matched but
didn't grant the requested verb — maps to the same `404 Not Found` a
genuinely nonexistent repo would produce. See `docs/security.md` for why.

Use `haybale policy check` to dry-run a decision without making a real
request:

```
haybale policy check --config haybale.yaml \
  --id run-9f2c1a --repo github.com/acme/widgets --verb read
```

This loads `--config` the same way `haybale serve` does (so it's
checking the exact policy engine that would actually be running) and
prints `ALLOW`/`DENY`, the matched rule (or `none (default deny)`), and
the reason. It makes no network call and never touches an upstream
credential.

## Upstreams

```yaml
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential:
      type: github-app
      appID: 123456
      privateKeyPath: /etc/haybale/github-app.pem
      apiBaseURL: https://api.github.com   # optional, default shown

  - host: git.internal.example
    baseURL: https://git.internal.example:8443
    credential:
      type: static
      username: git                          # optional, default: x-access-token
      tokenEnv: HAYBALE_INTERNAL_GIT_TOKEN    # never set the token inline
```

At least one upstream is required; `host` must be unique across all of
them.

haybale's URL scheme encodes the upstream as the **first path segment**:
a client requests `http://haybale.internal:8466/{host}/{owner}/{repo}.git/<endpoint>`,
haybale strips the `{host}` segment and rewrites the rest onto
`baseURL` — `host` is purely a routing key and need not match `baseURL`'s
actual hostname (this is also what makes it easy to point a test harness
at a fake upstream under an arbitrary key). One `host` entry is one
egress-allowlist entry in front of haybale.

### `credential`

Every upstream's `credential` block picks how haybale authenticates the
*outbound* leg of a proxied request — never the same credential the
client presented to haybale, which is discarded immediately after
`identity`/`policy` checks pass.

**`type: static`** — a single, fixed Basic-auth credential:

- `username` (optional, default `x-access-token`): the Basic-auth
  username presented upstream. Most git hosts (including
  `git-http-backend`) ignore the username entirely and check only the
  password, so the default works for authenticating with just a token.
- `tokenEnv` (required): the name of an environment variable haybale
  reads the secret from, at startup. **The token must never be written
  inline in the YAML file** — a `token:` field set directly in the
  config is rejected outright at startup (not silently ignored), since a
  config file is far more likely to end up committed, in a support
  bundle, or in shell history than the environment variable it should
  live in instead.

**`type: github-app`** — a GitHub App installation token, minted
per-request and scoped to the minimum needed:

- `appID` (required): the GitHub App's ID.
- `privateKeyPath` (required): path to the App's PEM-encoded RSA private
  key. Read and parsed once, at startup — a missing file or one that
  isn't a valid RSA key fails startup immediately.
- `apiBaseURL` (optional, default `https://api.github.com`): override for
  a GitHub Enterprise Server instance, e.g. `https://ghe.example.com/api/v3`.

For each request, haybale resolves which installation owns the target
repo (cached ~1h — this mapping is stable) and mints a fresh installation
access token scoped to **exactly that one repository** and the minimal
permission the request's verb needs (`contents: read` for a fetch,
`contents: write` for a push) — never a broader, org-wide, or
multi-repo token. Minted tokens are cached and refreshed ahead of expiry
(GitHub installation tokens are short-lived), with concurrent requests
for the same repo/verb collapsed into a single mint call.

## Worked example

A complete, minimal `haybale.yaml`:

```yaml
listen: ":8466"
logLevel: info
tls:
  certPath: /etc/haybale/tls/tls.crt
  keyPath: /etc/haybale/tls/tls.key
drainTimeout: 2m

identity:
  type: static-token-file
  path: /etc/haybale/identities.yaml

policy:
  path: /etc/haybale/policy.yaml

upstreams:
  - host: github.com
    baseURL: https://github.com
    credential:
      type: github-app
      appID: 123456
      privateKeyPath: /etc/haybale/github-app.pem
```

```yaml
# /etc/haybale/identities.yaml
identities:
  - id: run-9f2c1a
    tokenDigest: sha256:3f9c1e6b2a...
```

```yaml
# /etc/haybale/policy.yaml
rules:
  - identities: ["run-*"]
    repos: ["github.com/acme/*"]
    permissions: [read, write]
```
