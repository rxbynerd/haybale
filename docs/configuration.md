# Configuration

haybale is configured by a single YAML file, plus a small number of
`haybale serve` flags that override specific fields in it:

```console
haybale serve --config haybale.yaml
```

`--config` defaults to `haybale.yaml` in the current directory. The file is
loaded once, at startup: `haybale serve` fails fast (refuses to start,
exit code 1) if the config or a required policy, key, certificate, or JWKS file
is missing, malformed, or otherwise invalid, rather than
starting up and failing unpredictably on the first request.

This document describes every supported configuration field. Unknown fields
are not part of haybale's configuration contract and should not be used, with
one exception: the `cache` block rejects unknown fields (see "Cache").

## Top-level fields

```yaml
listen: ":8466"          # optional, default shown
logLevel: info            # optional, default shown: debug|info|warn|error
drainTimeout: 0s           # optional, default shown (0s = wait indefinitely)
tls: { ... }               # optional, see "TLS" below
identity: { ... }          # required, see "Identity" below
policy: { ... }            # required, see "Policy" below
upstreams: [ ... ]         # required, at least one entry, see "Upstreams" below
telemetry: { ... }         # optional, OpenTelemetry export, see "Telemetry" below
cache: { ... }             # optional, response cache for reads, off by default, see "Cache" below
```

| Field          | Default  | Notes                                                                                                |
|----------------|----------|-------------------------------------------------------------------------------------------------------|
| `listen`       | `:8466`  | Address `net/http.Server` binds to.                                                                   |
| `logLevel`     | `info`   | One of `debug`, `info`, `warn`, `error` (case-insensitive).                                            |
| `drainTimeout` | `0s`     | Go duration string bounding graceful shutdown. `0s` (the default) means wait indefinitely — see "Graceful drain" below. |

`logLevel` controls the `log/slog` level haybale logs at. Every log line
— including request logs and security events — passes through a
scrubbing handler that redacts token/credential material before it
reaches the log sink, regardless of level (see the [security
model](security.md#logging)).

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

`keyPath` must not have any group or other permission bit set. Use
`chmod 600` (owner read/write only) before pointing `keyPath` at it.

TLS (or its absence) never changes the server's read/write timeout
behaviour: haybale sets `ReadHeaderTimeout: 10s` (bounding only how long
the server waits to read a request's headers) and deliberately no
read/write/idle timeout at all, with or without TLS — pack transfers can
run to gigabytes and take arbitrarily long. See the [security
model](security.md#tls) for when plain HTTP is acceptable.

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

`drainTimeout` bounds step 2 only. The default, `0s`, means **wait
indefinitely**: `Shutdown` blocks until every in-flight request finishes
on its own, however long that takes — matching haybale's own
no-read/write/idle-timeout design (pack transfers can run to gigabytes
and take arbitrarily long, so a finite default here would silently
reintroduce exactly the cap that design otherwise avoids).

Set `drainTimeout` to a finite duration (e.g. `2m`) to instead give
shutdown a deliberate backstop against a connection that never completes
on its own. Doing so accepts a real tradeoff: a legitimate transfer
slower than that bound is cut off too. If the bound is reached before
every in-flight request finished, haybale treats this as an intentional,
operator-configured cutoff, not a crash — it logs a clear warning
(`drainTimeout exceeded before every in-flight request finished...`) and
exits through a distinct path (exit code `3`, no `Error:` prefix)
immediately, rather than force-closing connections itself or exiting
exactly like a startup/runtime failure would (exit code `1`).

## Telemetry

```yaml
telemetry:
  endpoint: "otel-collector:4317"   # required to enable; empty disables telemetry
  protocol: grpc                     # optional, default shown: grpc|http/protobuf
  environment: prod                  # optional, sets deployment.environment
  serviceNamespace: haybale          # optional, sets service.namespace
  headersEnv: OTEL_EXPORTER_OTLP_HEADERS  # optional, env var naming OTLP headers
```

The `telemetry` block turns on OpenTelemetry export of traces, metrics, and
logs to an OTLP collector. It is entirely optional: **leaving it out (or
leaving `endpoint` empty) disables telemetry**: metric instruments become
no-ops, no OTLP connection is dialled, and per-request logging stays
stderr-only. What the enabled
pipeline emits is described in [`observability.md`](observability.md).

| Field              | Default   | Notes                                                                                   |
|--------------------|-----------|-----------------------------------------------------------------------------------------|
| `endpoint`         | (unset)   | OTLP collector endpoint. Empty disables telemetry. See the endpoint forms below.        |
| `protocol`         | `grpc`    | OTLP wire protocol: `grpc` or `http/protobuf`. Any other value fails startup.           |
| `environment`      | `local`   | `deployment.environment` resource label. Falls back to `OTEL_DEPLOYMENT_ENVIRONMENT`.   |
| `serviceNamespace` | `haybale` | `service.namespace` resource label. Falls back to `OTEL_SERVICE_NAMESPACE`.             |
| `headersEnv`       | (unset)   | Name of an env var holding OTLP request headers (see "Authenticating to the collector").|

`endpoint` forms, matching the two protocols:

- **grpc** — a bare `host:port` (e.g. `otel-collector:4317`) dialled without
  TLS (the local-collector default), or an explicit `https://host:port` URL
  to keep TLS on. A plain `http://` URL is also dialled without TLS.
- **http/protobuf** — a base URL ending in the collector's OTLP prefix (e.g.
  `https://otlp.example.com/otlp`); haybale appends the per-signal
  `/v1/traces`, `/v1/metrics`, `/v1/logs` segments itself. TLS is on for an
  `https://` URL and off for a plain `http://` or scheme-less one.

`environment` and `serviceNamespace` are bounded to a short, safe character
set (`[A-Za-z0-9._-]`, up to 64 chars); a value outside it — or a hostile
`OTEL_*` env-var value — falls back to the default rather than reaching an
exported batch verbatim.

### Authenticating to the collector

A managed collector usually needs an `Authorization` bearer token. As with
a credential's `tokenEnv`, that secret is **never written inline in the
config file** — set `headersEnv` to the name of an environment variable
holding an `OTEL_EXPORTER_OTLP_HEADERS`-style value (a comma-separated
`key=value` list), and haybale reads and forwards it to every OTLP exporter:

```yaml
telemetry:
  endpoint: "https://otlp.example.com/otlp"
  protocol: http/protobuf
  headersEnv: HAYBALE_OTLP_HEADERS
```

```sh
export HAYBALE_OTLP_HEADERS="authorization=Bearer <token>,x-tenant=acme"
```

The value is read from the environment at startup; it is never logged, and
haybale's log scrubber would redact it even if a bug tried to.

### Shutdown

On `SIGTERM`/`SIGINT`, the telemetry pipelines are flushed and shut down
*after* in-flight requests have drained (see "Graceful drain"), so the final
spans, metrics, and logs of a run reach the collector. This flush is bounded
by a short, fixed backstop (5s) so a collector that has gone away can never
hold process exit open — unlike the data path, which deliberately sets no
transfer timeout.

## Identity

haybale authenticates a caller by verifying a **JSON Web Token (JWT)**
the control plane issued to it, against the issuer's public keys. haybale
mints no identity tokens and holds no identity signing key — it is a pure
verifier trusting one or more issuers' JWKS. See the [JWT identity
contract](jwt-identity.md) for issuer requirements and the [GitHub Actions
OIDC recipe](github-actions.md) for that integration.

```yaml
identity:
  type: jwt
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      algorithms: [RS256]                 # default [RS256, ES256]
      audiences: [https://haybale.internal]
      leeway: 60s                          # default 60s
      typ: ""                              # optional required JOSE typ
      claimBindings:                       # ALL must match; exact or glob
        repository_owner: rxbynerd
        runner_environment: github-hosted
      identityTemplate: "gha:{repository}"
    - issuer: https://control-plane.example.internal
      jwksFile: /etc/haybale/control-plane-jwks.json
      algorithms: [ES256]
      audiences: [https://haybale.internal]
      typ: at+jwt
      identityTemplate: "{sub}"            # sub = run-<RunID>
      repoScopeClaim: haybale.dev/repos    # optional per-token narrowing
```

`jwt` is the only supported `type`. `issuers` lists every trusted issuer;
each is validated independently and a token is only ever checked against
the issuer its `iss` claim names.

Per-issuer fields:

| Field              | Default        | Meaning |
|--------------------|----------------|---------|
| `issuer`           | (required)     | The exact string a token's `iss` must equal. Also selects the issuer's trust material. Unique across issuers. |
| `jwksURL`          | —              | `https` URL haybale fetches this issuer's public keys from, refreshed in the background. Exactly one of `jwksURL`/`jwksFile`. `http` is permitted only for a loopback host (testing). |
| `jwksFile`         | —              | A static JWKS document on disk, read once at startup — the airgapped/e2e alternative to `jwksURL`. |
| `algorithms`       | `[RS256,ES256]`| Signing-algorithm allowlist. **Asymmetric only** — every HMAC variant and `none` are rejected outright (accepting one is the algorithm-confusion attack this allowlist prevents). |
| `audiences`        | (required)     | Acceptable `aud` values; a token must carry at least one. An issuer with no audience would admit tokens minted for another relying party. |
| `leeway`           | `60s`          | Clock-skew tolerance for `exp`/`nbf`/`iat`. |
| `typ`              | (unset)        | If set, the JOSE `typ` header the token must carry (compared case-insensitively, e.g. `at+jwt`). |
| `claimBindings`    | (none)         | Map of claim → required value(s) (exact or `path.Match` glob). **Every** binding must match or authentication fails. |
| `identityTemplate` | (required)     | Renders the authenticated identity's ID from verified claims, e.g. `gha:{repository}` or `{sub}`. Referenced claims must be present and string-typed. |
| `repoScopeClaim`   | (unset)        | Names a claim carrying repo-scope globs that **narrow** authorization (see "Policy" and `repoScopeClaim` below). |

A request authenticates by presenting its JWT as either the HTTP Basic
password (the username is ignored — this is what `git` itself sends) or an
`Authorization: Bearer <token>` header.

### What haybale checks, per RFC 8725

For every token, against **only** the selected issuer's trust material:

- The `alg` header is in the issuer's allowlist (asymmetric only) — checked
  before the signature, so `none` and HMAC confusion never reach a key.
- The signature verifies against the JWKS key named by the `kid` header.
- `exp` is present and unexpired (mandatory), `nbf`/`iat` are honored, all
  within `leeway`.
- `aud` carries at least one configured audience.
- `iss` equals the issuer whose keys just verified it.
- `typ` matches, if the issuer requires one.
- Every `claimBinding` matches, and every claim `identityTemplate`
  references is present and string-typed.

Any failure yields a `401` with no detail about *why* — the reason is
logged server-side only, never returned to the caller.

### `claimBindings` — why they are not optional in practice

An open issuer like GitHub Actions will mint a validly-signed token, with
your audience, for **any** workflow on github.com. The signature proves
only that GitHub issued it, not that *you* trust the repo it came from.
`claimBindings` are what pin an issuer to the callers you intend — e.g.
`repository_owner: rxbynerd` and `runner_environment: github-hosted`.
Never configure the public GitHub Actions issuer without them. See [Claim
bindings](security.md#claim-bindings).

### `repoScopeClaim` — per-token narrowing

If an issuer sets `repoScopeClaim`, a token may carry a claim listing
`{host}/{owner}/{repo}` globs. haybale **intersects** that list with the
YAML policy: a repo the policy would allow is still denied if it falls
outside the token's scope (`effective = policy ∩ scope`). A token can only
ever narrow its access this way, never widen it — the policy remains the
ceiling. An absent claim leaves policy to decide alone; an explicit empty
list denies every repo.

### JWKS refresh and failure behavior

A `jwksURL` is fetched once at startup (fail-fast — an unreachable or
empty JWKS refuses to start) and then refreshed in the background,
honoring the endpoint's `Cache-Control` and refetching on an unseen `kid`
(rate-limited). If refresh later **starts failing**, haybale keeps serving
the last successfully fetched key set and logs each failure at `warn`
(`jwks background refresh failed`) — availability over strict freshness.

There is no maximum stale-key duration and no OIDC discovery self-check. Alert
on `jwks background refresh failed` and see [JWKS
handling](security.md#jwks-handling) for the resulting trust tradeoff.

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
  - identities: ["run-readonly-*"]
    repos: ["github.com/acme/public-docs"]
    permissions: [read]
  - identities: ["run-writer-*"]
    repos: ["github.com/acme/*"]
    permissions: [read, write]
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
genuinely nonexistent repo would produce. See [Authorization and repository
privacy](security.md#authorization-and-repository-privacy).

Use `haybale policy check` to dry-run a decision without making a real
request:

```console
haybale policy check --config haybale.yaml \
  --id run-9f2c1a --repo github.com/acme/widgets --verb read
```

This loads and validates the full `--config` the same way `haybale serve` does,
then prints `ALLOW`/`DENY`, the matched rule (or `none (default deny)`), and the
reason. Upstream secret environment variables and private-key files must
therefore be available for validation. The command does not fetch JWKS data,
contact an upstream, or mint a credential.

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
them. `baseURL` must be an absolute URL with a scheme and a host, and must not
contain credentials (userinfo such as `https://user:token@host`); configure a
`credential` block instead.

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
  username presented upstream. Many token-based git hosts — GitHub.com
  in particular — ignore the Basic-auth username and check only the
  password, so the default works well for authenticating with just a
  token there. `git-http-backend` itself performs no HTTP authentication
  at all; whether an internal `git-http-backend` deployment ignores the
  username depends on the authentication service in front of it.
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
  isn't a valid RSA key fails startup immediately. The file must not be
  have any group or other permission bit set: use `chmod 600` before
  pointing `privateKeyPath` at it.
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

## Cache

```yaml
cache:
  enabled: false                   # optional, default shown
  dir: /var/cache/haybale/data     # required when enabled; created if missing, its parent must exist
  keyEnv: HAYBALE_CACHE_KEY        # optional, env var holding the cache key
  maxDiskSize: 10GiB               # optional, default shown
  maxEntrySize: 1GiB               # optional, default shown
  maxConcurrentFills: 4            # optional, default shown
  maxRequestBody: 1MiB             # optional, default shown
  retention: 24h                   # optional, default shown
  refsMaxAge: 0s                   # optional, default shown
  accessRecheck: 5m                # optional, default shown
  responseHeaderTimeout: 60s       # optional, default shown
  idleTimeout: 2m                  # optional, default shown
  exposeStatus: false              # optional, default shown
  staleIfErrorFor: 0s              # optional, default shown; 0s disables stale-if-error
```

The `cache` block turns on a response cache for Git smart HTTP reads
(clones and fetches). It serves the pack transfer of repeated identical clones
and fetches from local disk, so the upstream is not asked for it again. Ref
lookups still reach the upstream unless `refsMaxAge` is set. **The cache is off
by default**: leaving the block out, or leaving `enabled` false, serves every
request straight from the upstream. A disabled block is inert: it is not
defaulted or validated, although an unknown key in it is still rejected, and a
value of the wrong type, such as a malformed size, still fails when the file is
decoded. Writes
(pushes) are never served from the cache. The [caching guide](caching.md)
explains what the cache stores and how to operate it;
[`observability.md`](observability.md) describes what it emits.

Unlike the rest of the file, the `cache` block is decoded strictly: an unknown
key fails startup with `cache: unknown field ...`, so a mistyped or renamed
field can never silently fall back to its default. Aliases are followed, so a
typo inside an aliased block is also rejected. A YAML merge key (`<<`) inside
the block is rejected as an unknown field.

| Field                   | Default  | Notes                                                                                                   |
|-------------------------|----------|---------------------------------------------------------------------------------------------------------|
| `enabled`               | `false`  | Turns the cache on.                                                                                     |
| `dir`                   | (unset)  | Directory holding cached entries. Required when `enabled`. See "Cache directory" below.                 |
| `keyEnv`                | (unset)  | Name of an env var holding the 32-byte, base64-encoded key entries are sealed under. See "Cache key".    |
| `maxDiskSize`           | `10GiB`  | Disk budget for the cache: stored entries plus space reserved for fills in progress. Least recently used entries are evicted past it. An explicit `0` selects the default. Negative and malformed values fail startup. See "Sizing". |
| `maxEntrySize`          | `1GiB`   | Largest response that is stored. A larger response is delivered to the clients waiting on it without being stored. Must not exceed half of `maxDiskSize`, because a fill reserves its sealed size before it starts. An explicit `0` selects the default. Negative and malformed values fail startup. |
| `maxConcurrentFills`    | `4`      | Maximum number of pack responses being fetched into the cache at once. A request that finds no free slot is proxied without the cache. An explicit `0` selects the default. Negative and malformed values fail startup. Ref advertisements and `ls-refs` responses do not count: they have a fixed separate cap of 64 concurrent fills and reserve 1 MiB each. |
| `maxRequestBody`        | `1MiB`   | Largest decoded request body the cache will inspect. A read with a larger body bypasses the cache. An explicit `0` selects the default. Negative and malformed values fail startup. |
| `retention`             | `24h`    | Go duration string: the maximum age of any entry, after which it is not served. Must be greater than zero. See "Retention". |
| `refsMaxAge`            | `0s`     | Go duration string: how long a stored ref advertisement is reused without asking the upstream. `0s` always revalidates. When both are non-zero it must be less than `accessRecheck`. With a remote tier, refs entries are uploaded to the bucket only when it or `staleIfErrorFor` is greater than `0s`. |
| `accessRecheck`         | `5m`     | Go duration string: how long a cached pack is served after the last successful upstream refs response before the upstream is asked again. `0s` disables the check. See "Validation" for its relation to `refsMaxAge`. |
| `responseHeaderTimeout` | `60s`    | Go duration string bounding how long haybale waits for the upstream's response headers on a cache fill. `0s` applies no bound. Does not affect requests that bypass the cache. |
| `idleTimeout`           | `2m`     | Go duration string bounding the gap between body bytes from the upstream during a cache fill. `0s` leaves the gap unbounded. Does not affect requests that bypass the cache. |
| `exposeStatus`          | `false`  | Emits a `Cache-Status` response header describing how the cache handled the request. See [Cache-Status](security.md#cache-status-disclosure). |
| `remote`                | (unset)  | Optional remote tier that replicas share, in an S3-compatible bucket. Requires `keyEnv`. See "Remote tier". |
| `staleIfErrorFor`       | `0s`     | Go duration string: the maximum age of an entry served when the upstream cannot answer a read (stale-if-error). `0s` or empty disables it. Must not exceed `retention`. **Serves possibly outdated content; read "Stale-if-error" before setting it.** |

### Sizes and durations

Sizes (`maxDiskSize`, `maxEntrySize`, `maxRequestBody`) are written as a
number followed by an IEC unit: `KiB`, `MiB`, `GiB` or `TiB`, for example
`512MiB` or `1.5GiB`. Units are case-sensitive, one space before the unit is
allowed, and the number may be an integer or a decimal that works out to a
whole number of bytes. The one exception is a bare `0`, which means zero bytes
and so selects the default. Any other bare integer (`1073741824`), an SI unit
(`KB`, `MB`, `GB`), a negative value, or anything else fails startup, so a size
can never be misread by a factor of 1024.

Durations (`retention`, `refsMaxAge`, `accessRecheck`,
`responseHeaderTimeout`, `idleTimeout`, `staleIfErrorFor`) are Go duration
strings such as `30s` or `24h` and must not be negative.

### Validation

Validation of the `cache` block is structural: it checks that no key is
unknown, the syntax of every size and duration, that `dir` is set, that
`retention` is greater than zero, that `maxEntrySize` does not exceed half of
`maxDiskSize`, that `refsMaxAge` is less than `accessRecheck` when both are
non-zero, that `staleIfErrorFor` does not exceed `retention`, and, when `remote`
is set, the remote fields and that `keyEnv` is set (see "Remote tier"). An
explicit `0` for `maxDiskSize`, `maxEntrySize`, `maxConcurrentFills` or
`maxRequestBody` is replaced by the default before validation. Negative and malformed values fail startup.

A `maxEntrySize` above half of `maxDiskSize` fails with `cache: maxEntrySize
<size> must not exceed half of maxDiskSize <size>`, because a fill reserves its
sealed size before it starts. The `refsMaxAge` rule exists because a refs
response served from the cache does not renew the upstream access check that
cached packs depend on; with `refsMaxAge` at or above `accessRecheck`, packs
would stop being served while refs were still cached. A `staleIfErrorFor` above
`retention` fails with `cache: staleIfErrorFor "<value>" must not exceed
retention "<value>"`, because no entry is kept longer than `retention`.

Validation does not touch the filesystem, the network or the environment, so
`haybale policy check` stays offline when a cache block is present, with or
without the cache key, directory or bucket. The directory, the key and the
bucket are checked when `haybale serve` starts.

### Cache directory

`dir` holds repository contents. The final path element is created with mode
`0700` when it is missing, but its parent must exist. An existing directory must
be owned by the haybale process user (where the platform reports ownership) and
have no group or other permission bits; `haybale serve` refuses to start
otherwise. Mount the volume only into the haybale container; any sidecar
sharing it runs with the same UID and can read every entry.

Each `haybale serve` process needs its own cache directory. At startup the
process deletes the temporary files of other processes in the directory, so
replicas must not share a volume, whether the volume is a network filesystem or
a `ReadWriteMany` claim.

On Kubernetes, back `dir` with an `emptyDir` volume whose `sizeLimit` is above
`maxDiskSize`, so a full cache can never evict unrelated pods from the node. An
`emptyDir` is wiped when the pod is rescheduled, which is acceptable because
the cache holds nothing that cannot be fetched again. A freshly mounted
`emptyDir` is owned by root with open permissions, which fails the ownership
and mode check, so mount it at a parent such as `/var/cache/haybale` and set
`dir` to a subdirectory of it such as `/var/cache/haybale/data`, which haybale
creates itself; the [caching guide](caching.md#kubernetes) has a complete
example.

### Sizing

`maxDiskSize` is a budget shared by stored entries and by fills in progress. A
fill is one fetch, from the upstream or from the remote tier, whose response is
being written to the cache. It reserves its sealed size before it starts. A
fill from the remote tier reserves the object's size. A fill from the upstream
reserves the upstream's `Content-Length` when the upstream sends one, and
`maxEntrySize` otherwise, which is the usual case for a pack, plus a small
allowance for the sealing overhead. Ref advertisement and `ls-refs` fills are
reserved separately: up to 64 at a time, 1MiB each. `maxConcurrentFills` times
`maxEntrySize`, plus 64MiB for the refs fills, is therefore the space that
concurrent fills can hold at once, and `maxDiskSize` should exceed it by the
space wanted for stored entries. `maxEntrySize` must not exceed half of
`maxDiskSize`. With the defaults, fills reserve at most 4GiB plus 64MiB of the
10GiB budget. For a fleet that clones repositories well below the default
`maxEntrySize`, lowering `maxEntrySize` to a small multiple of the largest
repository reduces the reservation further.

A fill that cannot reserve space after evicting stored entries is proxied
without the cache and is not stored. A response larger than `maxEntrySize` is
delivered to the clients waiting on it but never stored. A response of unknown
length that is larger than `maxEntrySize` and larger than the free disk closes
those clients' connections once, and the key then goes to the upstream for
`retention`. The [caching guide](caching.md#sizing-and-volumes) has the formula
and the effects on clients.

### Cache key

Entries are encrypted and authenticated under a key read from the environment
variable named by `keyEnv` (32 random bytes, base64-encoded). As with a
credential's `tokenEnv`, the key is never written inline in the config file.
Protect it like a credential; the [security model](security.md#sealed-entries)
describes what it protects.

`keyEnv` is optional for a cache without a remote tier, and required with
`remote`, because replicas must seal and address entries under the same key.
When it is left empty, haybale generates a key at startup and discards it on
exit. At the next start it deletes every entry in the directory, because none
can be read, so the cache is empty after every restart. `haybale cache purge`
cannot address entries sealed under an ephemeral key. Set `keyEnv` to keep the
cache across restarts and to use the purge command.

Rotating the key is a cold cache. At the next start haybale deletes the entries
sealed under the previous key. The [caching guide](caching.md#purging-a-repository)
describes how to purge a repository before then.

### Retention

`retention` is the maximum age of any entry. Content removed upstream, for
example after a history rewrite that deleted a secret, can still be served until
its entry reaches `retention`. Lower `retention` to shorten that window, or
purge the repository: see the [caching guide](caching.md#purging-a-repository)
for the procedure. The [security model](security.md#retention-and-purging)
states what retention and purging do and do not guarantee, and
[Access recheck](security.md#access-recheck) states how revoked upstream access
becomes visible.

### Remote tier

```yaml
cache:
  enabled: true
  dir: /var/cache/haybale/data
  keyEnv: HAYBALE_CACHE_KEY        # required with remote
  remote:
    type: s3                       # required; the only type
    bucket: haybale-cache          # required
    prefix: prod/                  # optional; empty, or ending with "/"
    region: us-east-1              # required
    endpoint: ""                   # optional; https, or http for a loopback host
    forcePathStyle: false          # optional, default shown
    headerTimeout: 10s             # optional, default shown
    sse: ""                        # optional: AES256 or aws:kms
    kmsKeyID: ""                   # optional; only with sse: aws:kms
```

`remote` adds a second tier that every replica shares: a prefix of an
S3-compatible bucket. An entry stored on one replica's disk is uploaded to the
bucket, and a replica that misses on its own disk reads the entry from the
bucket before it asks the upstream. The [caching guide](caching.md#remote-tier)
explains how the two tiers interact and which stores work.

| Field            | Default | Notes |
|------------------|---------|-------|
| `type`           | (unset) | Required. `s3` is the only type. |
| `bucket`         | (unset) | Required. |
| `prefix`         | (unset) | Prepended to every object key. Empty, or ending with `/`. Replicas that share a prefix share entries, so one prefix is one trust domain. The trailing slash keeps one prefix from also matching another in IAM conditions and lifecycle filters (`prod` would match `prod-eu/`). An empty prefix stores entries at the bucket root: the whole bucket is then one trust domain, and a lifecycle rule without a prefix filter covers every object in it. |
| `region`         | (unset) | Required. The signing region, and the region of the AWS endpoint when `endpoint` is empty. It is never read from `AWS_REGION` or the shared AWS configuration. |
| `endpoint`       | (unset) | Service base URL. Must be `https`; `http` is accepted only for a loopback host. It must not carry credentials, a query or a fragment. Empty selects `https://s3.<region>.amazonaws.com`. |
| `forcePathStyle` | `false` | Addresses the bucket in the URL path (`https://<endpoint>/<bucket>/<key>`) instead of the host name. Most self-hosted stores need it. |
| `headerTimeout`  | `10s`   | Go duration string bounding each remote request except an upload: the response of an existence check, a deletion and each listing page, the response headers of a read, and then the read of a remote entry's 4KiB sealed header before a fill falls through to the upstream. It is also the single deadline for deleting a repository's remote refs entries after a push. The rest of a read's body falls under `idleTimeout`. `0s` removes the per-request bound: the sealed-header read is then bounded by `idleTimeout`, and the deletions after a push, after a failed verification and after a refs upload that a push superseded are bounded at one minute. |
| `sse`            | (unset) | Server-side encryption requested on upload: `AES256` or `aws:kms`. Optional, because entries are already sealed. |
| `kmsKeyID`       | (unset) | KMS key for `sse: aws:kms`; rejected with any other `sse`. Empty uses the bucket's default KMS key. |

Validation requires `keyEnv` whenever `remote` is set: under an ephemeral key no
replica could read another's entries. Like the rest of the block, validation is
structural and offline, and `haybale policy check` applies the same rules as
`haybale serve`. Validation refuses a remote block with one of these errors:

- `cache.remote: type is required (want "s3")`, or `cache.remote: type "..." is
  not supported (want "s3")`;
- `cache.remote: bucket is required`;
- `cache.remote: prefix "..." must end with "/"`;
- `cache.remote: region is required; it is never taken from AWS_REGION`, and,
  when `endpoint` is empty, `cache.remote: region "..." is not a valid AWS
  region name`;
- an endpoint error such as `cache.remote: endpoint "..." must use https (http
  is permitted only for a loopback host)`. An endpoint that carries userinfo,
  a query or a fragment, any of which can hold a secret, is refused with
  `cache.remote: endpoint "scheme://host" must not carry userinfo` (or `a
  query`, or `a fragment`), which shows only the scheme and host and never the
  rest of the URL;
- an `sse`, `kmsKeyID` or `headerTimeout` error naming the field; and
- `cache: keyEnv is required when cache.remote is set, so that every replica
  seals and addresses entries under the same key`.

When `haybale serve` or `haybale cache purge --remote` builds the S3 client, it
refuses three environments with a fixed message that carries no SDK text:

- `AWS_CA_BUNDLE` set to a non-empty value: `cache.remote: s3store:
  AWS_CA_BUNDLE is set, but the remote tier trusts only the system certificate
  store; unset AWS_CA_BUNDLE and add the CA certificate to the system trust
  store`;
- a `ca_bundle` key in the selected shared AWS profile: `cache.remote: s3store:
  the selected AWS profile sets ca_bundle, but the remote tier trusts only the
  system certificate store; remove ca_bundle from the profile and add the CA
  certificate to the system trust store`; and
- an `AWS_PROFILE` naming a profile the shared configuration files do not hold:
  `cache.remote: s3store: AWS_PROFILE names a profile that does not exist in the
  shared AWS configuration files`.

The purge command prints these messages after `Error: --remote: `, for example
`Error: --remote: cache.remote: s3store: AWS_PROFILE names a profile that does
not exist in the shared AWS configuration files`.

**Startup probe.** When `haybale serve` starts, it reads a random key under
`v1/.probe/` in the prefix (`v1/.probe/` followed by 32 hex characters, new at
every start), within 30 seconds. haybale never writes such an object, so a "not
found" answer (`NoSuchKey`, or a 404 `NotFound` without a body) means the
bucket is usable, and a bucket writer cannot plant the key in advance. The
probe makes one attempt, and its result decides whether startup continues.

Startup fails when:

- the SDK's default credential chain finds no provider, or a provider refuses
  (for example instance metadata answering 404, or web identity answering 400
  or 403), with `cache.remote: no AWS credentials were found in the SDK's
  default chain; configure IRSA, EKS Pod Identity, AWS_ACCESS_KEY_ID and
  AWS_SECRET_ACCESS_KEY, or a shared profile: s3store: get v1/.probe/<random>:
  NoCredentials`;
- the probe reads its random key successfully, with `cache.remote: the startup
  probe read a random key under v1/.probe/, which haybale never writes, so the
  endpoint is not behaving as S3-compatible storage`; or
- the store's certificate does not verify (`TLSVerificationFailed`), or the
  store answers with any 3xx or 4xx status other than a not-found 404, 307,
  308, 408 and 429. That covers `PermanentRedirect` (HTTP 301, a bucket in
  another region), `AccessDenied`, `InvalidAccessKeyId`,
  `SignatureDoesNotMatch`, `NoSuchBucket`, `AuthorizationHeaderMalformed`,
  `ExpiredToken`, `InvalidToken`, `InvalidBucketName` and plain 401 and 403
  responses.

These fail with `cache.remote: the bucket cannot be used with these credentials
and settings: s3store: get v1/.probe/<random>: <code> (HTTP <status>)`. The
status part is left out when no response arrived, as for a certificate
failure. On a general-purpose bucket, S3 answers a missing key with 403
`AccessDenied` instead of 404 when the identity lacks `s3:ListBucket`, so such
an identity fails the probe.

`haybale serve` exits with status 1 and prints each of these refusals, and the
three environment refusals above, on stderr after `Error: build cache: `:

```text
Error: build cache: cache.remote: the bucket cannot be used with these credentials and settings: s3store: get v1/.probe/<random>: AccessDenied (HTTP 403)
```

Startup continues, with a warning `cache.remote: the startup probe of the
bucket failed; continuing, and remote operations retry on use`, when the probe
fails in a way that can resolve itself:

- a timeout (`HeaderTimeout`, or `DeadlineExceeded`), or cancellation
  (`Canceled`);
- a request that could not be sent, such as a dial error (`RequestSendFailed`),
  any other failure without a service error code (`RequestFailed`), or a
  response the store cannot use (`InvalidResponse`);
- a 5xx response, such as `SlowDown`, or a 307, 308, 408 or 429 response; or
- a credential provider that failed in a way that can pass: a network timeout,
  a request that could not be sent, or a provider answering 5xx or 429, such
  as STS answering 503 to a web-identity exchange (`CredentialsUnavailable`). A
  deadline inside the credential chain, such as an instance metadata endpoint
  that does not answer, reports `DeadlineExceeded`.

Network failures carry no HTTP status. A bucket outage therefore cannot stop
haybale from starting. When the credentials could not be resolved at startup,
the first remote-tier operations fail as well, until the credentials resolve.
The probe cannot detect an endpoint that answers every request with 404
`NoSuchKey`: such an endpoint passes, and every remote read is then a miss.

The `response cache remote tier enabled` line at Info confirms the tier, with
`type`, `bucket`, `prefix`, `region` and `endpoint`.

**Endpoint.** haybale always sets the endpoint itself, so `AWS_ENDPOINT_URL`,
`AWS_ENDPOINT_URL_S3` and `endpoint_url` in the shared AWS configuration are
ignored. When `endpoint` is empty, haybale uses
`https://s3.<region>.amazonaws.com`, so leave it empty only for an AWS S3
general-purpose bucket reached through that standard regional endpoint. Set it
for:

- an S3 Express One Zone directory bucket: its zonal endpoint,
  `https://s3express-<zone id>.<region>.amazonaws.com`;
- the China partitions: `https://s3.<region>.amazonaws.com.cn`;
- FIPS, dual-stack, VPC (PrivateLink) and ISO-partition endpoints, which the
  default cannot express; and
- any other store: Cloudflare R2, Ceph RGW or the Google Cloud Storage
  interoperability endpoint.

A directory bucket needs `forcePathStyle: false`, because directory buckets do
not support path-style requests. A directory bucket applies its default
encryption and the request cannot override it, so leave `sse` empty and set the
bucket default. A KMS default must be a customer managed key given by key ID or
ARN, not an alias. The `aws/s3` key is unsupported.

The S3 client uses its own HTTP transport and trusts only the system
certificate store, so a store whose certificate is issued by a private
authority needs that authority in the system trust store; `AWS_CA_BUNDLE` and
a profile `ca_bundle` stop startup, as above. Proxy environment variables are
not used for the bucket either.

Cloudflare R2, Ceph RGW and the Google Cloud Storage interoperability endpoint
are untested in this release. The settings in the [caching
guide](caching.md#supported-stores) are expected to work, but have not been
verified against those stores.

**Credentials.** Credentials come from the AWS SDK's default chain: the
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables, the
shared credentials and configuration files, web identity (IRSA), the EKS Pod
Identity agent, the ECS container endpoint, and EC2 instance metadata. On
Kubernetes, prefer workload identity (IRSA or Pod Identity) to static keys, and
on EC2 nodes require IMDSv2 with a hop limit of 1, so pods cannot use the node's
instance role.

The server's identity and the identity that runs `haybale cache purge
--remote` both need `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject` on
`<bucket>/<prefix>*`, and `s3:ListBucket` on the bucket for the prefix. The
purge command writes the purge marker, so it needs `s3:PutObject` as well as
the read, list and delete permissions. Add `kms:GenerateDataKey` and
`kms:Decrypt` on the key when `sse` is `aws:kms`. For a bucket
`haybale-cache` and the prefix `prod/`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::haybale-cache/prod/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::haybale-cache",
      "Condition": { "StringLike": { "s3:prefix": "prod/*" } }
    }
  ]
}
```

An S3 Express One Zone directory bucket authorises object requests through
sessions, so the identity needs `s3express:CreateSession` on the bucket
instead. A lifecycle rule on a directory bucket also needs the bucket policy
to allow the S3 lifecycle service principal, `lifecycle.s3.amazonaws.com`,
`s3express:CreateSession` in `ReadWrite` session mode.

**Bucket.** Keep the bucket private. Add a lifecycle rule that expires objects
under the prefix after `retention` plus a margin, for example two days for the
default `24h`. haybale judges an entry's age from the time sealed into it, so
the rule is only garbage collection. Lifecycle expiry is day-granular on AWS
S3; the granularity of other stores is not verified. Server-side encryption is
optional defence in depth: the entries are already encrypted and authenticated
under the cache key.

### Stale-if-error

`staleIfErrorFor` lets haybale answer a read from a stored entry up to that old
when the upstream cannot answer it: the connection to the upstream fails, the
credential source cannot reach its API, no response headers arrive within
`responseHeaderTimeout`, or the upstream answers `500`, `502`, `503` or `504`.
It is off by default.

**The risk.** A client served stale receives the repository as it was when the
entry was stored, with nothing in git's output to say so. That clone can lack a
security fix pushed since, and can still contain a reverted commit or a secret
that a history rewrite removed. It also lets haybale keep serving a repository
for up to `staleIfErrorFor` after its own upstream access was revoked, while
the upstream is failing. Choose the shortest value that covers the outages the
workloads must ride out, and run `haybale cache purge` after any history
rewrite. The [security model](security.md#stale-if-error) states exactly what
can and cannot trigger stale service, and the [caching
guide](caching.md#serving-through-an-upstream-outage) describes what an outage
clone can do and the health gate that keeps requests from waiting out a
connection timeout.

Every stale response is logged as a `cache_stale_served` security event, and
the `response cache enabled` startup line reports the configured
`staleIfErrorFor`.

## Worked example

A complete, minimal `haybale.yaml`:

```yaml
listen: ":8466"
logLevel: info
tls:
  certPath: /etc/haybale/tls/tls.crt
  keyPath: /etc/haybale/tls/tls.key
drainTimeout: 2m   # optional; omit entirely to wait indefinitely instead (the default)

identity:
  type: jwt
  issuers:
    - issuer: https://token.actions.githubusercontent.com
      jwksURL: https://token.actions.githubusercontent.com/.well-known/jwks
      algorithms: [RS256]
      audiences: [https://haybale.internal]
      claimBindings:
        repository_owner: rxbynerd
        runner_environment: github-hosted
      identityTemplate: "gha:{repository}"

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
# /etc/haybale/policy.yaml
rules:
  - identities: ["gha:rxbynerd/*"]
    repos: ["github.com/rxbynerd/*"]
    permissions: [read, write]
```
