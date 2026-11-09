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
  dir: /var/cache/haybale          # required when enabled
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
```

The `cache` block turns on a response cache for Git smart HTTP reads
(clones and fetches), so repeated identical reads are served from local disk
instead of contacting the upstream. **The cache is off by default**: leaving
the block out, or leaving `enabled` false, serves every request straight from
the upstream, and a disabled block is inert (it is neither defaulted nor
checked beyond its syntax). Writes (pushes) are never served from the cache.
The [caching guide](caching.md) explains what the cache stores and how to
operate it; [`observability.md`](observability.md) describes what it emits.

Unlike the rest of the file, the `cache` block is decoded strictly: an unknown
key fails startup with `cache: unknown field ...`, so a mistyped or renamed
field can never silently fall back to its default.

| Field                   | Default  | Notes                                                                                                   |
|-------------------------|----------|---------------------------------------------------------------------------------------------------------|
| `enabled`               | `false`  | Turns the cache on.                                                                                     |
| `dir`                   | (unset)  | Directory holding cached entries. Required when `enabled`. See "Cache directory" below.                 |
| `keyEnv`                | (unset)  | Name of an env var holding the 32-byte, base64-encoded key entries are sealed under. See "Cache key".    |
| `maxDiskSize`           | `10GiB`  | Disk budget for the cache: stored entries plus space reserved for fills in progress. Least recently used entries are evicted past it. See "Sizing". |
| `maxEntrySize`          | `1GiB`   | Largest response that is stored. A larger response is streamed to the client without being stored. Must not exceed `maxDiskSize`. |
| `maxConcurrentFills`    | `4`      | Maximum number of pack responses being fetched into the cache at once. A request that finds no free slot is proxied without the cache. Must be at least `1`. Ref advertisements and `ls-refs` responses do not count: they have a fixed separate cap of 64 concurrent fills and reserve 1 MiB each. |
| `maxRequestBody`        | `1MiB`   | Largest decoded request body the cache will inspect. A read with a larger body bypasses the cache. Must be greater than zero. |
| `retention`             | `24h`    | Go duration string: the maximum age of any entry, after which it is not served. Must be greater than zero. See "Retention". |
| `refsMaxAge`            | `0s`     | Go duration string: how long a stored ref advertisement is reused without asking the upstream. `0s` always revalidates. When both are non-zero it must be less than `accessRecheck`. |
| `accessRecheck`         | `5m`     | Go duration string: how long a cached pack is served after the last successful upstream refs response before the upstream is asked again. `0s` disables the check. See "Validation" for its relation to `refsMaxAge`. |
| `responseHeaderTimeout` | `60s`    | Go duration string bounding how long haybale waits for the upstream's response headers on a cache fill. `0s` applies no bound. Does not affect requests that bypass the cache. |
| `idleTimeout`           | `2m`     | Go duration string bounding the gap between body bytes from the upstream during a cache fill. `0s` leaves the gap unbounded. Does not affect requests that bypass the cache. |
| `exposeStatus`          | `false`  | Emits a `Cache-Status` response header describing how the cache handled the request. See [Cache-Status](security.md#cache-status-disclosure). |
| `remote`                | (unset)  | Reserved for a later release; fails startup if set. See "Reserved fields".                               |
| `staleIfErrorFor`       | (unset)  | Reserved for a later release; fails startup unless empty or `0s`. See "Reserved fields".                 |

### Sizes and durations

Sizes (`maxDiskSize`, `maxEntrySize`, `maxRequestBody`) are written as a
number followed by an IEC unit: `KiB`, `MiB`, `GiB` or `TiB`, for example
`512MiB` or `1.5GiB`. Units are case-sensitive, one space before the unit is
allowed, and the number may be an integer or a decimal that works out to a
whole number of bytes. A bare integer (`1073741824`), an SI unit (`KB`, `MB`,
`GB`), a negative value, or anything else fails startup, so a size can never be
misread by a factor of 1024.

Durations (`retention`, `refsMaxAge`, `accessRecheck`,
`responseHeaderTimeout`, `idleTimeout`) are Go duration strings such as `30s`
or `24h` and must not be negative.

### Validation

Validation of the `cache` block is structural: it checks that no key is
unknown, the syntax of every size and duration, that `dir` is set, that
`retention` is greater than zero, that `maxEntrySize` does not exceed
`maxDiskSize`, that `maxConcurrentFills` is at least `1`, that
`maxRequestBody` is greater than zero, and that `refsMaxAge` is less than
`accessRecheck` when both are non-zero. The last rule exists because a refs
response served from the cache does not renew the upstream access check that
cached packs depend on; with `refsMaxAge` at or above `accessRecheck`, packs
would stop being served while refs were still cached. Validation does not touch the filesystem, the
network or the environment, so `haybale policy check` stays offline when a
cache block is present, with or without the cache key or directory. The
directory and key are checked when `haybale serve` starts.

### Cache directory

`dir` holds repository contents. The final path element is created with mode
`0700` when it is missing, but its parent must exist. An existing directory must
be owned by the haybale process user and be inaccessible to group and other
(mode `0700`); `haybale serve` refuses to start otherwise. Mount the volume only into the haybale container;
any sidecar sharing it runs with the same UID and can read every entry.

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

`maxDiskSize` is a budget shared by stored entries and by fills in progress.
A fill reserves space before it starts: the upstream's `Content-Length` when
the upstream sends one, and `maxEntrySize` otherwise, which is the usual case
for a pack. `maxConcurrentFills` times `maxEntrySize` is therefore the space
that concurrent fills can hold at once, and `maxDiskSize` should exceed it by
the space wanted for stored entries. With the defaults, fills reserve at most 4GiB of the
10GiB budget. For a fleet that clones repositories well below the default
`maxEntrySize`, lowering `maxEntrySize` to a small multiple of the largest
repository reduces the reservation further.

A fill that cannot reserve space after evicting stored entries is proxied
without the cache and is not stored. An entry larger than `maxEntrySize` is
streamed to the client but never stored.

### Cache key

Entries are encrypted and authenticated under a key read from the environment
variable named by `keyEnv` (32 random bytes, base64-encoded). As with a
credential's `tokenEnv`, the key is never written inline in the config file.
Protect it like a credential; the [security model](security.md#sealed-entries)
describes what it protects.

`keyEnv` is optional while only the local disk tier exists. When it is left
empty, haybale generates a key at startup and discards it on exit, so the cache
is empty again after every restart and `haybale cache purge` cannot address
its entries. Set `keyEnv` to keep the cache across restarts and to use the purge
command.

Rotating the key is a cold cache: entries sealed under the previous key are
never served again and are removed as they expire or are evicted.

### Retention

Cache entries are shared by every identity the policy allows to read a
repository; the policy, not the cache, decides who may read what. A cache hit
does not contact the upstream, so haybale's own access to a repository being
revoked becomes visible at the next `accessRecheck` boundary. Content removed
upstream, for example after a history rewrite that deleted a secret, can still
be served until its entry reaches `retention`; lower `retention` to shorten
that window, or run `haybale cache purge` (see the [caching
guide](caching.md#purging-a-repository)).

### Reserved fields

Two fields are reserved for later releases and **fail startup if set** in this
release:

- `remote`: an optional shared remote tier in object storage. Any non-empty
  value under `cache.remote` is rejected with `cache.remote is not supported in
  this release`. The planned fields are `type`, `bucket`, `prefix`, `region`,
  `endpoint`, `forcePathStyle`, `headerTimeout`, `sse` and `kmsKeyID`.
- `staleIfErrorFor`: serving an older entry when the upstream is unavailable.
  Only an empty value or `0s` is accepted; any other value is rejected with
  `cache.staleIfErrorFor is not supported in this release`.

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
