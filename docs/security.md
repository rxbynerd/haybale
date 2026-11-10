# Security model

This document describes haybale's trust boundaries, enforced security
properties, and operational limitations. Read it before exposing a haybale
listener or granting it upstream credentials.

## Trust boundaries

haybale sits between two independently authenticated connections:

1. a client presents a JWT to haybale; and
2. haybale presents a separate credential to an upstream Git host.

The client is not trusted with the upstream credential. The upstream is not
trusted with the client JWT. The operator is trusted to configure JWT issuers,
repository policy, upstream destinations, and secret delivery correctly.

haybale is designed to limit:

- use of a client token outside the repositories and verbs assigned to its
  identity;
- repository discovery through authorization responses;
- exposure of a GitHub App installation token or static upstream token to the
  client;
- exposure of the client's JWT to an upstream; and
- the blast radius of a minted GitHub App token.

haybale does **not** interpret pack content, read push bodies, enforce ref-level
push rules, support SSH or dumb HTTP, defend against a compromised upstream, or
correct an over-broad policy.

With the optional [response cache](#response-cache) enabled, haybale also reads
the body of each read request, bounded by `cache.maxRequestBody`, and scans the
pkt-line framing of cacheable responses. It never inspects pack data.

haybale does not provide connection rate limits or a concurrent-connection cap;
deploy an ingress or load balancer with those controls when untrusted clients
can reach the listener.

## Authentication

haybale is a JWT verifier. It holds no identity signing key. Each configured
issuer has independent trust material and verification rules.

Verification enforces:

- an operator-configured, asymmetric-only algorithm allowlist;
- signature verification against only the key set associated with the token's
  issuer;
- exact issuer matching and a required audience match;
- mandatory `exp`, plus `nbf` and `iat` validation with configured clock-skew
  leeway;
- an optional required JOSE `typ` value;
- all configured claim bindings;
- valid, non-empty claims referenced by the identity template; and
- a 64 KiB token-size limit before parsing.

HMAC algorithms and unsigned tokens are rejected. Trust material is never
shared across issuers, which prevents a key trusted for one issuer from
validating a token that claims another.

The unverified `iss` claim is used only to select a configured verifier. It is
not emitted as a metric label or normal audit field. Logging and authorization
use only claims from a successfully verified token.

### Claim bindings

A valid signature proves that the issuer created a token; it does not
necessarily prove that the workload is one the operator intended to trust. This
is especially important for a public issuer such as GitHub Actions, where many
workflows can request OIDC tokens.

Use `claimBindings` to constrain an issuer to trusted organizations,
repositories, workflows, and runner environments. Every configured binding must
match. Do not configure the public GitHub Actions issuer without suitable
bindings.

### Token repository scope

An issuer can name a claim containing repository globs. When present, haybale
intersects this token scope with the static policy:

```text
effective access = policy access ∩ token repository scope
```

A token can narrow policy but cannot expand it. An absent scope claim leaves the
policy unchanged; an explicit empty scope denies every repository.

## JWKS handling

A URL-backed JWKS must use HTTPS, except for loopback HTTP used in local tests.
The initial fetch is synchronous: haybale does not start if the endpoint is
unreachable, invalid, or contains no usable keys. Background refresh honors
`Cache-Control`, and unknown-key refreshes are rate-limited to avoid outbound
request amplification.

File-backed JWKS documents are read once at startup. Rotating a file-backed key
set requires replacing the file and restarting haybale.

For URL-backed issuers, a refresh failure leaves the last successfully fetched
key set active and emits a `jwks background refresh failed` warning. This
preserves availability during an issuer outage, but it also means stale keys
remain trusted for an unbounded period. If a compromised signing key is removed
from the issuer's JWKS while haybale cannot refresh it, tokens signed by that
key can continue to validate. Deployments that require fail-closed revocation
should alert on refresh failures and restart or isolate the affected instance
until trust material can be refreshed.

A compromised JWKS endpoint is equivalent to compromise of that issuer's
signing key. Protect its DNS, TLS, and administrative access accordingly.

## Authorization and repository privacy

Policy rules are ordered and first-match-wins. A request is allowed only when
the first matching identity/repository rule explicitly grants the required
`read` or `write` permission. No match is a denial. An empty rule list is valid
and denies all access.

The following cases all return `404 Not Found`:

- an invalid or unsupported Git smart-HTTP request;
- an unknown upstream host; and
- an authorization denial, including a token-scope denial.

This prevents clients from distinguishing a repository they cannot access from
one that does not exist. Authentication failures remain `401 Unauthorized` with
a Basic challenge so Git can supply a credential. Keep this distinction when
placing another proxy in front of haybale.

The `GET .../info/refs?service=git-receive-pack` push handshake is classified as
a write, despite using GET, and is denied to read-only identities before pack
data is exchanged.

## Credential separation

### Client JWT is not forwarded

After authentication, haybale removes the inbound `Authorization` header and
sets a new Basic-auth header from the selected upstream credential source. The
JWT is used only on the client-to-haybale connection.

### Upstream credential is not returned

If credential acquisition fails, haybale returns `502 Bad Gateway`, not `401`.
If an upstream rejects the injected credential with `401` or `403`, haybale
also returns a synthetic `502` and replaces all response headers and the body.
This prevents `WWW-Authenticate`, cookies, or other upstream-controlled error
headers from reaching the client and avoids a Git credential prompt the client
cannot satisfy.

Other upstream responses are streamed without this rewrite.

### GitHub App least privilege

For a `github-app` credential source, each installation token request names:

- exactly one repository; and
- only `contents: read` for fetch/clone or `contents: write` for push.

Tokens are cached per repository and permission, then refreshed five minutes
before expiry. A valid write token can satisfy a read request; a read token
never satisfies a write request. Concurrent requests for the same scope share a
single mint operation.

Installation IDs are cached for one hour. GitHub API calls have a 30-second
client timeout and also honor the inbound request context.

## Network and protocol behavior

### TLS

The listener carries client JWTs and the proxy process handles upstream
credentials. Plain HTTP is appropriate only on a network whose confidentiality
and membership the operator controls. Configure listener TLS whenever traffic
crosses a shared or untrusted network. TLS 1.2 is the minimum supported
version.

The Git upstream `baseURL` should also use HTTPS unless the upstream is reached
through an equivalently trusted private transport.

### Streaming and timeouts

On the passthrough path haybale does not buffer response bodies in memory. Pack
data is streamed through Go's reverse proxy and flushed on each write. Request
and response byte counts are observed while streaming. A response the cache
fetches is written to disk, not held in memory. The one in-memory exception is
an upstream error response, which haybale buffers up to 64KiB so that every
request waiting on the same fetch can receive it.

Request bodies are streamed as well, except that with the response cache
enabled the body of a read request is read in full, up to `cache.maxRequestBody`,
before the request is forwarded (see [Response cache](#response-cache)). At most
128 read requests are being read and classified at once; beyond that, reads pass
through without being inspected. A request the cache declines keeps the bytes it
read, at most `cache.maxRequestBody`, until they have been forwarded. Push
bodies are never read.

The server applies a 10-second request-header timeout but no read, write, or
idle timeout, and upstream connections use 30-second dial and TLS handshake
timeouts. This permits long-running, multi-gigabyte transfers, but an
authenticated slow client can retain resources indefinitely. The only
response-wait bounds are the response cache's fill timeouts, which apply to
fills and not to proxied requests. Use ingress-level
connection, rate, and idle controls where that risk matters, taking care not to
terminate legitimate large transfers.

A finite `drainTimeout` also places an upper bound on graceful shutdown. Its
default is `0s`, which waits indefinitely for active transfers.

### Forwarded headers

For requests proxied without the cache, smart-HTTP headers and content
encodings pass through unchanged. Requests the response cache handles carry only
the allowlisted headers described under [The upstream
request](#the-upstream-request). haybale does not generate `Forwarded` or
`X-Forwarded-*` headers, and inbound values for those headers are suppressed.
The upstream therefore does not receive the client's network address or haybale
listener details through those fields.

haybale does not inject its own OpenTelemetry `traceparent`, `tracestate`, or
`baggage` on upstream Git or GitHub API requests. Ordinary client-supplied
end-to-end headers continue to follow reverse-proxy forwarding rules.

## Response cache

The optional [response cache](caching.md) serves the pack transfer of repeated
identical clones and fetches from local disk. It is off by default. This
section describes what it changes about haybale's security properties; the
properties above hold for every request, cached or not. Stale-if-error is
reserved for a later release and is not available.

### Authentication and policy before any lookup

Authentication and policy run before the cache is consulted, before the request
body is read and before anything is looked up. A request that fails
authentication or is denied by policy is answered exactly as it is without the
cache, including the `404 Not Found` that is indistinguishable from a missing
repository, and never touches the cache. The cache therefore cannot be used to
test whether a repository exists or has been fetched recently by a caller policy
does not allow to read it.

Only the `read` verb is ever offered to the cache. A push, including the
`GET .../info/refs?service=git-receive-pack` handshake, is never cached, never
served from the cache and never has its body read. A completed
`git-receive-pack` request, whatever its status and even if the client
disconnects before the response ends, deletes that repository's cached ref
entries on this instance.

### What is cached

A read is cached only when haybale can classify it with certainty. The request
body is read in full, bounded by `cache.maxRequestBody` after decompression, and
parsed strictly as Git pkt-lines. Three request classes are cacheable: the ref
advertisement (`GET info/refs?service=git-upload-pack`), the protocol v2
`ls-refs` command, and a `fetch` whose arguments all come from an allowlist of
content-addressed ones. Everything else is a bypass: it takes the ordinary
passthrough path and stores nothing. That includes a body over the limit, a
`Content-Encoding` other than gzip or identity, a framing error, more than one
command, any capability or argument outside the allowlists, and every request
that carries `have` lines (incremental fetches), `want-ref`, `deepen-not`,
`packfile-uris`, a filter other than the allowlisted forms, or an unknown
command. Doubt always means bypass.

A response is stored only when all of the following hold: the request passed
authentication and policy, the upstream answered `200` with the expected
`Content-Type` and no content encoding other than identity, the body ended
cleanly within `cache.maxEntrySize`, and a scan of the pkt-line framing found no
in-band `ERR` packet or sideband error and a terminating flush at the end of the
body. The scan reads packet lengths and the sideband channel byte only. It never
interprets pack content.

A response that does not qualify is not stored, and is in most cases still
delivered to the client; the caching guide lists what clients see for each
[discard reason](caching.md#some-fills-are-discarded). A `200` response with any
other content encoding is not streamed through the cache; waiting requests are
sent to the upstream directly. A response over `cache.maxEntrySize` is delivered
to waiting clients without being stored when space can be reserved. If the
upstream fails part-way through a response, haybale closes the client
connection without a clean ending so the client cannot mistake a truncated
response for a complete one.

### The upstream request

For a cacheable request, haybale builds the upstream request itself from the
parsed, canonical form instead of forwarding the client's. The upstream request
carries the method and rewritten path, the canonical body (without the `agent`
and `session-id` lines), the `Content-Type` and `Accept` of a Git upload-pack
exchange, the validated `Git-Protocol` header, `Accept-Encoding: identity`, a
fixed `User-Agent` beginning `git/`, and the injected upstream `Authorization`.
No other client header reaches the upstream. The cache key is computed over
exactly these inputs, so no input the key does not cover can influence the
response that later readers receive. Inbound `Cache-Control`, `Pragma` and
`Cache-Status` request headers have no effect.

An upstream answer other than a cacheable `200` is shared with every request
waiting on the same fetch. haybale relays its status and body and its headers
other than hop-by-hop headers. An upstream `401` or `403` still becomes a `502`
with no upstream headers.

The upstream credential is minted only when a request needs the upstream. A
cache hit contacts neither the Git host nor the GitHub API, so token mint
events and metrics fall as the hit rate rises.

### Sealed entries

Every cached entry is sealed under the cache key (`cache.keyEnv`). Each entry is
sealed under its own AES key, derived from the cache key and a random salt
stored in the entry. The body is encrypted and authenticated with AES-256-GCM in
segments, and the entry header, which names the repository and its upstream, is
encrypted as well. Each segment is authenticated against the header, and haybale
verifies every segment before releasing its bytes to a client. Modification,
truncation, reordering and copying an entry to a different path or key all fail
verification. A failed entry is deleted and treated as a miss, or, when bytes
have already been sent, the connection is closed without a clean ending. Either
way a `cache_integrity_failed` security event is logged.

Entry names on disk are `v1/<group>/<repoHash>/<requestHash>`. The repository
hash is keyed. The request hash is an unkeyed SHA-256 of the canonical request.
A directory listing reveals whether an entry is a refs or pack entry, which
entries belong to the same repository, and each entry's size and time, but not
the repository name.

An entry's age is the creation time authenticated in its header, not the file
modification time, so changing a file's time does not extend its life.

The key protects a cache directory (or, in a later release, a bucket) against
someone who can read or write it but does not hold the key: such a party cannot
read repository contents or names and cannot forge, alter or move an entry,
although it can restore an earlier valid copy of one until `retention` ends. It
does not protect against a party that can read the haybale process's environment
or memory, and it does not hide the number, sizes and timestamps of entries.

Handle the key as a credential:

- generate it from a secure random source, for example
  `openssl rand -base64 32`, and deliver it through the same secret mechanism as
  other haybale secrets;
- keep it distinct from every other credential, and never write it in the
  config file;
- mount the cache directory only into the haybale container, with mode `0700`;
  and
- treat rotating it as a cold cache. At the next start haybale deletes the
  entries sealed under the previous key. `haybale cache purge` can address them
  only while the previous key is supplied.

When `keyEnv` is unset, haybale generates a key at startup and discards it on
exit. At the next start it deletes every entry in the directory, because none
can be read, so the cache is empty after every restart.

### Entries are shared across identities

An entry is keyed by repository and request, not by caller. Every identity that
policy allows to read a repository is served the same entries, and policy, not
the cache, decides who may read what. Sideband progress text from the upstream
is stored with the response and replayed to later readers; for GitHub this
carries nothing specific to the original caller, but an upstream that put
per-session text in progress output would replay it.

### Access recheck

A cache hit does not contact the upstream, so a retained pack could outlive
haybale's own access to the repository. A cached `fetch` response is therefore
served only if this haybale process saw a successful upstream refs response (a
ref advertisement or `ls-refs`) for the repository within `cache.accessRecheck`
(default `5m`). A normal clone makes that request first, so the rule costs
nothing for ordinary traffic. It stops a client that posts `want` lines directly
from reading retained packs after access has ended, and it bounds how long
revoked or removed access stays invisible. The record is held in memory per
process, so after a restart the first refs request for each repository
repopulates it. Setting `accessRecheck` to `0s` disables the rule, and cached
packs are then served until `retention` regardless of upstream access.

### Retention and purging

Cached content outlives upstream state for up to `cache.retention` (default
`24h`). After a history rewrite that removed a leaked secret, or after a
repository is deleted or transferred, a cached pack may still be served until
its entry expires. Retention is therefore the exposure window after a history
rewrite; lower it where that window is too long.

To end the exposure immediately, run `haybale cache purge` for the repository
(see [Purging a repository](caching.md#purging-a-repository)). The command
works on one cache directory. In this release every replica has its own
directory, so run the purge on every replica, or restart every replica that has
no `keyEnv`, which empties its cache.

Rewrite the history upstream first and purge afterwards. Some hosts, GitHub
among them, keep serving unreachable objects by id until garbage collection, so
a client that knows the old object ids can refill an entry after the purge. The
purge removes what is cached now. It also does not defend against someone who
can write the cache directory: they can restore a purged entry until `retention`
ends. The server's disk accounting corrects itself at the next janitor sweep.

### Cache-Status disclosure

With `cache.exposeStatus` set to `true`, responses carry an RFC 9211
`Cache-Status` header, including `fwd=bypass` on reads the cache passed
through. It is off by default because, within a repository that
several tenants may read, `hit` tells a client that another identity made the
identical request recently. Response timing can also differ between a hit and a
miss, so enable the header only where that disclosure is acceptable. The `cache`
field of the request log carries the same information for operators.

### Fill timeouts

A response being fetched into the cache has two bounds that passthrough requests
do not have: `cache.responseHeaderTimeout` (default `60s`) for the upstream's
response headers and `cache.idleTimeout` (default `2m`) for the gap between body
bytes. A single fill can serve many waiting clients, so a wedged upstream
connection would otherwise hold all of them. Expiry is treated as an upstream
failure. If the response headers had not arrived, the waiting requests are
released to the passthrough path and reach the upstream directly, so clients see
a delay of up to `responseHeaderTimeout`. If the body stalls after bytes were
sent, the waiting clients' connections are closed without a clean ending. In
both cases requests for the same key go straight to the upstream for one minute.
The number of fills in flight is bounded by `cache.maxConcurrentFills`; a
request that finds no free slot is proxied directly.

### Resource use

The cache bounds the memory and disk it uses. At most 128 read requests are
read and classified at once. Fills are bounded by `maxConcurrentFills` pack slots and 64
ref slots, and each reserves its disk before it starts. A response of unknown
length larger than both `maxEntrySize` and the free disk closes the connections
of the clients sharing it, once per `retention` for that key. It does not evict
stored entries beyond `maxEntrySize` to make room.

## Secrets at rest

Static upstream tokens, OTLP headers and the response cache key are read from
environment variables; they cannot be configured inline in YAML. Listener and
GitHub App private keys are read from files at startup. A private key file with
any group or other permission bit set is rejected; use mode `0600` or `0400`.

The GitHub App private key is parsed once to construct the signing transport.
It is not written or logged by haybale.

## Logging

Application logging uses structured fields and does not intentionally include
raw requests, complete URLs, tokens, or private keys. Every logger is wrapped
by a scrubber that redacts:

- Basic and Bearer authorization values;
- credentials in URL userinfo;
- compact JWTs;
- known GitHub token prefixes; and
- PEM private-key headers.

The scrubber applies to log messages, string attributes, error attributes, and
grouped values before records reach stderr or OTLP. It is defense in depth, not
a substitute for avoiding secret-bearing log fields.

Verified issuer, identity, token ID, expiry, repository, operation, status, and
installation ID are non-secret audit data and may be logged. Raw tokens and
minted token values are never audit fields.

## Security events

haybale emits warning-level structured events for:

- `authn_failed`
- `policy_denied`
- `upstream_auth_failed`
- `token_minted`
- `cache_integrity_failed`: a stored cache entry failed verification, was
  relocated, or carried an implausible creation time. It carries the host,
  owner, repository and request class and never key material.

Monitor repeated authentication failures, policy probes, upstream credential
failures, token-mint spikes, JWKS refresh warnings, and any
`cache_integrity_failed` events. See
[Observability](observability.md) for the related traces and metrics.
