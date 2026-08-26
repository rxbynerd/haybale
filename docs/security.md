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

haybale does **not** inspect pack or pkt-line content, enforce ref-level push
rules, support SSH or dumb HTTP, defend against a compromised upstream, or
correct an over-broad policy. It also does not provide connection rate limits or
a concurrent-connection cap; deploy an ingress or load balancer with those
controls when untrusted clients can reach the listener.

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

haybale does not buffer request or response bodies. Pack data is streamed
through Go's reverse proxy and flushed on each write. Request and response byte
counts are observed while streaming.

The server applies a 10-second request-header timeout but no read, write, or
idle timeout. This permits long-running, multi-gigabyte transfers, but an
authenticated slow client can retain resources indefinitely. Use ingress-level
connection, rate, and idle controls where that risk matters, taking care not to
terminate legitimate large transfers.

A finite `drainTimeout` also places an upper bound on graceful shutdown. Its
default is `0s`, which waits indefinitely for active transfers.

### Forwarded headers

Smart-HTTP headers and content encodings pass through unchanged. haybale does
not generate `Forwarded` or `X-Forwarded-*` headers, and inbound values for
those headers are suppressed. The upstream therefore does not receive the
client's network address or haybale listener details through those fields.

haybale does not inject its own OpenTelemetry `traceparent`, `tracestate`, or
`baggage` on upstream Git or GitHub API requests. Ordinary client-supplied
end-to-end headers continue to follow reverse-proxy forwarding rules.

## Secrets at rest

Static upstream tokens and OTLP headers are read from environment variables;
they cannot be configured inline in YAML. Listener and GitHub App private keys
are read from files at startup. A private key file with any group or other
permission bit set is rejected; use mode `0600` or `0400`.

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

Monitor repeated authentication failures, policy probes, upstream credential
failures, token-mint spikes, and JWKS refresh warnings. See
[Observability](observability.md) for the related traces and metrics.
