# Security model

This document describes haybale's threat model and the security
invariants its implementation actually enforces, file and line
referenced where useful. If a claim here and the code ever disagree,
the code is the ground truth — file an issue.

## Threat model

haybale sits between a credential-free caller (a Stirrup sandbox, or any
other client that should never hold a real git-host credential) and one
or more real git hosts. It exists because that caller needs to
clone/push private repos without ever being handed a credential that
works directly against the git host — see `docs/stirrup-integration.md`
for the deployment this was built for.

What haybale defends against:

- **A compromised or over-curious caller** using its haybale token to
  read/write repos it isn't entitled to, or to discover which repos
  exist beyond what it's entitled to.
- **The caller obtaining the upstream git-host credential itself** (the
  GitHub App installation token, or the static upstream token) — the
  premise of the whole design is that the caller never holds a
  credential that works directly against GitHub/the internal git host.
- **A caller's haybale token leaking upstream**, or an **upstream
  credential leaking back to the caller** — either direction would
  undermine the isolation this component exists to provide.
- **Operational blast radius**: a leaked haybale token should be
  scoped to one policy entry (one identity's allowed repos/verbs), and a
  minted upstream credential should be scoped to the one repo and verb
  it was minted for.

What haybale explicitly does **not** defend against (see also each
milestone's non-goals in the project plan): pack/pkt-line content
inspection or ref-level push rules; the dumb git protocol (rejected
outright, see below); SSH transport; a compromised upstream git host
itself; an operator who mis-scopes policy.yaml.

- **Connection/resource exhaustion (slow-loris-shaped or otherwise).**
  `newServer` (`cmd/haybale/cmd/serve.go`) sets `ReadHeaderTimeout: 10s`
  and deliberately no `ReadTimeout`/`WriteTimeout`/`IdleTimeout`, no
  `MaxHeaderBytes` override, and no cap on concurrent connections — a
  direct, load-bearing consequence of pack transfers legitimately
  running to gigabytes and taking arbitrarily long (see "Streaming, not
  buffering" below). An authenticated-but-slow caller, or one that opens
  many connections and trickles data indefinitely, can tie up server
  resources for as long as it keeps doing so; nothing in haybale itself
  bounds that. `ReadHeaderTimeout` is the one exception: it still bounds
  how long a connection can sit open *before* sending a complete request
  line, so it does guard against the narrowest slow-loris shape (a
  connection that never finishes its headers at all).
  Rate limiting and connection-count limits are an explicit v0.1
  non-goal (see the project plan) — this tradeoff is deliberate, not an
  oversight, and is expected to be enforced at the ingress/load-balancer
  layer in front of haybale if it's a concern for a given deployment, not
  inside haybale itself.

## Sandbox token never forwarded upstream

The caller's own credential (its haybale token, presented as an HTTP
Basic password or `Authorization: Bearer`) is authenticated and then
discarded — never forwarded to the upstream git host. In the proxy's
`rewrite` step (`internal/proxy/proxy.go`), the inbound `Authorization`
header is explicitly deleted before the outbound request is sent, and a
completely separate, upstream-scoped credential (from the configured
`CredentialSource`) is injected in its place. Deleting first — rather
than relying on `SetBasicAuth`'s overwrite semantics alone — makes this
an explicit step in the code, not an incidental side effect.

## Upstream credential never reaches the caller

The reverse direction is enforced two ways:

1. **`WWW-Authenticate` is never forwarded.** If the upstream ever
   responds `401`/`403` *after* haybale already injected its own
   credential (`modifyResponse` in `internal/proxy/proxy.go`), that can
   only mean the upstream rejected haybale's credential — not something
   the caller did. haybale maps this to a synthetic `502 Bad Gateway`
   and **replaces the entire response header set** (not just deleting
   `WWW-Authenticate`) with a minimal, known-safe set, so no
   upstream-controlled header — `WWW-Authenticate`, `Set-Cookie`,
   anything else a compromised or misconfigured upstream's error page
   might set — reaches the caller.
2. **The caller never re-prompts for a credential it cannot supply.**
   Mapping a post-injection `401`/`403` to `502` (rather than passing the
   `401` straight through) means `git` never re-prompts for
   credentials — the caller has no real git credential to give it, so a
   passthrough `401` would just hang or fail confusingly instead of
   surfacing a clear gateway error.

A `CredentialSource` failure (a GitHub App mint error, a misconfigured
static token) is handled identically: `502`, never `401` — the caller
still has no upstream credential of its own to supply.

## Policy-denied and unknown repos are indistinguishable (no existence oracle)

Three cases collapse to the exact same `404 Not Found`, with nothing
written to the response beyond the status, in `internal/proxy/proxy.go`'s
`ServeHTTP`:

- a malformed/unrecognised request shape (`gitproto.ParseRequest`
  rejects it — includes the dumb protocol, path traversal, and any
  request that isn't one of the three smart-HTTP endpoint shapes);
- a request naming an upstream host that isn't configured at all;
- a request the policy engine denies, whether because no rule matched
  (default deny) or because a rule matched but doesn't grant the
  requested verb.

A caller probing repos it doesn't have access to therefore cannot tell
"this repo doesn't exist" apart from "this repo exists but you can't see
it" — deliberately, so policy.yaml's contents aren't discoverable by
probing.

Correspondingly, **authentication failure and policy denial are
distinct HTTP outcomes**: a missing/invalid token is a `401` (with a
`WWW-Authenticate: Basic` challenge, so `git` retries with a
credential), while a policy denial is the `404` described above — mixing
these would either leak "this repo exists, you're just unauthenticated"
information or make legitimate credential retries impossible.

## Streaming, not buffering

Pack data can run to gigabytes. Nothing in the request path buffers or
parses a request/response body: `internal/proxy` wraps
`httputil.ReverseProxy` with `FlushInterval: -1` (flush on every write,
rather than batching — this is what keeps `git`'s sideband progress
output live rather than arriving in bursts) and the only per-request
work beyond routing/rewriting a body does is counting bytes as they
stream past, for the request log (`countingReadCloser`/`statusRecorder`
in `internal/proxy/proxy.go`) — it never reads a body into memory.

The server sets `ReadHeaderTimeout: 10s` (bounding only how long it waits
to read a request's headers, against a client that opens a connection
and never sends a request line) and **no read/write/idle timeout at
all**, with or without TLS — an explicit, load-bearing choice documented
at the constant's own definition
(`cmd/haybale/cmd/serve.go`). Adding a read or write timeout here would
silently cap how large a clone/push haybale can proxy.

## Headers forwarded and suppressed

Every header on the inbound request is cloned onto the outbound one by
default (`httputil.ReverseProxy`'s normal behaviour), which in particular
means `Git-Protocol`, `Content-Type`, `Content-Encoding`, `Accept`, and
`Accept-Encoding` always reach the upstream unmodified — dropping
`Git-Protocol` in particular would silently downgrade a client from
protocol v2 to v1. The proxy's transport also sets
`DisableCompression: true` so it never decodes `Content-Encoding` itself;
this is a byte-for-byte passthrough, not a decoding proxy.

Two things are deliberately **not** forwarded:

- **`Authorization`** — replaced with the injected upstream credential,
  as described above (this is the one header
  `httputil.ReverseProxy`'s default hop-by-hop stripping does *not*
  cover, since `Authorization` is end-to-end, not hop-by-hop).
- **`X-Forwarded-*`/`Forwarded`** — haybale never calls
  `ProxyRequest.SetXForwarded()`, so these are never added (and any such
  header on the inbound request from the caller is simply dropped, not
  forwarded), meaning haybale never leaks the caller's IP/host/proto to
  the upstream.

## `info/refs?service=git-receive-pack` is a write

Per the git smart-HTTP protocol, the `GET .../info/refs?service=git-receive-pack`
handshake that precedes every push counts as a **write**
(`gitproto.ParseRequest` in `internal/gitproto/gitproto.go`), even though
its HTTP method is `GET`. A read-only identity is denied at this
handshake — before any pack data is exchanged — not merely at the
`POST .../git-receive-pack` that would follow it.

## Logging never contains token material

Every logger haybale constructs is wrapped in a scrubbing handler
(`internal/security/scrubhandler.go`) that redacts known secret shapes —
`Authorization: Basic`/`Bearer` headers, a credential embedded in a
URL's userinfo (`https://user:token@host/...`), a compact JWT (the
`eyJ`-prefixed three-segment token a caller now presents), GitHub's own
token prefixes (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`), and PEM
private key blocks — from any log record, regardless of level, before it
reaches the log sink. This is defense-in-depth: the primary defense is
that haybale's own logging call sites only ever pass
repo/owner/host/verb/identity/issuer/status as structured attributes (see
`internal/proxy/proxy.go`), never a raw request, URL, or credential —
the scrubber exists for the case where that discipline slips, e.g. in an
error string from a dependency this package doesn't control.

Full request URLs are never logged either way: log call sites pass the
individual `host`/`owner`/`repo`/`verb` fields gitproto parsed out, not
`r.URL` itself.

The **verified** claims of a JWT are assertions, not secrets, and so are
loggable: successful authentication logs the issuer, mapped identity,
`jti`, and `exp` — never the compact token itself. The **unverified**
`iss` a caller presents (used only to select which issuer's keys to
verify against) is treated as attacker-controlled: it is never used as a
metric label (it would be an unbounded-cardinality vector) and never
logged above debug. Only the verified issuer — drawn from the operator's
own bounded, configured set — appears on spans, metrics, and info logs.

## JWT verification (RFC 8725)

haybale is a **pure verifier**: it mints no tokens and holds no signing
key. It trusts one or more issuers, each through that issuer's published
public keys (a JWKS). See `docs/jwt-identity.md` for the token contract.
Verification (`internal/identity/jwt.go`) enforces, per issuer:

- an **asymmetric-only** algorithm allowlist, checked before the signature
  — so `alg: none` and the HMAC-signed-with-the-public-key confusion
  attack are rejected before a key is ever consulted;
- **issuer-bound trust material**: the token's unverified `iss` only
  *selects* a verifier; full validation then runs against **only** that
  issuer's key set, never "try every issuer's keys", closing cross-issuer
  key confusion;
- **mandatory** `aud` (any-of the configured set) and `exp`; honored
  `nbf`/`iat` within a configurable leeway; optional required `typ`;
- a **size cap** (64 KiB) applied before the parser runs, bounding the
  work an attacker can force with a giant, never-valid blob.

Authentication yields an identity via each issuer's `claimBindings`
(pinning an open issuer to trusted callers) and `identityTemplate`; the
YAML policy engine remains the sole authorization decision point. Signature
verification uses a **public** key, so it is not a secret comparison and no
constant-time discipline applies to it — unlike the prior static-token
scheme, where a digest comparison used `crypto/subtle.ConstantTimeCompare`.

## JWKS is haybale's first outbound dependency

A `jwksURL` is the first non-upstream outbound request haybale makes.
This is a named part of the threat model:

- A **compromised or spoofed JWKS endpoint** can mint an arbitrary
  identity *for that issuer* — it is equivalent to a signing-key
  compromise. Two things bound the blast radius: haybale keeps each
  issuer's trust material separate (a bad JWKS for issuer A cannot forge a
  token for issuer B), and the operator's `claimBindings` restrict which
  callers an issuer may authenticate at all.
- Config validation **requires `https`** for a `jwksURL` (plaintext
  `http` is permitted only for a loopback host, for testing), so trust
  material is never fetched over a spoofable plaintext channel.
- The initial fetch is **fail-fast**: an unreachable or empty JWKS at
  startup refuses to serve traffic. At runtime the key set is refreshed in
  the background (honoring `Cache-Control`) and refetched on an unseen
  `kid` behind a rate limit, so a burst of unknown-`kid` tokens cannot be
  turned into an outbound-fetch amplification vector.

### Known limitation: unbounded stale keys on sustained refresh failure

If background refresh **starts failing** (the JWKS endpoint becomes
unreachable), haybale currently keeps serving the **last successfully
fetched** key set indefinitely, logging each refresh failure at `warn`
(`jwks background refresh failed`). It favors availability: a JWKS outage
does not lock every caller out.

The security trade this makes is **unbounded trust duration** (CWE-613): if
an issuer's signing key is compromised and rotated out of the published
JWKS, *and* an attacker can simultaneously prevent haybale's egress to that
one JWKS URL (a targeted partition), haybale would keep accepting tokens
signed by the revoked key. This requires a prior key compromise plus a
sustained, targeted network partition to exploit.

A per-issuer `staleIfErrorFor` bound (serve last-known-good for at most
N after refresh begins failing; `0` = fail closed immediately) is a
**planned v0.2 follow-up**, deliberately deferred here: the value is a
judgment call the deployment owner should sign off on, and the current
JWKS library exposes no refresh-*success* signal to implement the bound
correctly without a custom storage wrapper. An operator who needs
fail-closed behavior today should monitor the `jwks background refresh
failed` warning and rotate the deployment. The optional startup
`discoveryCheck` (verify the configured issuer/jwksURL against the
issuer's OIDC discovery document) is deferred on the same track.

## Default-deny policy

`policy.yaml`'s rules are evaluated in order, first-match-wins; a
request matching no rule at all is denied. An **empty rules list is a
valid configuration** — it denies everything, which is a legitimate
(if unusual) choice, not treated as a mistake. See
`docs/configuration.md` for the rule shape.

## Least-privilege GitHub App token minting

When an upstream's credential is `type: github-app`
(`internal/upstream/githubapp.go`), every minted installation token is
scoped to:

- **exactly one repository** — the `repositories` field in the mint
  request names only the target repo, never the installation's full
  repo set;
- **the minimal permission the request's verb needs** — `contents: read`
  for a fetch, `contents: write` for a push, never both, and nothing
  beyond `contents`.

A compromised minted token can therefore act on nothing but the single
repo/permission it was minted for. Tokens are cached per
`(host, owner, repo, verb)` and refreshed 5 minutes ahead of their actual
expiry (`earlyRefreshWindow` in `internal/upstream/tokencache.go`) so an
in-flight transfer never gets handed a token that goes stale mid-stream;
a valid cached write-scoped token also satisfies a read request
(write-satisfies-read), but never the reverse. Concurrent requests for
the same repo/verb collapse into a single mint call
(`golang.org/x/sync/singleflight`), so a burst of simultaneous clones
against the same repo doesn't multiply GitHub API mint calls.

Every successful mint emits a `token_minted` security event (host,
owner, repo, verb, installation ID) — never the token itself, in the
event or in any error `GitHubAppSource` returns.

## GitHub App private key handling

The App's private key (`credential.privateKeyPath`) is read from disk
and parsed **once, at config-validation time**
(`internal/config/config.go`'s `buildCredentialSource`) — a missing file
or one that isn't a valid RSA private key fails startup immediately,
rather than on the first mint attempt. The key material is held only
long enough to build the JWT-signing transport
(`ghinstallation.NewAppsTransport`) and is never logged or written
anywhere else; the scrubber's `pem_private_key` pattern is a backstop
for the case where it's ever accidentally passed to a log call.

## TLS vs. plain HTTP

haybale carries the caller's bearer token and (during
`rewrite`/`modifyResponse`) the upstream git credential over its
listener. **Plain HTTP is safe only when that listener is genuinely
cluster-internal** — reachable exclusively from trusted callers over a
network haybale's operator controls (e.g. same-namespace pod-to-pod
traffic in Kubernetes, or a Stirrup sandbox reaching a
same-cluster-internal Deployment as in `docs/stirrup-integration.md`).

Configure `tls.certPath`/`tls.keyPath` (see `docs/configuration.md`)
whenever haybale's listener is reachable from anything less trusted than
that — a shared network segment, a multi-tenant cluster, or any path
crossing a network boundary an operator doesn't fully control. When
configured, haybale serves HTTPS with `tls.Config.MinVersion` pinned to
TLS 1.2, and — as with plain HTTP — sets no read/write/idle timeout
beyond the same 10s `ReadHeaderTimeout`, so TLS never becomes a second
place a large transfer could be silently capped.

## Graceful shutdown doesn't create a window for cut-off credentials

On `SIGTERM`/`SIGINT`, haybale marks itself draining (`/healthz` starts
returning `503`) and then calls `http.Server.Shutdown`, which lets any
in-flight request — including one mid-way through streaming a large pack
— finish completely rather than being cut off. This matters for the
security model too, not just reliability: an abruptly severed connection
mid-push is exactly the kind of failure mode that leaves a caller
uncertain whether a write actually landed; letting it complete removes
that ambiguity. See `docs/configuration.md`'s "Graceful drain" section
for the operational details (`drainTimeout`, defaults).
