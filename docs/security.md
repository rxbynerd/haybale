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
URL's userinfo (`https://user:token@host/...`), GitHub's own token
prefixes (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`), and PEM
private key blocks — from any log record, regardless of level, before it
reaches the log sink. This is defense-in-depth: the primary defense is
that haybale's own logging call sites only ever pass
repo/owner/host/verb/identity/status as structured attributes (see
`internal/proxy/proxy.go`), never a raw request, URL, or credential —
the scrubber exists for the case where that discipline slips, e.g. in an
error string from a dependency this package doesn't control.

Full request URLs are never logged either way: log call sites pass the
individual `host`/`owner`/`repo`/`verb` fields gitproto parsed out, not
`r.URL` itself.

The identity file (`identities.yaml`) stores only a SHA-256 digest of
each token (`sha256:<hex>`), never the raw token — `haybale token new`
prints the raw token exactly once, to the operator's terminal, and never
persists it anywhere. Authentication (`internal/identity/statictoken.go`)
hashes the presented credential and compares digests using
`crypto/subtle.ConstantTimeCompare`, so response timing can't leak how
close a guessed token is to a valid one.

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
