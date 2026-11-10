# Design: response cache for Git smart HTTP reads

Status: accepted; the first pull request implements Decisions 1 to 7 and 9
(tier 1 only), the second pull request implements the remote tier, and the
third pull request implements Decision 8. Revised 2026-11-09 after
design review (pressure test, security threat model, API design review,
adversarial document review) and a research survey of prior art. This document records the design
decisions behind haybale's optional response cache so that future changes
can be checked against the reasoning, not only the code. Paragraphs marked
"Implemented as" record where the implementation differs from the
decision text.

## Problem

Fleets of sandboxed agents frequently clone the same repository within
seconds or minutes of one another. Today every clone is a full upstream
transfer: haybale authenticates, authorizes, injects a credential, and
streams the pack from the Git host. For a 500 MiB repository and fifty
agents that is 25 GiB of upstream egress and fifty rounds of upstream
pack generation to deliver the same bytes. (Installation-token minting is
already deduplicated by the token cache in `internal/upstream`; the cost
here is bandwidth and upstream CPU, not credentials.)

Two capabilities are wanted:

1. **Deduplication.** Identical read requests, sequential or concurrent,
   should cost one upstream transfer.
2. **Reads during an upstream outage** (operator opt-in). When the Git
   host or the GitHub API is unreachable, recently fetched content should
   still be servable, with the staleness risk accepted explicitly.

Writes (pushes) are never cached and never served during an outage.

## Constraints inherited from haybale's security model

The cache preserves every invariant in [security.md](../security.md):

- the client token never reaches upstream; the upstream credential never
  reaches the client;
- authentication and policy run before anything else, including any
  body read or cache lookup, and a policy denial is a 404 byte-identical
  to a missing repository (no existence oracle);
- `GET info/refs?service=git-receive-pack` is a write;
- the `Git-Protocol` header is always forwarded; and
- a post-injection upstream 401/403 becomes a 502 with no upstream
  headers leaking through.

Two stated properties change, and the security document is updated with
the implementation:

- haybale reads the body of a *read* request, bounded by
  `cache.maxRequestBody`, to derive a cache key and to build the upstream
  request; and
- haybale scans the pkt-line *framing* of a read response to decide
  whether it is safe to store.

> Implemented as: At most 128 requests are in the pre-stream phase at once:
> reading and classifying the body, then looking up an entry or joining or
> starting a fill. Beyond that limit, a read passes through unclassified. The
> slot is released on every exit of that phase, and before a response starts
> streaming, so a long transfer never holds one.

It still never buffers a response body in memory, never interprets pack
contents, and never reads a push body. Bypassed and write requests take
exactly today's passthrough path.

> Implemented as: A non-200 upstream response is buffered up to 64 KiB so it
> can be shared (Decision 4). No other response body is held in memory.

Standards note: by the definition in RFC 9111 haybale with the cache
enabled is a shared cache, and the Git smart-HTTP specification forbids
clients from reusing cached `POST` responses. This cache is deliberately
non-standard. It is safe because policy runs before every lookup at the
same granularity as the key (the repository), which is the authorization
check RFC 9111 section 3.5 requires before a stored authenticated
response may be reused.

## Observed protocol behaviour

A capture of real `git` 2.54 clients against `git http-backend`, taken
while writing this design, and the research survey's experiments against
GitHub established the following. Specifications:
[gitprotocol-http](https://git-scm.com/docs/gitprotocol-http),
[gitprotocol-v2](https://git-scm.com/docs/gitprotocol-v2),
[gitprotocol-pack](https://git-scm.com/docs/gitprotocol-pack), and
[gitprotocol-common](https://git-scm.com/docs/gitprotocol-common).

- Two `git clone` runs of the same repository send byte-identical
  request bodies for `ls-refs` and `fetch`. The only client-variable
  lines are `agent=` and, when `transfer.advertiseSID` is on,
  `session-id=`; the specification marks both informational.
- A protocol v2 clone is three requests: `GET info/refs` (empty body;
  the response is a capability advertisement, static for a server
  version), `POST git-upload-pack` with `command=ls-refs` (the
  freshness-sensitive request: its response is the current ref tips), and
  `POST git-upload-pack` with `command=fetch` listing `want` lines and
  `done`. Against GitHub, a v2 `POST` without the `Git-Protocol` header
  is rejected with 400.
- **git gzips any fetch request body over 1024 bytes** (`remote-curl.c`),
  so a clone of a repository with more than roughly twenty refs arrives
  with `Content-Encoding: gzip`. Bodies above `http.postBuffer` (1 MiB)
  stream chunked and uncompressed.
- `--depth 1` adds `deepen 1` and `include-tag`; protocol v0 sends one
  `want` line carrying the capability list (including `agent=`) followed
  by `done`. Partial-clone filters appear as `filter <spec>`.
- An incremental fetch sends `have` lines and omits `done`; the server
  answers with acknowledgments, `ready`, and the pack in one response.
- An in-band error (for example `want` of an unknown object) is an HTTP
  200 whose body is a single `ERR ...` pkt-line. Status codes alone
  cannot decide cacheability.
- Against GitHub, repeated identical fetches are **not** byte-identical:
  sideband framing differs between runs while the pack payload and the
  object set are identical. Only semantic equivalence matters; the
  client validates every object id and the pack checksum.
- Servers send `Cache-Control: no-cache`; clients send
  `Accept-Encoding: deflate, gzip`.

The decisive property is narrower than "packs are immutable". For a
request whose arguments are all content-addressed (`want <oid>` with no
`have`, no ref names, `done`), the response is a function of the request
and of immutable objects: a pack satisfying `want X` is a complete
closure of `X` and stays a correct answer to that exact request. Requests
that name refs (`want-ref`, `deepen-not`), depend on negotiation state
(`have`), or ask the server to emit URLs (`packfile-uris`) are not
immutable and are never cached. One allowed argument, `include-tag`,
makes the response depend on the server's current tag set as well; the
design accepts that drift for shallow clones (Decision 2). Otherwise only
the ref advertisement (which tips are current) has a freshness problem,
and the design separates the two.

## Decision 1: a request-keyed response cache, not a bare-repository mirror

Two architectures were considered.

**Response cache.** Store upstream responses keyed by (repository,
canonical request). Serve identical requests from the store. This is the
model of GitLab's Gitaly pack-objects cache, built to absorb exactly the
"many CI runners clone the same commit" burst, and of Varnish's git
caching, which keys on the request body minus `agent` and `session-id`.

**Bare mirror.** Maintain a bare clone per repository on local disk,
fetch from upstream on demand, and serve `git-upload-pack` locally (the
model of GitHub Enterprise Server repository caching and
`git-cache-http-server`).

The mirror serves any request shape from local state and offers true
offline reads. It was rejected because it changes what haybale is:
haybale would become a Git server, carrying the attack surface of a `git`
binary or a Go reimplementation of `upload-pack` inside a distroless
image, holding long-lived repository state that must be garbage-collected
and repaired, and doing every first fetch twice. A pluggable storage
backend is also meaningless for a mirror. The response cache keeps
haybale a proxy whose stored artefacts are opaque sealed blobs, which is
what makes local disk and object storage interchangeable.

The cost is coverage: only content-addressed requests with no `have`
lines are cached, so incremental fetches always go upstream. Those are
small by construction and are not the fleet-clone case.

## Decision 2: request classes, canonical form and key

Only requests whose verb is `read` are considered. The request body is
read in full, bounded by `cache.maxRequestBody` (default `1MiB`) on the
*decoded* size, and gzip-decoded when `Content-Encoding: gzip` is
present. The body is then parsed strictly into pkt-lines. Any of the
following classifies the request `bypass`, which takes today's
passthrough path unchanged and stores nothing: a body over the bound, a
`Content-Encoding` other than gzip or identity, a decode error, a pkt-line
framing error, trailing bytes after the terminating flush, more than one
command, more than one `agent=` or `session-id=`, a capability or
argument outside the allowlists below, a `Git-Protocol` header that is
absent for a v2-shaped body or present more than once, or any other
surprise. The parser guesses nothing: doubt means bypass.

| Class | Request | Freshness | Stored |
| --- | --- | --- | --- |
| `advertisement` | `GET info/refs?service=git-upload-pack` (v0 ref advertisement or v2 capability advertisement) | refs policy | yes |
| `ls-refs` | v2 `command=ls-refs` with arguments from {`symrefs`, `peel`, `unborn`, `ref-prefix <p>`} | refs policy | yes |
| `fetch` | v2 `command=fetch`, or v0 `want` lines, with arguments only from the fetch allowlist, at least one `want`, no `have`, and `done` | content-addressed | yes |
| `bypass` | everything else | n/a | no |

The fetch allowlist is: `want <oid>`, `done`, `thin-pack`, `no-progress`,
`include-tag`, `ofs-delta`, `deepen <n>`, `deepen-relative`,
`deepen-since <ts>`, `shallow <oid>`, and `filter <spec>` where `<spec>`
matches `blob:none`, `blob:limit=<n>[kmg]`, `tree:<depth>`,
`object:type=<blob|tree|commit|tag>`, or `sparse:oid=<full hex oid>`.
For v0 the capability list on the first `want` line must include
`side-band-64k` or `side-band`, and every capability must be from
{`multi_ack`, `multi_ack_detailed`, `no-done`, `side-band`,
`side-band-64k`, `thin-pack`, `no-progress`, `include-tag`, `ofs-delta`,
`shallow`, `deepen-since`, `deepen-not`, `deepen-relative`, `filter`,
`agent=`, `session-id=`, `object-format=`}; v0 request lines may be
`want`, `shallow`, `deepen`, `deepen-since`, one allowlisted `filter`,
then a flush and `done` (the v0 body ends with `done`, not a flush).
Explicitly bypassed: `have`, `want-ref` (sent automatically by stock
clients when a server advertises `ref-in-want`; it resolves a ref name at
request time), `deepen-not`, `packfile-uris`, `sideband-all`,
`wait-for-done`, `server-option`, any other filter spec, and any unknown
command (`object-info`, `bundle-uri`). Capability lines before the
delimiter must be from {`command=`, `agent=`, `session-id=`,
`object-format=`}; `object-format` stays in the key.

`include-tag` is allowed with a documented limit. A full clone sends an
explicit `want` for every tag it saw in `ls-refs`, so a new tag changes
the key and no drift occurs. A `--depth` or `--single-branch` clone
relies on `include-tag` for annotated tags that point into the wanted
history; served from the cache, such a clone lacks annotated tags created
after the entry was stored, for at most `retention`. This is accepted
because shallow clones are the dominant agent pattern and tags are rarely
load-bearing for them; tag-aware invalidation is deferred.

**Canonical form.** The canonical body is the parsed body re-encoded as
pkt-lines with the `agent=` and `session-id=` lines removed (for v0, the
`agent=` token removed from the capability list) and nothing else
changed, including line order and duplicate `want` lines. Clients built
from the same image produce identical canonical bodies.

**The upstream request is synthesised from the canonical form, not
cloned from the client.** For cacheable classes the request sent upstream
has exactly: the method and rewritten path; the canonical body with
`Content-Length` and no `Content-Encoding`; `Content-Type`
`application/x-git-upload-pack-request` (POST only); `Accept`
`application/x-git-upload-pack-result` or `*/*`; the single validated
`Git-Protocol` header; `Accept-Encoding: identity`; a fixed haybale
`User-Agent` beginning `git/`; and the injected `Authorization`. Nothing
else from the client is forwarded. The key is computed over exactly these
forwarded inputs, so no unkeyed input can select the response other
readers receive (this is the cache-poisoning vector the security review
rated high).

**Key.** The canonical-request digest is
`sha256(class || "\n" || Git-Protocol value || "\n" || canonical body)`, and
`keyHash = HMAC-SHA256(pathKey, digest)`, where `pathKey` is derived from
the cache key with HKDF-SHA256 (info `haybale response cache path key v1`),
so a reader of object names or bucket access logs cannot confirm a guessed
request.
`repoHash = HMAC-SHA256(cacheKey, upstream base URL || "\n" || owner || "/" || name)`,
where `cacheKey` is the deployment's cache key (Decision 6). Including
the configured base URL means repointing a host key or sharing a bucket
between deployments with different upstreams never serves another
origin's entries. Owner and repository case is not normalised: policy
matching is exact-case, and the cache follows policy.

Entries are addressed on both tiers as
`v1/<group>/<repoHash>/<keyHash>` where `group` is `refs` (classes
`advertisement` and `ls-refs`) or `pack` (class `fetch`). Grouping by
freshness rather than by class lets push invalidation delete one prefix
(`v1/refs/<repoHash>/`), lets a bucket lifecycle rule give the two groups
different ages, and lets new v2 commands join a group without a layout
change. Every
path component is a hex digest; no client-supplied string is ever a path
segment, and names read back from disk or a bucket are re-validated
against the pattern before use.

Inbound `Cache-Control`, `Pragma` and `Cache-Status` request headers have
no effect on cache behaviour.

## Decision 3: freshness policy

- **`pack` entries are content-addressed.** They are retained for
  `cache.retention` (default `24h`) or until evicted for space. A
  retained pack is always a valid answer to its request (with the
  `include-tag` drift accepted above), but it may be an answer upstream
  would no longer give: after a force-push that
  removed a leaked secret, a deleted or transferred repository, or
  revocation of haybale's own upstream access. Two controls bound that
  window. A `pack` hit is served only if this instance saw a successful
  upstream refs response (`advertisement` or `ls-refs`) for the
  repository within `cache.accessRecheck` (default `5m`); with the
  default refs policy every clone performs that request, so this costs
  nothing for normal traffic and stops a client that posts `want` lines
  directly from reading retained packs after access ends. `haybale cache
  purge` (below) removes a repository's entries from both tiers on
  demand. Retention is therefore also the exposure window after a
  history rewrite, and the operational notes say so.
- **`refs` entries are served from the cache only if younger than
  `cache.refsMaxAge`** (default `0s`: always revalidate with upstream).
  They are still stored, because stale-if-error needs them and they are a
  few hundred bytes, and they are uploaded to tier 2 only when a replica
  can read them back: when `refsMaxAge > 0` or `staleIfErrorFor > 0`.
  Refs requests are coalesced only when `refsMaxAge > 0`; with the
  default every refs request reaches upstream, so no client ever
  observes tips older than its own request.
  An operator who wants to absorb a burst of ref lookups sets a few
  seconds and accepts tips up to that age. The v2 capability
  advertisement follows the refs policy deliberately: it is tiny and
  the request is the first of every clone, so it must exist in the
  cache for stale service.
- **Pushes invalidate refs.** Any `git-receive-pack` `POST` for a
  repository through this instance, whatever its status (a rejected push
  still returns 200), deletes the repository's `refs` prefix in both
  tiers and bumps an in-memory per-repository generation. A refs fill
  whose upstream request began under an older generation is discarded at
  commit. Replicas that did not see the push keep their tier-1 refs
  entries until they age out, which matters only when `refsMaxAge > 0`, or
  during an outage with `staleIfErrorFor` set.

> Implemented as: Refs entries are written and counted against the disk
> budget. At the default `refsMaxAge` of `0s` they are never served as hits;
> stale-if-error is their consumer.

> Implemented as: Retention and `refsMaxAge` are decided from the creation
> time authenticated in the entry header, not the file modification time.
> The janitor uses the modification time for garbage collection only. A
> creation time more than five minutes in the future is an integrity
> failure.

> Implemented as: The invalidation is deferred until the push handler
> returns, so it runs once per push even when the client disconnects during
> the response.

With the defaults, fifty concurrent v2 clones cost one hundred small
upstream requests (advertisement and `ls-refs` per clone) and one pack
transfer, with no staleness.

## Decision 4: coalescing through a shared spool

Every cacheable read that misses tier 1 (and tier 2, when configured)
subscribes to a *fill* for its key. The first subscriber starts the fill;
later subscribers attach while it is in flight. The fill runs in its own
goroutine: it performs the upstream round trip through the proxy's
fetcher (Decision 7) and writes the sealed response into a spool file on
tier 1. **Every subscriber, including the first, is served by reading the
spool**, decrypting and verifying each segment as soon as it is complete.
Subscribers therefore run at their own pace, a slow client never
throttles the fill or other clients, and leader, follower and later hit
all take one read path and emit identical response headers.

Lifecycle:

- The fill's context derives from the server lifetime, not from any
  request. It is cancelled when the subscriber count has been zero for a
  short grace period, and on `Close` after graceful drain.
- Before the first byte is spooled, a subscriber waits for the fill's
  *header outcome*. On a 200 with an allowlisted `Content-Type`, the
  subscriber streams. On any other status the fill buffers the response
  body up to 64 KiB, applies the same sanitising as passthrough
  (401/403 become a header-less 502), and every subscriber receives that
  one response: the upstream answer depends only on haybale's credential
  and the identical request, so fifty subscribers never become fifty
  upstream attempts against a 404, 429 or 503. A non-200 body over
  64 KiB, or a transport failure before headers, releases every
  subscriber at once to the passthrough path (no serial re-election).
  Attach, detach and cancellation take one lock, so a request cannot
  attach to a fill that is being torn down.
- Whether an entry is stored never affects clients. Two outcomes are
  distinct. **"Will not commit"** covers an oversize response (over
  `maxEntrySize`), a storability-scan doubt, an in-band `ERR` or
  sideband-3 message, a `Content-Length` mismatch, and a refs generation
  change: the fill keeps spooling, every subscriber is served to
  completion with upstream's own bytes (including upstream's error
  text), and the spool is deleted afterwards instead of committed.
  **"Cannot continue"** covers an upstream transport error mid-stream, a
  spool write error, a sealed-segment verification failure, and a disk
  budget that is still exhausted after evicting committed entries: the
  spool is discarded and every subscriber is aborted with
  `panic(http.ErrAbortHandler)`, which closes the connection without a
  clean chunk terminator so no client can mistake a truncated body for a
  complete one. After an oversize response the key is marked uncacheable
  in memory for `retention`, so the next burst for that key passes
  straight through instead of spooling to the limit again; after a
  transient error the mark lasts a short cooldown. While stale-if-error is
  enabled, a fetch error marks nothing, so the key can still be answered
  stale (Decision 8).
- Fills carry their own timeouts, which stale-if-error does not change but
  depends on: stale-if-error requires a non-zero
  `cache.responseHeaderTimeout` (Decision 8). No
  response headers within `cache.responseHeaderTimeout` (default `60s`)
  or no body bytes for `cache.idleTimeout` (default `2m`; upload-pack
  sends a keepalive every 5 s while preparing a pack) is a transport
  failure. Passthrough requests keep today's unbounded behaviour; one
  wedged upstream connection then affects one client, whereas a wedged
  fill would hold every subscriber.
- Subscribers write every sealed segment to the client as soon as it is
  verified and flush, so progress and keepalives reach clients with at
  most the segment flush bound (below) of added latency.
- `recover()` guards every fill goroutine; a panic in the scanner or
  sealing code aborts that fill and its subscribers, never the process.
- Concurrent fills are bounded by `cache.maxConcurrentFills` (default
  `4`); a request that cannot obtain a slot bypasses. A fill of unknown
  length reserves `maxEntrySize` up front, so with the defaults four
  fills reserve at most 4 GiB of the 10 GiB budget, leaving the rest for
  stored entries; operators size the three values together.

> Implemented as: A subscriber that attaches after the fill committed is
> served from the committed entry. A subscriber that attaches after a
> discard decision is served from the spool, which stays readable until
> every attached subscriber has opened a reader. A refs request does not join
> a fill that began before the repository's latest push, because that fill is
> discarded at commit and may carry the pre-push tips; it passes through.

> Implemented as: A response with a known `Content-Length` over
> `maxEntrySize` is spooled and served to completion without committing when
> the reservation can be made from free space, so concurrent requests still
> coalesce. Otherwise the waiting requests are released to passthrough.
> Either way the key is marked for `retention`. Growth past
> `SealedSize(maxEntrySize)` that free space cannot hold aborts the subscribers
> (reason `too_large`) and marks the key for `retention`. Any other budget
> exhaustion (reason `disk_budget`), a shared non-200 response and every other
> discard or abort mark the key for one minute. A `generation` discard, a
> fill cancelled because its subscribers left, and, while `staleIfErrorFor` is
> above zero, a `fetch_error` release or abort mark nothing. A commit failure
> after a fully spooled body is a discard: subscribers are served to
> completion, while a failure to write the trailer aborts them.

> Implemented as: A pack fill reserves the sealed size of the upstream
> `Content-Length`, or of `maxEntrySize` when the length is unknown, plus a
> small allowance, rather than reserving only its first segment. Refs fills
> do not take a pack slot. They are capped at 64, each reserving 1 MiB. A
> reservation that cannot be made, after evicting unopened entries, releases
> the request to passthrough. Growth past `SealedSize(maxEntrySize)` uses
> free space only. `maxEntrySize` must not exceed half of `maxDiskSize`.

A fill that completes the storability checks (Decision 5) commits the
spool by rename and becomes a normal entry.

## Decision 5: what may be stored

An entry is committed only when all of the following hold:

1. the response came from the configured upstream for that host, with
   the injected credential, for a request that passed authentication and
   policy;
2. the status was 200 and `Content-Type` was
   `application/x-git-upload-pack-advertisement` (advertisement) or
   `application/x-git-upload-pack-result` (POST);
3. the response was identity-encoded (haybale asked for identity);
4. the body ended with a clean EOF, the byte count matched any
   `Content-Length`, and the body did not exceed `cache.maxEntrySize`
   (default `1GiB`);
5. a pkt-line framing scan saw no in-band error and a terminating
   flush-pkt exactly at EOF: no `ERR` packet in any section, no sideband
   channel 3 frame inside the `packfile` section (v2) or the sideband
   stream (v0), no malformed length (below 4 and not a special, `0003`,
   or above 65520), and no unexpected section order; and
6. the per-repository invalidation generation is unchanged since the
   upstream request began (refs only).

> Implemented as: A `200` with any content encoding other than identity
> releases the waiting requests to passthrough and is never stored. The fill
> reason is `encoding`.

The scanner is a streaming state machine over pkt-line lengths and the
first byte of each sideband frame. It treats lengths as skip counts,
never allocates from a length field, never looks at channel 1 content,
and handles frames split at any byte offset. Any state it does not
recognise means "do not store". It never alters or delays the stream.
It is fuzzed.

## Decision 6: sealed entries, two storage tiers

**Entry format.** Every stored object, on both tiers, is a preamble, a
sealed header, and sealed segments. The preamble (magic, format version,
key id, per-entry random nonce prefix) is clear text. The header is
encrypted and authenticated like the body, so repository names are
hidden from anyone who can read the disk or bucket without the key; it
records only fields known when the response starts: `repoHash`, group,
class, `keyHash` (the keyed digest of the canonical request, Decision 2), plain
repository name and upstream base URL, creation time, `Content-Type`,
and protocol. The body is encrypted and authenticated with
AES-256-GCM in a STREAM-style construction (nonce = prefix || segment
counter || final-segment flag) with the header's digest as associated
data on every segment. **Segments are variable length**, each framed by
an explicit ciphertext length, with 64 KiB as the maximum plaintext per
segment: the fill seals a segment when 64 KiB has accumulated or when
pending bytes are older than about 200 ms, so upload-pack's 5-byte
keepalives and sideband progress reach subscribers promptly. The total
body length is carried in an authenticated trailer in the final segment
and cross-checked by the reader. A reader verifies the header and each
segment before releasing bytes to the client; truncation, reordering,
relocation under another key, and modification all fail verification.
Verification failure is a miss plus a store-error metric; if bytes were
already sent, the connection is aborted.

> Implemented as: The sealed header is a fixed 4096-byte block. The preamble
> carries a 16-byte random salt. Each entry is sealed under a key derived
> from the cache key and that salt with HKDF-SHA256, with the nonce
> construction unchanged. Format version 1 is used because no earlier format
> shipped.

> Implemented as: The entry is deleted before the connection is aborted, and
> a `cache_integrity_failed` security event is logged with the host, owner,
> repository and class.

The sealing key comes from the environment variable named by
`cache.keyEnv` (32 bytes, base64), matching every other haybale secret.
It is optional when only tier 1 is configured: haybale then generates an
ephemeral key at startup, so a local-only cache does not survive a process
restart. It is required when `cache.remote` is set, because replicas must read
each other's entries. The key is distinct from any storage credential; whoever
can write to the bucket still cannot forge or relocate an entry
(the security review's highest-severity finding). Rotating the key is a
cold cache: `repoHash` is keyed, so entries under the previous key are
unreachable. Tier 1 deletes entries sealed under any other key id at startup,
both with an ephemeral key and after a key change. Tier 2 entries under the
previous key age out through the bucket lifecycle. The key id in the preamble
exists so a reader can reject such entries cleanly, not to support dual-key
operation.

**Tier 1, local disk (`cache.dir`), required when the cache is enabled.**
It is the spool for in-flight fills, the read path for every subscriber,
and the local cache. Requirements: haybale creates the leaf directory
with mode 0700 if it is missing (its parent must exist, so a root-owned
`emptyDir` mounted at the parent needs no init container); the directory
must be owned by the process user with no group or other permission
bits; every file operation goes through `os.Root` so symlinks cannot
escape it; and one directory serves one server process (opening a store
removes other processes' temporary files, so replicas must not share a
volume). Files are
created `0600`, written to a temporary name under the directory, synced,
and renamed into place; a partially written entry is never visible.
Temporary names carry a per-process prefix, so the startup sweep removes
every temporary file from earlier processes without an age heuristic and
the janitor never touches a live spool. A disk budget (`cache.maxDiskSize`,
default `10GiB`) counts committed bytes, in-flight spool reservations, and
evicted-but-still-open bytes; a fill that cannot reserve its first segment
bypasses. A janitor evicts least-recently-used entries past the budget, removes
expired entries and orphaned temporary files, and only ever deletes names
matching the entry pattern. Operators deploy an `emptyDir` with `sizeLimit`
above `maxDiskSize` so a full cache can never evict unrelated pods.

> Implemented as: The reservation covers the whole fill, as described under
> Decision 4.

**Tier 2, remote object storage (`cache.remote`), optional.** After a
tier-1 commit, the sealed file is uploaded by a bounded worker pool from
its finalised length (for `pack` entries a `Stat` first skips the upload
when a peer already stored the key; `refs` entries replace the shared copy so
it is refreshed, and are uploaded only under the condition in Decision 3).
On a tier-1 miss, tier 2 is consulted before upstream under
`cache.remote.headerTimeout` (a time-to-first-byte bound; body
reads fall under the fill's idle timeout); a tier-2 hit is streamed into the tier-1
spool as a fill source, so subscribers coalesce on it exactly as on an
upstream fill. A tier-2 failure before the first byte falls through to
upstream inside the same fill; a failure mid-stream resumes with a ranged
`Get` from the current offset a bounded number of times, since the object
is immutable and its length is known from the header, and only then
aborts. Bucket lifecycle expiry is day-granular on AWS S3, and other
stores were not checked, so expiry is decided from the header's creation
time and lifecycle rules are garbage collection only. Objects are stored
as `application/octet-stream` with no user metadata (limits and encoding
rules differ per vendor; the in-object header is the only metadata).
Entries over 5 GiB are not uploaded (single-request PUT limit), which the
default `maxEntrySize` already guarantees.

```go
// BlobStore is the remote tier. Implementations are safe for concurrent
// use; callers own deadlines through ctx.
type BlobStore interface {
    Stat(ctx context.Context, key string) (ObjectInfo, error)             // ErrNotFound
    Get(ctx context.Context, key string, offset int64) (io.ReadCloser, ObjectInfo, error)
    Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error
    Delete(ctx context.Context, key string) error                        // nil when absent
    List(ctx context.Context, prefix string) iter.Seq2[ObjectInfo, error]
}
```

Tier 1 is a concrete spool store inside `internal/cache`, not a
`BlobStore`; it needs growing-file reads, atomic rename and eviction that
no remote store has. `BlobStore` is defined on the consumer side in
`internal/cache`; each backend lives in its own package so the AWS SDK
never enters the core.

**`s3` backend** (first implementation) uses the AWS SDK for Go v2 (S3,
config and credentials modules; no upload manager, since every upload has
a known length). The research survey measured the alternatives: the
official SDK adds 19 modules, minio-go 14, and a hand-rolled SigV4 client
2, but the weight is the credential chain, and IRSA, EKS Pod Identity and
IMDS support is exactly what a Kubernetes deployment needs and what is
not worth owning. Configuration covers AWS S3, S3 Express One Zone
directory buckets, Cloudflare R2, Ceph RGW, and Google Cloud Storage's
S3 interoperability endpoint through `endpoint`, `region` and
`forcePathStyle`. Constraints: `endpoint` must be `https` (loopback
`http` allowed for tests, matching the JWKS URL rule); the endpoint is
always set explicitly from configuration so `AWS_ENDPOINT_URL*` cannot
redirect the cache; the SDK's HTTP client uses an explicit transport with
no environment proxy; request and response checksums are set to `WhenRequired`
(the SDK's default CRC32 checksums break several non-AWS stores);
`prefix` is empty (the bucket root, one trust domain for the whole bucket) or
ends with `/` (so one prefix cannot also match another in IAM conditions and
lifecycle filters); optional `sse` and `kmsKeyID`
fields request server-side encryption where the store supports it (R2
has none); errors are logged by operation,
error code and status only; and the log scrubber gains AWS access-key-id
patterns. Documentation recommends workload identity (IRSA or Pod
Identity) with IMDSv2 hop limit 1, and names Cloudflare R2 as the
zero-egress vendor-neutral option. Azure Blob Storage and native Google
Cloud Storage are future `BlobStore` implementations; the MinIO server is
archived and is not recommended for new deployments.

> Implemented as: The upload pool is four workers behind a queue of 256
> entries; an entry committed while the queue is full is not uploaded and is
> counted as `dropped`. Entries filled from tier 2 are not uploaded again. A
> refs upload is skipped once a push has bumped the repository's generation,
> and any upload is skipped once a purge marker covers it. Tier 2 is consulted
> before upstream only under the tier-1 hit rules: a pack needs a recent
> upstream refs success (`accessRecheck`), and a refs entry needs a positive
> `refsMaxAge`. With stale-if-error enabled it is also read, after upstream
> fails or the health gate holds the request, under the stale rules of
> Decision 8. A tier-2 fill is reported to the client as `fwd=miss`, like any
> fill.

> Implemented as: There is no fill-source interface. Reading tier 2 is a
> separate path at the start of the fill, which spools the sealed object as
> it is and verifies it as it passes; on a miss or an early failure the same
> fill continues with the upstream request.

> Implemented as: "Before the first byte" is the point where the fill
> publishes its outcome to subscribers: after the `Get` returns and the
> 4 KiB sealed header has been read and verified, within `headerTimeout` of
> the `Get` returning (within `idleTimeout` when `headerTimeout` is `0s`),
> with no resume. A failure up to that point falls
> through to upstream. After it, a failed or idle body resumes with a ranged
> `Get` from the current offset, up to three times, with a backoff from
> 100 ms that doubles; a resume always checks that size, modification time
> and ETag are unchanged, and is conditional on the ETag (`If-Match`) when
> the store reports one.
> A stall inside the first sealed segment therefore resumes rather than
> falls through, and if the read cannot continue the fill aborts and
> subscribers that received nothing are released to the passthrough path.
> `Stat` and `Get` make a single SDK attempt, so `headerTimeout` is their
> only bound and the three resumes are the only retries; `Put`, `Delete`
> and `List` keep the SDK's default retryer.

> Implemented as: A read that cannot continue after its resumes, or whose
> object changed or was deleted, ends the fill with `fetch_error` and
> leaves the object; it is not an integrity failure. A failure of the
> sealed reader itself (header or segment authentication, a missing final
> segment, bytes after it) is an integrity failure: the object is deleted
> from tier 2 within `headerTimeout` (one minute when it is `0s`) before
> the fill moves on. A tier-2 entry past `retention` or older than a purge
> is deleted in the background, each deletion bounded at one minute and at
> most eight such tasks at a time, and the fill falls through to upstream.

> Implemented as: Push invalidation deletes the repository's tier-2 refs
> entries before `Invalidate` returns, after the tier-1 deletion, with one
> deadline of `headerTimeout` (one minute when it is `0s`) across the `List`
> and the `Delete`s, best effort. The push time is kept in memory per
> repository, and a tier-2 refs entry created no later than it is a miss on
> that replica. A refs upload whose generation moved during its `Put`
> deletes the object again.

Memcached and Redis were rejected as the remote tier: packs are routinely
hundreds of megabytes, memcached's item limit is 1 MiB by default, and
Redis would hold every pack in RAM. OCI registries were rejected: entries
are keyed by request, not content digest, so every entry would need a
manifest and tag, and registries offer no expiry.

## Decision 7: integration with the proxy

The proxy keeps one upstream transport and one set of credential-boundary
functions, used by both the passthrough and the cache paths:

- request construction (strip the client `Authorization`, inject the
  upstream credential, never set `X-Forwarded-*`, empty trace
  propagator), today in `rewrite`;
- response sanitising (the 401/403-to-502 reset), today in
  `modifyResponse`; and
- the transport (`DisableCompression`, HTTP/1.1, and new dial and TLS
  handshake timeouts of 30 s, which also apply to passthrough).

The proxy exposes a `Fetcher` built from these pieces to the cache; the
cache never constructs an upstream request itself. `proxy.New` gains a
variadic option `WithCache`, so existing callers are unchanged and a nil
cache is exactly today's behaviour. Within `ServeHTTP`, after policy
allows a read, the cache is offered the request; it returns an outcome and
whether it handled the response, and the proxy keeps the single place that
records metrics and the request log.

**Lookup precedes credential minting.** Today the credential is minted
before forwarding. With the cache, a hit never contacts upstream or the
GitHub API, so the fetcher mints lazily, and the `CredentialSource`
documentation changes accordingly. `CredentialSource` implementations
wrap transport failures and upstream-API 5xx responses in a new sentinel,
`upstream.ErrUnavailable`; every other mint error (bad key, suspended app,
installation removed, repository not in installation, rate limiting)
remains opaque and is never treated as an outage.

> Implemented as: A credential mint failure inside a fill releases the
> request to passthrough, which re-mints and answers `502`, unless
> stale-if-error answers it. The cache path
> always requests `<base>/<owner>/<repo>.git/<endpoint>`, where passthrough
> keeps the client's path form.

Existing tests for `Authorization` replacement, `X-Forwarded`
suppression, no upstream `traceparent`, and 401/403-to-502 become
table-driven over both paths.

## Decision 8: stale-if-error (operator opt-in)

`cache.staleIfErrorFor` (default `0s`, disabled) is the maximum age of an
entry that may be served when upstream cannot answer. It must not exceed
`retention`, and it requires a non-zero `cache.responseHeaderTimeout`,
since an unbounded fill or probe against a hung upstream would hold
requests indefinitely. The configuration reference and the security model
describe the risk in plain terms: a stale clone can lack a security fix or still
contain a reverted or scrubbed commit, and git shows no indication to the
user.

A read becomes eligible for stale service when, for that request:

- the credential source returned `upstream.ErrUnavailable`;
- the upstream connection failed (DNS, dial, TLS) before response headers
  arrived, including a TLS alert on an established connection, or no
  response headers arrived within `cache.responseHeaderTimeout`; or
- upstream returned 500, 502, 503 or 504.

A subscriber to a fill whose header outcome is eligible is served stale
when a qualifying entry exists, before the shared non-200 response is
relayed. Not eligible: 401 and 403 (a credential problem, still mapped to 502),
404 and other 4xx (passed through), 429 or rate-limit 403 (a policy
signal, not an outage), and every write. An eligible request is answered
from an entry for its key no older than `staleIfErrorFor`: the tier-1
entry when it qualifies, otherwise the tier-2 entry. The
`accessRecheck` rule is waived for stale service; the response carries
`Cache-Status` with `fwd=stale` when exposed; a `cache_stale_served`
security event records identity, repository, class and entry age; and a
metric is recorded. Without a qualifying entry the request fails as it
does today. A 5xx induced by one client's own request can only steer that
client's own key to its stale entry; it changes nothing for other
readers.

**Health gate.** Each upstream host carries a gate so an outage does not
cost every request a connection timeout before falling back. The gate
opens only on failures a client cannot induce: DNS, dial and TLS errors,
and `ErrUnavailable` from the credential source. Response-header timeouts
and 5xx never open it. While open, requests that have a qualifying stale
entry are served immediately; requests without one, and one probe request
at a time, go upstream. A success closes the gate; an open gate admits its
next probe 5 s after the previous one ended. The probe interval is a
constant, not configuration. A held request with a qualifying tier-1 entry
is answered before it takes a fill slot, and a request that finds a probe
due but cannot become the probe, for want of a slot or because its key is
marked, is answered stale too, so fills stuck on upstream cannot crowd it
out; a tier-2 answer is spooled through a fill and so needs a slot. A
probe's subscribers wait at most the probe interval for upstream headers
and are then answered from a qualifying tier-1 entry with reason
`health_gate`, while the probe's upstream request continues until headers
arrive or `responseHeaderTimeout` expires; its result, not the deadline,
decides the gate. When `responseHeaderTimeout` is shorter it expires first
and sets the reason. A hung upstream that accepts connections never opens
the gate, so the deadline applies only while an earlier connect failure
holds it open.

A clone during an outage therefore succeeds only if the same clone (same
tips, same options) happened recently through this instance or a peer
sharing tier 2. The latest stored refs may name tips for which no pack is
stored (for example after a peer's incremental fetch refreshed `ls-refs`);
that clone then fails at the fetch step as it would without the cache.
Both limits are stated in the documentation.

> Implemented as: A connection failure is recognised by the error the
> transport returns: a dial or name-resolution error, a TLS handshake error
> (including an untrusted certificate and the handshake timeout), or a TLS
> alert. An error that can arise after a connection exists, such as a reset
> or an EOF, is not eligible. The proxy's fetcher rewrites an upstream 401 or
> 403 into a 502 before the cache sees it, so it names the original status in
> an internal `Haybale-Upstream-Status` header that the cache classifies by
> and strips. The fetcher and the passthrough path delete any copy the
> upstream sends, and the cache honours the header only on a 502 and only
> for 401 or 403. The tier-1 entry is used whenever it qualifies, and tier 2 is
> read only when it does not, so a newer remote refs entry does not replace a
> qualifying local one: tier 1 answers a held request without a fill slot,
> while tier 2 is read only through a fill that takes one. Purge markers and
> retention still apply. With a
> remote tier, no entry is served stale until the repository's purge marker
> check is current (a successful check within the marker interval, or a read
> made now); a failed read, a marker that fails verification, or a check
> skipped under the backoff fails closed. Concurrent checks of a repository
> share one marker read, which runs under the cache's lifetime, so a caller
> that leaves neither cuts it short nor fails it for the others. A failure
> answered stale leaves the key cacheable, so later requests during the
> outage are answered stale too, and while stale-if-error is enabled a
> `fetch_error` marks nothing. A key marked for another reason is still
> answered stale from tier 1 while the gate is open, because the held answer
> is tried before the mark is honoured. The proxy passes the verified
> identity to `Serve` as a parameter. The `cache_stale_served` event also carries `tier`,
> `reason` (`connect`, `credential_unavailable`, `header_timeout`,
> `upstream_status` or `health_gate`) and `entryAgeSeconds`. The gate exists
> only while `staleIfErrorFor` is above zero. Any upstream answer other than
> 500, 502, 503 or 504 counts as a success. Probes ride on client requests:
> at most one at a time, admitted no sooner than 5 s after the previous probe
> ended or the gate opened, and a probe ends when its response headers or its
> fetch error arrive. Its purge marker check starts beside its upstream
> request; at the deadline its subscribers are answered stale only when that
> check is current and the tier-1 entry still qualifies, and otherwise keep
> waiting for upstream. Once the deadline has answered, the fill is
> unregistered, so a later request for the key is held by the gate or
> starts its own fill and never inherits the stale answer; two fills for one
> key can briefly overlap. A probe is never abandoned, even when its client
> leaves; once its headers have reached the gate, a probe fill that no
> subscriber holds ends at once and its response is discarded unread, with
> no mark. A connect failure of an attempt that
> began before the latest success is ignored. A request the gate holds back
> that has no qualifying entry goes upstream, and a held request answered
> from tier 1 records no fill metric. With the cache enabled, the
> passthrough path bounds a read's wait for response headers by
> `responseHeaderTimeout` too, so a read declined after a fill's header
> timeout fails with a 502 instead of waiting on the upstream without
> bound. Request-driven probing, the neutrality of 5xx and header
> timeouts for the gate, and the `identity` parameter on `Serve` are the
> accepted design.

## Decision 9: what the client sees

Responses served through the cache path carry the stored `Content-Type`,
`Content-Encoding: identity` semantics (no header), the same
`Cache-Control: no-cache` posture upstream sends, and nothing else from
upstream. When `cache.exposeStatus` is `true` (default `false`), the
response also carries an RFC 9211 `Cache-Status: haybale; ...` header with
`hit`, `fwd=miss` (with `collapsed` for a subscriber that joined an
in-flight fill), `fwd=bypass` (written by the proxy on the passthrough
path for a read the cache declined), or `hit; fwd=stale` for stale
service, with `fwd-status=<n>` when an upstream status arrived. Whether a fill was stored is only known after the
response has been written, so it appears in the request log
(`cacheStored`), not in the header. The header is off by
default because within a repository that several tenants may read, a
`hit` reveals that another identity made the identical request recently.
The request log's `cache` field carries the same values for operators.

> Implemented as: Responses served through the cache path carry
> `Cache-Control: no-cache, max-age=0, must-revalidate`, `Pragma: no-cache`
> and an `Expires` date in 1980, as upstream sends. A shared non-200
> response relays the upstream headers other than hop-by-hop headers, with
> `Content-Length` recomputed. The `fwd=bypass` `Cache-Status` is written by
> the cache when it declines a request, not by the proxy. The stale form is
> `haybale; hit; fwd=stale` also when the health gate kept the request from
> upstream. `fwd-status` is present only when an upstream status arrived; it
> is omitted after a connect failure, an unavailable credential source, a
> header timeout, and a gate-held request.

## Operator controls

`haybale cache purge --config haybale.yaml --repo HOST/OWNER/REPO [--group refs|pack]`
removes a repository's entries from the local tier-1 directory and, when
`--remote` is passed, from tier 2. It is the documented response to a
history rewrite that removed a secret, a repository deletion or transfer,
or a suspected poisoned entry. It runs as a separate process against a
directory a server may be using: the server treats a vanished file as a
miss, and the purge only ever deletes names matching the entry pattern.

Purge reaches one replica's tier 1. With a remote tier, purge also writes
a per-repository marker object (`v1/purge/<repoHash>`, holding the purge
time) that every replica reads when it refreshes the repository's
`accessRecheck` record; a local entry created before the marker is a
miss and is deleted. Without a remote tier, the procedure is to run the
purge in every replica (or restart every replica when the key is
ephemeral), and the documentation says so.

> Implemented as: The marker is sealed in the entry format and records the
> purge time of each group, so purging one group keeps the other group's time.
> A replica checks it alongside an upstream refs fill for the repository,
> before renewing the access record that pack hits depend on. A successful
> check (the marker read and verified, or confirmed absent) stays current for
> one minute, or for `accessRecheck` when that is shorter, and concurrent refs
> fills share one read, so a replica honours a purge within about a minute
> plus its next upstream refs request. A failed or skipped check leaves the
> access record unrenewed, so pack hits lapse within `accessRecheck`; after a
> failed read the marker is not read again for one minute. Entries read from
> tier 2 are checked against the marker as well.

> Implemented as: `purge --remote` writes the marker first, then deletes the
> tier-2 entries, then the tier-1 entries. A marker that cannot be written
> stops the purge before anything is deleted; a failed tier-2 deletion still
> lets the tier-1 step run, and a rerun is safe. A missing local directory
> is skipped with `--remote`. Without `--remote` and with a remote tier
> configured, the command warns that replicas will refill the entries from
> the bucket.

## Observability

Metrics (host and class only, never owner or repository), under the
`haybale.response_cache.` prefix to avoid colliding with the token cache:

- `lookups.total` labels host, class, result (`hit`, `miss`, `stale`,
  `bypass`);
- `fills.total` labels host, class, tier (`upstream`, `remote`: where the
  fill read the response; a tier-2 attempt that falls through counts once,
  as `upstream`), result (`stored`, `discarded`),
  reason (`error_packet`, `sideband_error`, `framing`, `truncated`,
  `too_large`, `disk_budget`, `store_error`, `generation`,
  `upstream_status`, `fetch_error`, `encoding`);
- `fill_bytes.total` and `served_bytes.total` labels host, class, tier
  (`disk`, `remote`, `upstream`);
- `collapsed.total` labels host (subscribers that joined an in-flight
  fill);
- `store_errors.total` labels tier, operation;
- `uploads.total` labels result; `evictions.total`; `disk_bytes` gauge.

Spans `haybale.response_cache.lookup` and `haybale.response_cache.fill`
nest under the request span; the fill span is linked from, not parented
to, the first subscriber's span because the fill outlives it. The request
log gains a `cache` field. Security events: `cache_stale_served` and
`cache_integrity_failed` (warning). Hits keep `outcome=proxied` on the existing
request metrics so current dashboards and SLOs include them; the documented
meaning of `proxied` widens to "answered on the client's behalf", and
upstream-load panels should use the fill metrics instead.

> Implemented as: The spans `haybale.response_cache.lookup` and
> `haybale.response_cache.fill` are not implemented. The request span
> carries `haybale.cache.result`, `haybale.cache.collapsed` and
> `haybale.cache.stored`. A fill's upstream request is a root span because
> the fill outlives its first subscriber.

## Configuration

```yaml
cache:
  enabled: false
  dir: /var/cache/haybale          # required when enabled; no group or other permission bits, owned by the process user
  keyEnv: HAYBALE_CACHE_KEY        # 32-byte base64 key; optional for disk-only, required with remote
  maxDiskSize: 10GiB               # tier-1 budget: committed + in-flight + evicted-but-open
  maxEntrySize: 1GiB               # larger responses stream through unstored
  maxConcurrentFills: 4            # with maxEntrySize, bounds in-flight disk use
  maxRequestBody: 1MiB             # decoded size; larger read bodies bypass
  retention: 24h                   # all entries; also the post-rewrite exposure window
  refsMaxAge: 0s                   # 0s = always revalidate refs upstream
  accessRecheck: 5m                # pack hits need a recent upstream refs success
  responseHeaderTimeout: 60s       # fills and passthrough reads: time to upstream response headers
  idleTimeout: 2m                  # fills only: max gap between upstream body bytes
  exposeStatus: false              # emit Cache-Status
  remote:                          # optional tier 2
    type: s3
    bucket: haybale-cache
    prefix: prod/                  # empty (bucket root) or ending with "/"
    region: us-east-1
    endpoint: ""                   # https; set for R2, Ceph, GCS interop
    forcePathStyle: false
    headerTimeout: 10s             # each remote Stat, Get, List page and Delete, and the sealed-header read; 0s = no per-request bound
    sse: ""                        # "AES256" or "aws:kms"
    kmsKeyID: ""
  staleIfErrorFor: 0s              # 0s = disabled; must not exceed retention; needs responseHeaderTimeout > 0
```

The `cache` block is decoded strictly (unknown keys are errors) even
though the rest of the file is not, so a mistyped or renamed key fails
startup instead of silently reverting to a default. Sizes use a
`ByteSize` YAML type that accepts IEC units only (`KiB`, `MiB`, `GiB`, `TiB`)
and rejects bare integers other than 0 and SI units, so a value can never be
misread by a factor of 1024. Durations use Go duration
strings as elsewhere. `cache` follows the configuration package's
pattern: a structural `validate()` at load time (parses sizes and
durations, requires `retention > 0`, requires `refsMaxAge < accessRecheck`
when both are set, checks `staleIfErrorFor <= retention`, refuses a
non-zero `staleIfErrorFor` with an explicit `responseHeaderTimeout: 0s`,
requires `keyEnv` with `remote`, recognises the remote type) with no filesystem or network side
effects, so `haybale policy check` stays offline; and a
`BuildCache(ctx, logger, metrics)` step called from `serve` that opens
the directory, loads or generates the key, constructs the remote client,
and starts the janitor and upload workers. The cache has `Close(ctx)`,
called after graceful drain so fills and uploads survive the drain window
and pending uploads are flushed within a bound; its goroutines are not
bound to the SIGTERM context. `BuildCache` probes the bucket with a
`Stat` of a sentinel key: `ErrNotFound` is healthy, an authorization or
configuration error fails startup (matching the fail-fast JWKS
behaviour), and a transient network or 5xx error logs a warning and
continues, so a bucket outage cannot stop haybale from starting.

> Implemented as: `BuildCache(ctx, logger, metrics)` takes no upstream list.
> An explicit zero size or count selects the default. Validation also requires
> `maxEntrySize` not above half of `maxDiskSize`, and `remote.region` is
> always required. The startup probe is a `Get` of a random key under
> `v1/.probe/`, new at every start so a bucket writer cannot plant it, rather
> than a `Stat`, because a HEAD response has no body to tell a missing bucket
> from a missing object. A not-found 404 passes, a 307, 308, 408 or 429 warns,
> and any other 3xx or 4xx fails startup. A credential-chain failure that can
> pass (a timeout, a send failure, or a provider answering 5xx or 429) warns,
> while a chain that finds no provider or is refused fails startup. With
> `headerTimeout: 0s` the sealed-header read is bounded by `idleTimeout`,
> and the deletions after a push, after a failed verification and after a
> refs upload that a push superseded by one minute.

## Operational notes

- The cache directory and bucket contain repository contents, sealed
  under the cache key. Protect the key as a credential, give the bucket
  no public access, and set a lifecycle rule at `retention` plus a margin
  as garbage collection. Server-side encryption is additional defence.
- Mount the cache volume only into the haybale container; any sidecar
  sharing it runs as the same UID.
- One `remote.prefix` is one trust domain: one upstream per host key and
  one credential scope. Deployments whose host keys point at different
  base URLs must not share a prefix (the `repoHash` already includes the
  base URL, so they would not collide, but they should not share a key).
- Cache entries are shared across every identity policy allows to read a
  repository. Policy, not the cache, decides who may read what.
- `accessRecheck` and coalescing are per instance. Behind a load balancer
  without client affinity, a clone's `ls-refs` and `fetch` may land on
  different replicas; the cost is a lower hit rate (a tier-2 hit or an
  upstream fill instead of a local hit), never a safety loss. Prefer
  client affinity where the balancer offers it.
- A hit does not contact upstream. haybale's own access being revoked
  becomes visible at the next `accessRecheck` boundary, and stale-if-error
  extends reads to `staleIfErrorFor`. After a history rewrite that
  removed a secret, run `haybale cache purge` for the repository.
- Sideband progress text is replayed verbatim to later readers. For
  GitHub it is identity-neutral; an upstream that embeds per-session text
  in progress output would replay it.

## Alternatives considered

- **HTTP-level caching (Varnish, nginx `proxy_cache`).** Git marks every
  response `no-cache`, keys would be raw POST bodies, and no
  general-purpose cache coalesces streaming POST responses. Rejected;
  Varnish's purpose-built git module confirms a body-keyed design.
- **Caching with `have` lines.** Replaying an acknowledgment set is
  valid for the client but has a near-zero hit rate. Rejected.
- **Keying on `Accept-Encoding`.** Requesting identity upstream removes
  encoding from the problem entirely.
- **Serving subscribers only after the fill completes** (singleflight).
  Turns a burst of fifty clones into one transfer and forty-nine waits;
  the spool costs little more and is what Gitaly does.
- **Tee to the leader's client.** Couples fill speed to the slowest
  client and gives the leader different headers from followers; the
  spool-for-everyone model avoids both.
- **Per-identity cache isolation.** Defeats the purpose and adds no
  protection policy does not already provide.
- **Unauthenticated digests for integrity.** Anyone who can rewrite an
  entry can rewrite its digest; only a keyed construction helps.
- **A bare-mirror backend behind the same interface.** A mirror is a
  POSIX filesystem, not a blob; see Decision 1.

## Delivery plan

Three stacked pull requests. Each is independently shippable with the
cache disabled by default, and PR 1 rejects configuration that later PRs
introduce (`remote`, `staleIfErrorFor`) rather than ignoring it, since the
YAML loader is not strict.

1. **Core**: `internal/pktline` (framing reader and streaming scanner,
   fuzzed), `internal/cache` (classification, canonical form, key, sealed
   entry format, tier-1 spool store, fills and subscribers, janitor,
   generation and invalidation, `BlobStore` interface and fill-source
   abstraction with no remote implementation yet), `upstream.ErrUnavailable`,
   proxy `Fetcher` and `WithCache`, shared transport timeouts,
   configuration with `ByteSize`, `BuildCache` and `Close`, metrics,
   `haybale cache purge` (tier 1), documentation, and end-to-end tests
   with real `git` including a fixture with at least forty refs so request
   bodies are gzip-encoded.
2. **Remote tier**: the `s3` backend package, upload workers,
   read-through fill source, `purge --remote`, scrubber patterns, tests
   against an in-process S3-compatible fake, documentation.
3. **Stale-if-error**: eligibility, health gate, `cache_stale_served`,
   `Cache-Status` stale form, documentation of the risk in the security
   model.

## Deferred

- Git over SSH: haybale is HTTPS-only. The canonical form and key would
  carry over to an SSH front end, but SSH support is out of scope.
- Azure Blob Storage and native Google Cloud Storage backends.
- Pre-warming a repository into the cache ahead of a fleet run.
- Caching negotiation rounds that carry `have` lines.
- Tag-aware invalidation of `include-tag` pack entries (would require
  parsing `ls-refs` responses).
- A plain-`http` remote endpoint for in-cluster stores; entries are
  sealed, so the remaining exposure is traffic analysis, but the option
  is withheld until there is demand.
- Case-normalising owner and repository names for case-insensitive
  upstreams (would need the same change in policy matching).
- Admission policies (cache on second sight) if one-off keys are found to
  evict hot entries in practice.
