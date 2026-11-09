# Response cache

haybale can cache the responses to Git clone and fetch requests on local disk,
and optionally share them between replicas through an S3-compatible bucket, so
that a fleet of workloads cloning the same repository costs one upstream pack
transfer instead of one per clone. The cache is optional and off by default.
This guide explains what it does, how to size and deploy it, and how to operate
it. The field reference is in [`configuration.md`](configuration.md#cache), the
security properties are in [`security.md`](security.md#response-cache), and the
signals it emits are in [`observability.md`](observability.md).

## What the cache does and does not do

The cache:

- stores the upstream's response to a read request and serves it to later
  identical requests, from any identity that policy allows to read the
  repository;
- collapses concurrent identical requests into one fill: the first request
  starts a fill, later requests join it, and every one of them is served from
  the same stored copy at its own pace. A fill is one fetch, from the upstream
  or from the [remote tier](#remote-tier), whose response is being written to
  the cache;
- keeps every stored entry encrypted and authenticated under a key only haybale
  holds; and
- runs after authentication and policy, so a caller that policy denies learns
  nothing from it.

The cache does not:

- store pushes, or serve anything for a write;
- serve incremental fetches, which send `have` lines and always go upstream;
- serve reads while the upstream is down, unless
  [stale-if-error](#serving-through-an-upstream-outage) is enabled, and then only
  repeats of requests it has already stored;
- share entries between haybale processes unless a [remote tier](#remote-tier)
  is configured: each process has its own directory and its own copy; or
- change what clients receive. A cached response is the upstream's own bytes for
  the same request.

## When a request is a hit

A read is a hit when an identical request was answered recently and the stored
entry is still valid. "Identical" means the same repository, the same
`Git-Protocol` header, and the same command with the same arguments, after
haybale removes the client-specific `agent` and `session-id` lines. Clients of
the same Git version and image send identical requests, so a fleet of agents
cloning one commit shares an entry.

haybale caches protocol v2 `ls-refs` and `fetch` requests, and protocol v0 and
v1 upload-pack `want` requests that negotiate side-band. v1 is treated like v0.
A v2 request sent without a `Git-Protocol: version=2` header is not cached.

Consequences worth knowing:

- A `--depth 1` clone and a full clone send different arguments, so they are
  different entries. The same holds for different `--depth` values, filters and
  `--single-branch`.
- A clone asks for specific commits. When the branch advances, the next clone
  asks for a new commit and misses once; the clones after it hit.
- A `git fetch` in an existing clone sends `have` lines and always goes
  upstream. Those requests are small by construction.
- Requests that name refs instead of commits (`want-ref`), use `deepen-not`,
  request `packfile-uris`, use a filter other than `blob:none`,
  `blob:limit=`, `tree:`, `object:type=` or `sparse:oid=`, or carry a body over
  `maxRequestBody` are not cached.
- A request body gzipped by the client is decompressed before it is compared, so
  the large `fetch` bodies that Git compresses are cached like any other.
- Shallow and single-branch clones rely on `include-tag` to receive annotated
  tags that point into the cloned history. A cached response for such a clone
  lacks annotated tags created after the entry was stored, for at most
  `retention`. A full clone asks for every tag by name, so it is not affected.

An entry is served only while it is younger than `retention`. Ref
advertisements and `ls-refs` responses are stored too, but they are served from
the cache only if they are younger than `refsMaxAge`, which defaults to `0s`.
With the default every clone asks the upstream for the current refs, so in
practice only the pack is served from the cache. The refs entries are small and
are kept so that [stale-if-error](#serving-through-an-upstream-outage) can
answer a whole clone during an outage. See [Request flow](#request-flow).

## Request flow

A protocol v2 clone is three requests. With the cache enabled, haybale handles
each as follows:

1. `GET info/refs` returns the capability advertisement. It is stored as a refs
   entry and, with the default `refsMaxAge`, fetched from the upstream every
   time.
2. `POST git-upload-pack` with `command=ls-refs` returns the current ref tips.
   It follows the same refs policy: with the default, it always reaches the
   upstream, so no client sees tips older than its own request. A successful
   response also records that upstream access for the repository is working,
   which keeps cached packs servable (see `accessRecheck` in the
   [security model](security.md#access-recheck)).
3. `POST git-upload-pack` with `command=fetch` returns the pack. This is the
   large transfer and the one the cache exists for. It is served from the cache
   when a valid entry exists; otherwise it joins or starts a fill.

For each request haybale authenticates the caller, applies policy, reads the
request body and classifies it, and then looks for an entry. On a miss it
fetches from the upstream with the minted credential, writes the response to
disk and serves every waiting client from that copy. The response is stored only
if it completed cleanly, fit within `maxEntrySize`, carried no content encoding
and contained no in-band error. A response that does not qualify is not stored,
and in most cases is still delivered to the clients; the exceptions are listed
under [Troubleshooting](#some-fills-are-discarded). A push ends with the
repository's cached refs entries being deleted, even when the pusher
disconnects before the response completes. With a [remote tier](#remote-tier),
a fill first looks for the entry in the bucket and asks the upstream only when
the bucket has no usable copy.

If the upstream answers a fill's request with something other than a cacheable
`200`, for example a `404` or `503`, haybale buffers up to 64KiB of that
response and every request waiting on the same fill receives it. A larger error
body, or a failure before response headers, sends the waiting requests straight
to the upstream instead. After a discarded or aborted fill, requests for the
same key go straight to the upstream for one minute. Two reasons differ: after
an oversize response (`too_large`) the period is `retention`, and a `generation`
discard, or a fill cancelled because every request waiting on it left, marks
nothing. With `staleIfErrorFor` set, an outage-shaped failure is answered from a
stored entry instead when one qualifies, and marks nothing either; see [Serving
through an upstream outage](#serving-through-an-upstream-outage).

With the default settings, fifty concurrent clones of one repository cost one
hundred small upstream requests (the advertisement and `ls-refs` of each clone)
and one pack transfer.

To absorb bursts of ref lookups as well, set `refsMaxAge` to a few seconds.
Clients then receive tips up to that old. `refsMaxAge` must be less than
`accessRecheck` (when both are non-zero), because a refs response served from the
cache does not renew the upstream access check that cached packs depend on;
`haybale serve` refuses to start otherwise.

## Sizing and volumes

The cache holds up to `maxDiskSize` of stored entries and in-progress fills. A
fill reserves its sealed size before it starts. A fill from the bucket reserves
the object's size. A fill from the upstream reserves the upstream
`Content-Length` when sent, otherwise `maxEntrySize`, plus a small allowance.
Most Git hosts send packs without a length, so the reservation is usually
`maxEntrySize`. Ref advertisement and `ls-refs` fills do not take a fill slot.
They are capped at 64 at a time and reserve 1MiB each. Size the values
together:

```text
maxDiskSize  >=  maxConcurrentFills x maxEntrySize  +  64MiB  +  space for stored entries
```

`maxEntrySize` must not exceed half of `maxDiskSize`; `haybale serve` refuses to
start otherwise. With the defaults (4 fills, 1GiB entries, 10GiB budget) fills
reserve at most 4GiB plus 64MiB, leaving the rest for stored entries. Set
`maxEntrySize` to a small multiple of the largest repository clone that should
be cached, and raise `maxDiskSize` to match the formula.

At startup haybale logs a Warn line, `concurrent fills can reserve more than the
disk budget`, with the three values, when `maxConcurrentFills` is greater than
`maxDiskSize` divided by `maxEntrySize`. That is a floor, not the whole formula:
it ignores the 64MiB for ref fills and the space for stored entries, so a
configuration can satisfy it and still be undersized.

A request that cannot obtain a fill slot or space is proxied without the cache,
so undersizing costs hit rate. One case also affects clients: see [Clients see a
connection closed mid-clone](#clients-see-a-connection-closed-mid-clone) below.
A response with a known `Content-Length` over `maxEntrySize` is delivered to
every request waiting on it when the space can be reserved, and is not stored.
If the space is not free, the requests go straight to the upstream.

Each haybale process needs its own cache directory. Do not mount one volume into
several replicas: a starting process deletes the temporary files of any other
process in the directory. Replicas share entries only through a [remote
tier](#remote-tier), never through a shared volume.

haybale creates the last element of `cache.dir` with mode `0700` when it is
missing; the parent must exist. An existing directory must be owned by the
haybale user (where the platform reports ownership) and have no group or other
permission bits, and `haybale serve` refuses to start otherwise. A freshly
mounted volume is usually owned by root with open permissions, so do not use
its mount point as `cache.dir`: mount the volume at a parent and point
`cache.dir` at a subdirectory.

### Kubernetes

Use an `emptyDir` volume per pod with a `sizeLimit` above `maxDiskSize`, so a
full cache can never evict unrelated pods from the node, and deliver the cache
key from a Secret. Mount the volume at `/var/cache/haybale` and set `cache.dir`
to `/var/cache/haybale/data`, which haybale creates with the right owner and
mode:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: haybale
spec:
  replicas: 2
  selector:
    matchLabels: { app: haybale }
  template:
    metadata:
      labels: { app: haybale }
    spec:
      containers:
        - name: haybale
          image: ghcr.io/rxbynerd/haybale:sha-<full-commit-sha>
          args: ["serve", "--config", "/etc/haybale/haybale.yaml"]
          env:
            - name: HAYBALE_CACHE_KEY
              valueFrom:
                secretKeyRef: { name: haybale-cache-key, key: key }
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            allowPrivilegeEscalation: false
          volumeMounts:
            - { name: cache, mountPath: /var/cache/haybale }
            - { name: config, mountPath: /etc/haybale, readOnly: true }
      volumes:
        - name: cache
          emptyDir:
            sizeLimit: 12Gi
        - name: config
          configMap: { name: haybale-config }
```

The image's user is the named `nonroot` (UID 65532), so `runAsUser` must be
numeric for the kubelet to verify `runAsNonRoot`. The cache block in
`haybale.yaml`, which the `haybale-config` ConfigMap holds, points `cache.dir`
at a child of the mounted volume:

```yaml
cache:
  enabled: true
  dir: /var/cache/haybale/data     # a child of the mounted volume
  keyEnv: HAYBALE_CACHE_KEY
  maxDiskSize: 10GiB
```

Create the key once and share it with every replica, so the Secret holds one
value:

```sh
kubectl create secret generic haybale-cache-key \
  --from-literal=key="$(openssl rand -base64 32)"
```

An `emptyDir` is wiped when the pod is rescheduled and survives a container
restart. Entries that survive a restart are read again when the cache key is
unchanged. Without `keyEnv`, or after the key changes, haybale deletes every
entry sealed under another key when it starts. The key therefore matters for
purging (below) more than for persistence. Without a load balancer that keeps a
client on one replica, a clone's `ls-refs` and `fetch` can reach different
replicas; the cost is a lower hit rate, never incorrect results. Prefer client
affinity where the load balancer offers it. To let the replicas share entries,
give each pod its own `emptyDir` as above and configure a [remote
tier](#remote-tier).

### Podman and Docker

The published image has no writable parent directory for `cache.dir`. Mount a
writable volume at a parent directory and point `cache.dir` at a child of it, as
in the Kubernetes example. The haybale user (UID 65532) must be able to write to
the volume, and creates the child with mode `0700`.

## Remote tier

With [`cache.remote`](configuration.md#remote-tier) set, replicas share entries
through a prefix of an S3-compatible bucket. Each replica keeps its own disk
tier, and the bucket is a second tier behind it. All replicas sharing a prefix
must use the same `keyEnv` key, the same upstreams and the same policy: one
prefix is one trust domain, and every replica that can write it can make the
others serve what it stored.

How the two tiers interact:

- After a fill from the upstream stores an entry on disk, the replica uploads
  it in the background. Pack entries are always uploaded. Refs entries are
  uploaded only when `refsMaxAge` or `staleIfErrorFor` is above `0s`, because
  otherwise no replica reads them from the bucket. Four uploads run at a time and up to 256 wait;
  when the queue is full the entry is not uploaded, and `uploads.total` counts
  it with `result=dropped`. A refs entry replaces the bucket's copy, so peers
  see the latest tips. An upload is skipped (`result=skipped`) when the bucket
  already holds the pack, whose content is fixed by its request, when the
  local entry was evicted before its upload ran, or when a push or a purge
  superseded the entry.
- On a disk miss, a replica reads the entry from the bucket before it asks the
  upstream, under the same freshness rules as a disk hit: a pack needs a recent
  upstream refs success on this replica (`accessRecheck`), and a refs entry is
  used only while `refsMaxAge` is above `0s` and the entry is younger than it.
  Requests for the same key join that read as they would join an upstream fill,
  and the entry is stored on this replica's disk too. The request is reported
  as a miss (`fwd=miss` in `Cache-Status`, `cache=miss` with `cacheStored` in
  the request log), and its bytes are counted with `tier=remote`.
- If the bucket has no copy, or the read fails or stalls before the fill starts
  serving it, the same fill asks the upstream at once, with no retry. That
  phase covers the read's response headers, bounded by `headerTimeout`, and
  the entry's 4KiB sealed header, which must arrive within `headerTimeout` of
  the response headers, or within `idleTimeout` when `headerTimeout` is `0s`.
  Stat and read requests make a single attempt, without the AWS SDK's
  retries, so `headerTimeout` is the only bound on them; uploads, deletions
  and listings keep the SDK's default retries.
- Once the fill has started serving the entry, a read that fails, or stalls for
  `idleTimeout`, resumes from where it stopped with a ranged read, up to three
  times, after a pause of 100ms that doubles each time. Each resume checks
  that the object's size, modification time and ETag are unchanged, and when
  the store reports an ETag the ranged read is also conditional on it
  (`If-Match`). An object replaced or deleted in the meantime ends the read at
  once, without further resumes. A read that cannot continue ends the fill
  with `reason=fetch_error`: requests that had received bytes lose the
  connection, and requests that had received nothing go to the upstream
  directly. This is a transport failure, so the object is left in the bucket
  and no security event is logged. A stall inside the entry's first segment,
  after its header arrived, is also handled this way rather than by falling
  through.
- An entry read from the bucket is verified segment by segment with the cache
  key, and each segment is verified before any of its bytes reach a client. A
  failed authentication of the header or of a segment, a missing final
  segment, or bytes after it, is an integrity failure: the entry is deleted
  from the bucket, within `headerTimeout` (one minute when it is `0s`), before
  the fill moves on, and a `cache_integrity_failed` security event is logged
  with `tier=remote`. When the header fails, the same fill asks the upstream.
  When a segment fails, the fill ends with `reason=store_error`: requests that
  had received bytes lose the connection, and requests that had received
  nothing go to the upstream directly. An object truncated in the bucket fails
  this way, because its final segment is missing.
- A remote object whose size cannot be a valid entry, or one past `retention`
  or older than the repository's last purge, is not used, and the fill asks
  the upstream. An expired or purged object is deleted from the bucket in the
  background, each deletion bounded at one minute and at most eight at a
  time; the rest are dropped with a Debug line. Such a deletion can race the
  upload that follows the fill, which then finds the old object and is
  skipped, so the key can stay absent from the bucket until a later miss
  uploads it again.
- A push deletes the repository's refs entries from the bucket before the push
  handler returns, after the local deletion, within one `headerTimeout` (one
  minute when `headerTimeout` is `0s`) across the listing and the deletions.
  It is best effort: a failure is logged as `remote cache tier operation
  failed` with `operation=list` or `operation=delete`, and the push itself is
  unaffected. The Debug line `cache: invalidated remote refs entries after a
  push` is logged only when the listing and every deletion succeeded. The
  replica also records the push time in memory, and does not serve a refs
  entry from the bucket created no later than that time. A refs upload that
  was in flight when the push arrived deletes its object again and counts as
  `skipped`.
- At shutdown, `haybale serve` waits for queued uploads within the same bound it
  gives fills in progress, then abandons the rest and counts them as
  `dropped`. Background deletions and push invalidation that shutdown cuts
  short log no warning and count no store error.

Behind a load balancer without client affinity, a clone's `ls-refs` and `fetch`
can reach different replicas. The `fetch` then misses on the second replica's
disk, and is served from the bucket if that replica has itself seen a recent
refs success for the repository, or from the upstream otherwise.

### Supported stores

| Store | Settings |
|-------|----------|
| AWS S3, general-purpose bucket | `region`; no `endpoint`, except in the China partitions (`https://s3.<region>.amazonaws.com.cn`). |
| AWS S3 Express One Zone directory bucket | `endpoint` set to the zonal endpoint (`https://s3express-<zone id>.<region>.amazonaws.com`); an empty `prefix` or one ending with `/`. Suits replicas in that Availability Zone. |
| Cloudflare R2 | `endpoint: https://<account id>.r2.cloudflarestorage.com`, `region: auto`, no `sse`. R2 charges no egress, which suits replicas spread across clouds. |
| Ceph RGW | `endpoint` set to the gateway URL, `forcePathStyle: true` unless the gateway serves bucket host names, and `region` set to the zonegroup's API name. |
| Google Cloud Storage | The interoperability endpoint, `endpoint: https://storage.googleapis.com`, with an HMAC key supplied as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; `region` set to the bucket's location or `auto`; no `sse`. |

Cloudflare R2, Ceph RGW and Google Cloud Storage are untested in this release:
their rows give the settings those stores document for S3 compatibility. The
MinIO server's community repository is archived, so MinIO is not recommended
for new deployments. An existing MinIO installation works like any
S3-compatible store with `forcePathStyle: true`.

### Sizing the bucket

The bucket holds one copy of each entry any replica stored, until the lifecycle
rule removes it. Its size is roughly the distinct pack entries the fleet creates
within `retention` plus the lifecycle margin; refs entries are kilobytes.
Entries over 5GiB are never uploaded, which the default `maxEntrySize` of 1GiB
already guarantees. Request volume is one read per eligible disk miss, at most
one small read of each repository's purge marker per minute, or per
`accessRecheck` when that is shorter (on an upstream refs request), and one
upload per stored pack entry, plus an existence check first, and per stored
refs entry when `refsMaxAge` is above `0s`. A push costs a listing of the
repository's refs entries and a deletion for each one found.
Every read of the bucket leaves the store's network, so egress pricing matters
when replicas run outside the bucket's region or cloud.

### Bucket hygiene

Keep the bucket private and add a lifecycle rule that expires objects under the
prefix after `retention` plus a margin, for example two days for the default
`24h`. haybale judges an entry's age from the time sealed into it, so the rule
is garbage collection only. Lifecycle expiry is day-granular on AWS S3; other
stores have not been checked. Server-side encryption (`sse`) is optional,
because the entries are already sealed.

Keep the hosts' clocks synchronised, including the host that runs `haybale
cache purge --remote`. A purge compares the purging host's clock with the
creation time each replica sealed into its entries. haybale tolerates a
creation time up to 5 minutes in the future; an entry or purge marker from a
host whose clock runs further ahead fails verification as an integrity
failure. For an entry, that costs one upstream fetch. For a purge marker, it
stops pack hits for that repository on every replica, and the
`cache_integrity_failed` event with `class=purge` repeats, until the clocks
catch up or `purge --remote` is run again from a host with a correct clock
(see [Purging a repository](#purging-a-repository)).

### When the bucket is unavailable

haybale does not track the bucket's health, apart from the marker read backoff
below; every other operation tries the bucket afresh. During an outage:

- each eligible disk miss waits for the bucket before it goes upstream: up to
  `headerTimeout` for the read's response headers, and up to `headerTimeout`
  again (`idleTimeout` when `headerTimeout` is `0s`) for the entry's sealed
  header when the headers arrived;
- an upstream refs fill waits for the repository's purge marker read, at most
  30 seconds, and after a failed read the replica does not read that
  repository's marker again for a minute;
- while marker reads fail, upstream refs responses do not renew the access
  record that pack hits depend on, so pack requests stop hitting, on disk as
  well, within `accessRecheck` and go to the upstream instead, unless
  `accessRecheck` is `0s`, which disables the rule;
- a push's result is unaffected, but the push handler can take up to
  `headerTimeout` (one minute when it is `0s`) longer to return while it tries
  to delete the bucket's refs entries; and
- uploads fail and are counted as `result=failed`.

To shorten the wait on each request, lower `headerTimeout`. `0s` removes the
per-request bound: a disk miss then waits for the read's response headers
until the bucket answers or the connection fails, the entry's sealed header is
bounded by `idleTimeout`, and the deletions a request waits on are bounded at
one minute. Use `0s` only with a store that fails fast.

## Serving through an upstream outage

`cache.staleIfErrorFor` (default `0s`, off) lets haybale answer a read from a
stored entry when the upstream cannot answer it, as long as the entry is no
older than that duration. It is a trade of freshness for availability with a
security cost, described in the [security model](security.md#stale-if-error): a
client can receive content up to `staleIfErrorFor` old, and git gives no sign of
it. Set it only for workloads that are better served by outdated content than
by a failed clone.

A read is answered stale when all of these hold:

- the upstream request failed in a way that only an outage explains:
  - the connection to the upstream failed: name resolution, the TCP connection
    or the TLS handshake;
  - the credential source could not reach its API (for the GitHub App source, a
    network error, its own timeout or a `5xx` from the GitHub API);
  - no response headers arrived within `responseHeaderTimeout`; or
  - the upstream answered `500`, `502`, `503` or `504`;
- an entry for the identical request is stored on this replica's disk or in the
  remote tier, created no more than `staleIfErrorFor` ago and not purged; and
- the request was offered to the cache: a read that the cache declines (see
  [Clones always miss](#clones-always-miss)) takes the passthrough path, which
  never serves stale.

The `accessRecheck` and `refsMaxAge` rules are waived for stale service, since
both exist to make haybale ask the upstream, and the upstream cannot answer.
The disk entry is used when it qualifies; otherwise the remote tier's copy is
read, served and stored on disk like any remote fill. Every request waiting on
the failed fill is served the stale entry rather than the upstream's error
response.

These are never answered stale and fail as they do without the setting:

- `401` and `403` from the upstream, including a `403` that signals rate
  limiting: haybale's credential was rejected, and the client still receives
  `502`;
- `404`, `429` and every other `4xx`, which the client receives as the upstream
  sent them;
- a credential source that refuses to mint: a bad key, a suspended or removed
  installation, a repository outside the installation, or rate limiting;
- any other error, such as a connection reset after the request was sent;
- every push; and
- a request with no stored entry, or only one older than `staleIfErrorFor`.

A stale response carries `Cache-Status: haybale; hit; fwd=stale;
fwd-status=503` when `exposeStatus` is on, where `fwd-status` is the upstream's
status and is left out when no response arrived. The request log records
`cache=stale`, `lookups.total` counts it with `result=stale`, and
`served_bytes.total` counts its bytes under the tier it came from. Every stale
response also logs a `cache_stale_served` security event at warning level,
described in [`observability.md`](observability.md#logs).

### What an outage clone can do

Stale service replays stored responses to byte-identical repeat requests; it
never assembles a response from other entries. A clone during an outage
therefore succeeds only if the same clone, with the same tips and the same
options, went through this replica, or a replica sharing the remote tier, within
`staleIfErrorFor`. In particular:

- a clone with a different `--depth`, filter or branch selection is a different
  request, and fails;
- `git fetch` in an existing clone sends `have` lines, which are never cached,
  and fails;
- the stored ref advertisement and `ls-refs` response can name tips for which no
  pack is stored, for example after another replica's incremental fetch
  refreshed the remote tier's `ls-refs` entry. That clone then fails at its
  fetch step, as it would without the cache; and
- the stale tips are the ones stored, so the clone lacks every commit pushed
  since, including security fixes.

### Health gate

While stale-if-error is enabled, haybale keeps a health gate per upstream host so
that an outage does not make every request wait out a connection timeout first.
The gate opens when a request cannot connect to the upstream or the credential
source reports its API unavailable. A `5xx` response or a response-header
timeout never opens it: one repository can be slow or failing while the host is
healthy, and a client can provoke those for its own requests.

While the gate is open:

- a request with a qualifying stored entry is answered from it at once, without
  contacting the upstream;
- a request without one still goes to the upstream, since nothing else can answer
  it; and
- one request at a time goes to the upstream as a probe, at most once every 5
  seconds. A failed probe is answered stale like any other request.

Any upstream answer other than `500`, `502`, `503` or `504` closes the gate.
Probes ride on client requests, so with no traffic the gate stays open until the
next request finds the upstream reachable. Opening and closing are logged at Info
with the `host`: `upstream health gate opened; stale entries answer requests
without contacting upstream` and `upstream health gate closed`.

## Observing the cache

The metrics are described in [`observability.md`](observability.md). To judge the
cache:

- hit rate: `haybale.response_cache.lookups.total` with `result=hit` over all
  lookups of `class=fetch`. Judge the `fetch` class: with the default
  `refsMaxAge`, ref requests are always recorded as misses by design;
- bytes saved: `served_bytes.total` with `tier=disk`, against `fill_bytes.total`
  with `tier=upstream`, which is what the fills fetched from the upstream,
  including discarded fills and refs fills. With a remote tier,
  `fill_bytes.total` and `served_bytes.total` with `tier=remote` count what
  replicas read from the bucket instead of the upstream;
- load on the upstream: `fills.total` with `tier=upstream` counts the fills
  that fetched from the upstream, and `fill_bytes.total` with `tier=upstream`
  the bytes they read. A fill that tried the bucket and fell through to the
  upstream counts once, as an upstream fill. Add the `bypass` results of
  `lookups.total`, which go straight to the upstream;
- uploads to the remote tier: `uploads.total` by `result`;
- coalescing: `collapsed.total` counts requests that joined a fill already in
  flight;
- fills that were not stored: `fills.total` with `result=discarded` and its
  `reason`; and
- storage health: `store_errors.total` by `tier` and `operation`, and the
  `disk_bytes` up/down counter (read it as a gauge) against `maxDiskSize`.

Each `proxied request` log line of a read carries a `cache` field (`hit`,
`miss`, `stale` or `bypass`), plus `cacheCollapsed` and `cacheStored` on a
miss. To see the result on a single response, enable `exposeStatus` and read
its `Cache-Status` header; the [security
model](security.md#cache-status-disclosure) explains why that is off by
default.

### What to alert on

Log lines to alert on, all at Warn unless noted:

- `fill aborted`: a fill could not continue and its clients were released or
  disconnected. Check the `reason` field.
- the `cache_integrity_failed` security event: a stored entry or purge marker
  failed its integrity check. The accompanying `entry failed verification;
  deleting it` line, or `remote entry failed verification; deleting it` for an
  entry read from the bucket, is logged at Debug, so alert on the event. An
  entry that fails is deleted. A purge marker that fails (`class=purge`,
  `tier=remote`) is not deleted: pack hits for that repository stop on every
  replica within `accessRecheck` (unless `accessRecheck` is `0s`, which
  disables the rule), and each replica logs the event again about every
  minute while it receives refs requests for the repository, until `haybale
  cache purge --remote` replaces the marker. A single event can be disk
  corruption or a host clock running more than 5 minutes ahead.
  Repeated events, or events after nobody changed the key, suggest someone is
  writing to the cache directory or the bucket.
- `entry failed mid-stream; aborting the response`: a stored entry failed while
  it was being sent, after the client had received bytes, so that response was
  cut short. The `cache_integrity_failed` event accompanies it only when the
  failure was an integrity failure.
- `entry could not be read; deleting it`: a stored entry could not be read for a
  reason other than failing its integrity check, so there is no security event.
  The entry is deleted and counted in `store_errors.total` with
  `operation=open`.
- `entry could not be committed`: a finished response could not be stored.
  Clients still received it.
- `disk store operation failed` and `disk usage exceeds the budget and open
  entries cannot be evicted`: storage trouble.
- `fill panicked` and `flush panicked` (both Error): a bug. Report it with the
  logged stack.
- `fill failed mid-stream; aborting the response`: the upstream or the disk
  failed after clients had received bytes.
- `invalidating refs entries after a push failed`: the push's cached refs
  entries could not be deleted. With `refsMaxAge` above `0s`, later reads can
  receive the tips from before the push until the entries expire.
- `response cache did not close cleanly`: shutdown left fills running or
  uploads pending.
- `remote cache tier operation failed`: a read, upload, existence check,
  listing or deletion against the bucket failed. The `operation` field names
  it. For a failed request the `error` field carries the operation, the S3
  error code and the HTTP status, never the SDK's message. For a read whose
  body failed mid-stream it carries the network error, which can name the
  local and remote addresses.
- `cache.remote: the startup probe of the bucket failed; continuing, and remote
  operations retry on use`: the bucket could not be reached at startup.
- the `cache_stale_served` security event: a read was answered from a stale
  entry because the upstream could not answer. Alert on any occurrence where
  `staleIfErrorFor` is set; its `reason` field tells an outage (`connect`,
  `credential_unavailable`, `health_gate`) from a failing repository
  (`upstream_status`, `header_timeout`).

Lines of lower value, all at Warn except where noted:

- `request could not be classified`: the request body could not be read or
  classified, so the request was proxied without the cache;
- `removing cache entries sealed under another key failed`: the start-up cleanup
  after a key change did not finish;
- `ignoring a non-regular file at an entry path`: something other than a regular
  file sits where an entry belongs, and haybale leaves it alone;
- `subscribers did not open the spool in time; releasing it`: a discarded fill's
  temporary file was released after a grace period although a waiting request
  had not yet opened it;
- `set entry modification time`: a stored entry's file time could not be set.
  Freshness does not depend on it;
- `janitor not started: interval and retention must be positive` (Error): the
  cache runs without its periodic cleanup; and
- `remote entry size is out of range; fetching upstream` (Debug only): a
  bucket object's size cannot be a valid entry, so it was not read. Something
  other than haybale may be writing to the prefix.

Informational lines to expect, at Info, in start-up order: the ephemeral-key
notice (when `keyEnv` is unset), `removed cache entries sealed under another key`
(after a key change), `response cache enabled` (with `dir`, `keyMode` and the
sizes and `staleIfErrorFor`) and `response cache remote tier enabled` (with the
type, bucket, prefix, region and endpoint); `cache: removed entries older than
the repository's purge marker` on every replica that reads a purge marker newer
than the purges it already knew, including the server on the host where the
purge command ran, and with `entries=0` when it had nothing to remove; the
[health gate](#health-gate) opening and closing; and `response cache closed` at
shutdown.

Metrics to alert on: any increase of `store_errors.total`; a sustained rate of
`fills.total` with `reason` of `store_error`, `disk_budget` or `encoding`;
`uploads.total` with `result` of `failed` or `dropped`; and
`lookups.total` bypass rates that rise without a change in traffic. Bypass
reasons appear only in the debug-level `bypass` log line (see [Clones always
miss](#clones-always-miss)).

## Purging a repository

Retention keeps entries for `retention` (24 hours by default) even if the
upstream has changed. Purge a repository when its history was rewritten to
remove a secret, when it was deleted or transferred, or when an entry is
suspected to be bad:

```sh
haybale cache purge --config /etc/haybale/haybale.yaml \
  --repo github.com/acme/widgets
```

`--repo` is `HOST/OWNER/REPO`. The host must match an upstream `host` key in the
config. Owner and repository names are case-sensitive, because entries are
addressed by a keyed hash of the exact names. `--group refs` or `--group pack`
limits the purge to one kind of entry.

The command prints `purged N entries` (`purged 1 entry` for a single one). It
needs three things:

- the same `--config` as the server. The command loads the whole config the way
  `haybale serve` does, so every file and environment variable the config names
  must be readable: the TLS certificate and key files, the policy file, any
  GitHub App private key file, and the environment variable named by every
  upstream's `tokenEnv`, as well as `cache.keyEnv`. `haybale policy check` has
  the same requirement;
- the cache key in the environment variable named by `cache.keyEnv`. Entries are
  addressed by a keyed hash of the repository, so only the key they were sealed
  under finds them. A cache without `keyEnv` uses a key nobody can supply, so the
  command cannot address its entries, and restarting haybale deletes them
  instead; and
- the same user as the server, because the directory must be owned by the
  process user. With `--remote` and no local directory, the local step is
  skipped instead.

`purged 0 entries` is reported with exit status 0. It means that nothing is
cached for that repository in this directory (another replica may hold it), that
the key in `keyEnv` is not the key the entries were sealed under, that the host,
owner or repository is spelled differently from what clients send, that the
upstream's `baseURL` is not the one the entries were stored under (it is part
of the keyed hash), or that `--group` excluded the entries that exist. The
command cannot tell these apart.

The command fails with an error when the cache is not enabled, when `keyEnv` is
not set in the config (an ephemeral key cannot address entries), when the
variable `keyEnv` names is unset or malformed, when the host is not a configured
upstream, when `--remote` is given without a `cache.remote` block, or when
`--group` is not `refs` or `pack`.

It works while the server runs: the server treats a removed entry as a miss. The
server's disk accounting corrects itself at the next janitor sweep, within about
a minute, so `disk_bytes` lags a purge. Fills already in progress are not
interrupted and can still store an entry afterwards, so run the purge after the
upstream change, and run it again once clones that were in flight have finished
if the content must not be served at all.

With a remote tier, add `--remote`:

```sh
haybale cache purge --config /etc/haybale/haybale.yaml \
  --repo github.com/acme/widgets --remote
```

The command then works in this order, printing a line as each step finishes:

1. It records the purge in the repository's purge marker in the bucket
   (`v1/purge/<repoHash>` under the prefix).
2. It deletes the repository's entries from the bucket and prints `wrote the
   purge marker and purged N entries from the remote tier`.
3. It deletes the entries in this host's `cache.dir` and prints `purged N
   entries`. With `--remote`, a `cache.dir` that does not exist is skipped with
   `notice: cache.dir "..." does not exist; there are no local entries to
   purge` on stderr, so the command can run on a host with no local cache.
   Other directory errors, such as the wrong owner, still fail the command.

It needs the bucket credentials as well, and the whole run is bounded at five
minutes. If the marker cannot be written, the command deletes nothing and exits
with status 1, printing `Error: --remote: write the purge marker (nothing was
deleted): ...`. If a deletion from the bucket fails, the command still runs the
local step, then exits with status 1, printing `Error: --remote: the purge
marker was written, but purging the remote tier failed (N entries deleted so
far): ...`. If deleting the local entries fails, with or without `--remote`,
the command exits with status 1, printing `Error: purge <group> entries (N
entries purged so far): ...`, where `<group>` is `refs` or `pack`. Running the
command again is safe in every case.

An existing marker that fails verification, for example one sealed under
another key or by a host whose clock ran ahead, is replaced, with `notice: the
repository's purge marker failed verification and was replaced` on stderr. The
replacement records only the groups purged now, so the other group's earlier
purge time is lost for every replica that had not already read it. When the
purge that printed the notice used `--group`, run it again without `--group`,
so both groups are purged. This applies at any `refsMaxAge`.

The marker is sealed under the cache key and records the purge time of each
group. A replica checks it alongside an upstream refs request for the
repository, and drops its local entries created before the purge time; until
then those entries are still served. Because a pack hit needs a recent refs
success, a replica that reads the marker on a clone's `ls-refs` also misses that
clone's `fetch`. A successful check, which finds the marker or confirms there
is none, stays current for a minute (or for `accessRecheck` when that is
shorter), and concurrent refs requests for the repository share one read. A
replica therefore honours a purge within about a minute plus its next upstream
refs request for the repository. A check that fails, because the read fails,
times out after 30 seconds, or finds a marker that fails verification, is not
retried for a minute, so a replica whose checks are failing honours a purge
up to that minute later. A failed check does not renew the access record that
pack hits depend on, so the replica's pack hits for the repository lapse
within `accessRecheck` and go to the upstream until a check succeeds, unless
`accessRecheck` is `0s`, which disables the rule. With `refsMaxAge` above
`0s`, a refs hit does not read the marker, so cached refs entries can be
served for up to `refsMaxAge` after the purge.

Without `--remote`, the command reaches only this host's directory. When
`cache.remote` is configured, it then prints `warning: cache.remote is
configured but --remote was not given: replicas will refill the purged entries
from the bucket; use --remote to purge the shared tier` on stderr. The bucket
still holds the entries, but the command exits with status 0 when the local
purge succeeds.

Without a remote tier each replica has its own directory, so purge on every
replica. On Kubernetes, run the command inside each pod, where the container
already has the key:

```sh
for pod in $(kubectl get pods -l app=haybale -o name); do
  kubectl exec "$pod" -- /usr/local/bin/haybale cache purge \
    --config /etc/haybale/haybale.yaml --repo github.com/acme/widgets
done
```

Rotating the key is a cold cache. At the next start haybale deletes every entry
sealed under the previous key. To remove a repository's entries before then, run
the purge with the previous key still set. In the bucket, entries under the
previous key are addressed by different names, are never read again, and age
out through the lifecycle rule.

## Troubleshooting

### Clones always miss

- Check the `class=fetch` lookups, not the ref requests (see [Observing the
  cache](#observing-the-cache)). Ref requests miss by design while `refsMaxAge`
  is `0s`.
- Look at the `cache` log field. `bypass` means the cache did not serve the
  request. The reason is in the debug-level `bypass` log line, so set
  `logLevel: debug` to see it. A request can be ineligible: an incremental
  fetch, a `want-ref` request, a body over `maxRequestBody`, a filter or
  argument outside the allowlists, or a protocol v2 request without the
  `Git-Protocol` header that Git normally sends. In the logs and metrics such a
  request has `class=bypass`, because it could not be classified. That includes
  a request that found none of the 128 classification slots free
  (`body_budget`). A request that was classified but not served has its real
  class and one of these reasons:
  - `uncacheable`: the key was marked after a discarded fill and the mark has
    not expired. An upstream `401` that haybale turned into a `502` is one
    example;
  - `no_slot`: every fill slot was busy (`maxConcurrentFills` for packs, 64 for
    refs);
  - `stale_fill`: with `refsMaxAge` above `0s`, a push finished after the refs
    fill that is in flight began, so its response might carry the tips from
    before the push and the request is proxied instead of joining it; and
  - `verification`: a freshly stored entry failed its integrity check, so the
    request was proxied instead.
- Repeated `miss` results for the `fetch` class usually mean the clones ask for
  different commits or use different options. A busy branch changes the
  requested commit with each push, and each combination of options is its own
  entry.
- A fill that was discarded marks its key uncacheable for one minute, or for
  `retention` after an oversize response (`too_large`), so clones for that key
  miss until the mark expires.
- With several replicas behind a load balancer, each replica has its own cache
  unless they share a [remote tier](#remote-tier). With a remote tier, check
  `uploads.total` for `failed` or `dropped` results and `store_errors.total`
  with `tier=remote`. Pack requests also stop hitting, on disk as well, while
  a replica's purge marker checks fail: see [When the bucket is
  unavailable](#when-the-bucket-is-unavailable), and a `cache_integrity_failed`
  event with `class=purge` for a marker that fails verification.

### Hits are rare after a restart

haybale records upstream access in memory. After a restart the first refs
request for a repository renews the record, and pack hits resume. With `keyEnv`
the entries survive the restart. With `refsMaxAge` above `0s`, a surviving refs
entry can delay that renewal by up to `refsMaxAge`.

### Some fills are discarded

The `reason` on `fills.total` says why, and what clients see depends on it:

- `too_large`: the response exceeded `maxEntrySize`. Clients still receive it
  when the space was available. If the response outgrew `maxEntrySize` while
  streaming and the free disk budget cannot hold the rest, the fill aborts and
  clients that had received bytes lose the connection. In every case the key
  goes straight to the upstream for `retention`.
- `error_packet`, `sideband_error`, `framing`, `truncated`: the response was not
  safe or not valid to store. Clients still receive it.
- `generation`: a push finished while a refs fill was in flight, so its response
  might carry the tips from before the push and is not kept. Clients still
  receive it, and the key is not marked.
- `upstream_status`: the upstream answered with something other than a
  cacheable `200`. The waiting requests share that one response, or go to the
  upstream if it was over 64KiB.
- `fetch_error`: a transport failure, a timeout, a failure to obtain a
  credential, a failure reading an error body, or a read from the remote tier
  that could not continue after three resumes or whose object was replaced or
  deleted during the read. Requests that had not yet received bytes go to the
  upstream directly. If the failure comes mid-response, clients that had
  received bytes lose the connection.
- `encoding`: the upstream answered with a content encoding. The waiting
  requests go to the upstream directly.
- `store_error`: the disk failed, the fill panicked, or an entry read from the
  remote tier failed verification. If the entry could not be committed after
  the whole body was received and sealed, clients still
  receive the response. If the disk failed earlier, including while writing the
  entry's trailer, requests that had received bytes lose the connection, and
  requests that had not go to the upstream directly.
- `disk_budget`: no space could be reserved, so requests go to the upstream
  directly. If more space cannot be reserved while a response within
  `maxEntrySize` is still arriving (a ref advertisement beyond its 1MiB
  reservation, or a body longer than its `Content-Length`), the fill aborts and
  clients that had received bytes lose the connection.

Except where noted above, each of these marks the key for one minute.

Keep `maxDiskSize` well above `maxEntrySize`, and size it by the formula in
[Sizing and volumes](#sizing-and-volumes). Most Git hosts send packs without a
length, so a pack that outgrows `maxEntrySize` while the budget is full (the
`too_large` abort) is the case to plan for.

### Clients see a connection closed mid-clone

The connection is closed without a clean ending only after bytes were sent: the
upstream failed or went silent mid-response, the disk failed or its budget ran
out mid-response (including a response that outgrew `maxEntrySize` with no free
budget left), a stored entry failed its integrity check while it was being
read, or a read from the remote tier failed after three resumes, found its
object replaced or deleted, or failed its integrity check. If the upstream does
not send response headers within `responseHeaderTimeout`, waiting requests are
instead sent to the upstream directly, and clients see only the delay. After a
failed fill, requests for the same key go straight to the upstream for one
minute, or for `retention` after an oversize response.

### `haybale serve` refuses to start

The directory is not owned by the process user or grants group or other access
(for example the root of a freshly mounted volume); `keyEnv` names a variable
that is unset or does not hold 32 base64-encoded bytes; `refsMaxAge` is not less
than `accessRecheck`; `maxEntrySize` exceeds half of `maxDiskSize`; or the
startup probe of the remote tier failed in a way that will not resolve itself,
such as missing credentials, a certificate that does not verify, a redirect or
an authorization or bucket error; or `AWS_CA_BUNDLE`, a profile `ca_bundle` or
an `AWS_PROFILE` naming a missing profile stopped the S3 client from being
built. The error names which; for the remote tier it is printed on stderr after
`Error: build cache: `, and [Remote tier](configuration.md#remote-tier) in the
configuration reference lists the messages.

### A replica serves ref tips from before a push

A push deletes the repository's cached refs entries on the replica that handled
it, and then in the remote tier, best effort. Other replicas keep their local
copies until `refsMaxAge` passes, which matters only when `refsMaxAge` is above
`0s`. If the deletion from the bucket fails (`remote cache tier operation
failed` with `operation=list` or `operation=delete`), pre-push refs entries can
stay in the bucket for up to `refsMaxAge`. The replica that handled the push
never serves them, because it remembers the push time, but other replicas can
read them from the bucket, and so can the same replica after a restart, which
forgets the push time.

Pre-push refs entries can also reach the bucket, or be served from it, when
the deletion succeeds:

- Another replica's refs upload that was queued before the push still runs,
  because that replica did not see the push. It can land after the pushing
  replica's deletion, and every replica except the pushing one can then serve
  it from the bucket until it is older than `refsMaxAge`.
- The push time is the pushing replica's wall-clock time, and an entry's
  creation time is the clock of the replica that sealed it. A replica whose
  clock runs a few seconds ahead, within the 5-minute tolerance, can seal an
  entry fetched before the push with a creation time after the push time, and
  the pushing replica then serves it from the bucket too.
- A refs upload that a push superseded deletes its object again. That
  deletion can remove another replica's newer object at the same key, which
  costs only a miss. If shutdown cuts the deletion short and the replica
  restarts, the pre-push object stays, and the restarted replica, which has
  forgotten the push time, can serve it until it is older than `refsMaxAge`.

None of these cases arise at the default `refsMaxAge` of `0s`, because refs
entries are then neither uploaded nor read from the bucket.

## Limits and roadmap

In this release:

- only `git-upload-pack` reads of the shapes above are cached;
- replicas share entries only through an S3-compatible remote tier; Azure Blob
  Storage and native Google Cloud Storage are not supported;
- rotating the cache key empties the local cache at the next start, and leaves
  the remote tier's entries unreadable until the lifecycle rule removes them;
- stored content can be older than the upstream's by up to `retention`, and
  shallow clones can miss newer annotated tags for the same time; and
- when the upstream is unavailable, requests fail as they do without the cache,
  unless `staleIfErrorFor` is set; then only repeats of stored requests succeed,
  as [Serving through an upstream outage](#serving-through-an-upstream-outage)
  describes.

When haybale shuts down, fills still running after in-flight requests have
drained are cancelled.
