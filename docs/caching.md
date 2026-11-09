# Response cache

haybale can cache the responses to Git clone and fetch requests on local disk,
so that a fleet of workloads cloning the same repository costs one upstream
pack transfer instead of one per clone. The cache is optional and off by default.
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
  the same stored copy at its own pace. A fill is one upstream fetch whose
  response is being written to the cache;
- keeps every stored entry encrypted and authenticated under a key only haybale
  holds; and
- runs after authentication and policy, so a caller that policy denies learns
  nothing from it.

The cache does not:

- store pushes, or serve anything for a write;
- serve incremental fetches, which send `have` lines and always go upstream;
- serve reads while the upstream is down: stale-if-error is planned, not
  available;
- share entries between haybale processes: each process has its own directory
  and its own copy; or
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
are kept for stale-if-error, which is planned. See [Request
flow](#request-flow).

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
disconnects before the response completes.

If the upstream answers a fill's request with something other than a cacheable
`200`, for example a `404` or `503`, haybale buffers up to 64KiB of that
response and every request waiting on the same fill receives it. A larger error
body, or a failure before response headers, sends the waiting requests straight
to the upstream instead. After any discarded fill except an oversize or generation discard,
requests for the same key go straight to the upstream for one minute.

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
fill reserves its sealed size before it starts: the upstream `Content-Length`
when sent, otherwise `maxEntrySize`, plus a small allowance. Most Git hosts send
packs without a length, so the reservation is usually `maxEntrySize`. Ref
advertisement and `ls-refs` fills do not take a fill slot. They are capped at 64
at a time and reserve 1MiB each. Size the values together:

```text
maxDiskSize  >=  maxConcurrentFills x maxEntrySize  +  64MiB  +  space for stored entries
```

`maxEntrySize` must not exceed half of `maxDiskSize`; `haybale serve` refuses to
start otherwise. With the defaults (4 fills, 1GiB entries, 10GiB budget) fills
reserve at most 4GiB plus 64MiB, leaving the rest for stored entries. Set
`maxEntrySize` to a small multiple of the largest repository clone that should
be cached, and raise `maxDiskSize` to match the formula.

A request that cannot obtain a fill slot or space is proxied without the cache,
so undersizing costs hit rate. One case also affects clients: see [Clients see a
connection closed mid-clone](#clients-see-a-connection-closed-mid-clone) below.
A response with a known `Content-Length` over `maxEntrySize` is delivered to
every request waiting on it when the space can be reserved, and is not stored.
If the space is not free, the requests go straight to the upstream.

Each haybale process needs its own cache directory. Do not mount one volume into
several replicas: a starting process deletes the temporary files of any other
process in the directory.

haybale creates the last element of `cache.dir` with mode `0700` when it is
missing; the parent must exist. An existing directory must be owned by the
haybale user and have mode `0700`, and `haybale serve` refuses to start
otherwise. A freshly mounted volume is usually owned by root with open
permissions, so do not use its mount point as `cache.dir`: mount the volume at a
parent and point `cache.dir` at a subdirectory.

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
affinity where the load balancer offers it.

### Podman and Docker

The published image has no writable parent directory for `cache.dir`. Mount a
writable volume at a parent directory and point `cache.dir` at a child of it, as
in the Kubernetes example. The haybale user (UID 65532) must be able to write to
the volume, and creates the child with mode `0700`.

## Observing the cache

The metrics are described in [`observability.md`](observability.md). To judge the
cache:

- hit rate: `haybale.response_cache.lookups.total` with `result=hit` over all
  lookups of `class=fetch`. Judge the `fetch` class: with the default
  `refsMaxAge`, ref requests are always recorded as misses by design;
- bytes saved: `served_bytes.total` with `tier=disk`, against `fill_bytes.total`,
  which is what the fills fetched from the upstream, including discarded fills
  and refs fills (its `tier` is always `upstream`);
- coalescing: `collapsed.total` counts requests that joined a fill already in
  flight;
- fills that were not stored: `fills.total` with `result=discarded` and its
  `reason`; and
- storage health: `store_errors.total` by `operation`, and the `disk_bytes`
  up/down counter (read it as a gauge) against `maxDiskSize`.

Each `proxied request` log line of a read carries a `cache` field (`hit`,
`miss` or `bypass`), plus `cacheCollapsed` and `cacheStored` on a miss. To see
the result on a single response, enable `exposeStatus` and read its
`Cache-Status` header; the [security model](security.md#cache-status-disclosure)
explains why that is off by default.

### What to alert on

Log lines to alert on, all at Warn unless noted:

- `fill aborted`: a fill could not continue and its clients were released or
  disconnected. Check the `reason` field.
- `entry failed verification; deleting it` and `entry failed mid-stream;
  aborting the response`: a stored entry failed its integrity check. Each is
  accompanied by a `cache_integrity_failed` security event. A single event can
  be disk corruption. Repeated events, or events after nobody changed the key,
  suggest someone is writing to the cache directory.
- `disk store operation failed` and `disk usage exceeds the budget and open
  entries cannot be evicted`: storage trouble.
- `fill panicked` (Error): a bug. Report it with the logged stack.
- `fill failed mid-stream; aborting the response`: the upstream or the disk
  failed after clients had received bytes.
- `response cache did not close cleanly`: shutdown left fills running.

Informational lines to expect, at Info: `response cache enabled` (with `dir`,
`keyMode` and the sizes), the ephemeral-key notice, `removed cache entries sealed
under another key` (at start, after a key change) and `response cache closed`.

Metrics to alert on: any increase of `store_errors.total`; a sustained rate of
`fills.total` with `reason` of `store_error`, `disk_budget` or `encoding`; and
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
  process user.

`purged 0 entries` is reported with exit status 0. It means that nothing is
cached for that repository in this directory (another replica may hold it), that
the key in `keyEnv` is not the key the entries were sealed under, that the host,
owner or repository is spelled differently from what clients send, or that
`--group` excluded the entries that exist. The command cannot tell these apart.

The command fails with an error when the cache is not enabled, when `keyEnv` is
not set in the config (an ephemeral key cannot address entries), when the
variable `keyEnv` names is unset or malformed, when the host is not a configured
upstream, when `--remote` is given (not supported in this release), or when
`--group` is not `refs` or `pack`.

It works while the server runs: the server treats a removed entry as a miss. The
server's disk accounting corrects itself at the next janitor sweep, within about
a minute, so `disk_bytes` lags a purge. Fills already in progress are not
interrupted and can still store an entry afterwards, so run the purge after the
upstream change, and run it again once clones that were in flight have finished
if the content must not be served at all.

Each replica has its own directory, so purge on every replica. On Kubernetes,
run the command inside each pod, where the container already has the key:

```sh
for pod in $(kubectl get pods -l app=haybale -o name); do
  kubectl exec "$pod" -- /usr/local/bin/haybale cache purge \
    --config /etc/haybale/haybale.yaml --repo github.com/acme/widgets
done
```

Rotating the key is a cold cache. At the next start haybale deletes every entry
sealed under the previous key. To remove a repository's entries before then, run
the purge with the previous key still set. `--remote` is rejected: purging a
remote tier is not supported in this release.

## Troubleshooting

### Clones always miss

- Check the `class=fetch` lookups, not the ref requests (see [Observing the
  cache](#observing-the-cache)). Ref requests miss by design while `refsMaxAge`
  is `0s`.
- Look at the `cache` log field. `bypass` means the request was not eligible:
  an incremental fetch, a `want-ref` request, a body over `maxRequestBody`, a
  filter or argument outside the allowlists, or a protocol v2 request without
  the `Git-Protocol` header that Git normally sends. The reason is in the
  debug-level `bypass` log line, so set `logLevel: debug` to see it.
- Repeated `miss` results for the `fetch` class usually mean the clones ask for
  different commits or use different options. A busy branch changes the
  requested commit with each push, and each combination of options is its own
  entry.
- A fill that was discarded marks its key uncacheable for one minute, or for
  `retention` after an oversize or out-of-budget fill, so clones for that key
  miss until the mark expires.
- With several replicas behind a load balancer, each replica has its own cache.

### Hits are rare after a restart

haybale records upstream access in memory. After a restart the first refs
request for a repository renews the record, and pack hits resume. With `keyEnv`
the entries survive the restart. With `refsMaxAge` above `0s`, a surviving refs
entry can delay that renewal by up to `refsMaxAge`.

### Some fills are discarded

The `reason` on `fills.total` says why, and what clients see depends on it:

- `too_large`: the response exceeded `maxEntrySize`. Clients still receive it
  when the space was available. The key goes straight to the upstream for
  `retention`.
- `error_packet`, `sideband_error`, `framing`, `truncated`, `generation`: the
  response was not safe or not valid to store. Clients still receive it.
- `upstream_status`: the upstream answered with something other than a
  cacheable `200`. The waiting requests share that one response, or go to the
  upstream if it was over 64KiB.
- `fetch_error`: a transport failure, a timeout, a failure to obtain a
  credential, or a failure reading an error body. Requests that had not yet
  received bytes go to the upstream directly.
- `encoding`: the upstream answered with a content encoding. The waiting
  requests go to the upstream directly.
- `store_error`: the disk failed. If it failed after the body was fully
  received, clients still receive the response. If it failed before, requests
  that had received bytes lose the connection.
- `disk_budget`: no space could be reserved, so requests go to the upstream
  directly. If space ran out while a response of unknown length was larger than
  `maxEntrySize`, the clients sharing it lose the connection, and the key goes
  straight to the upstream for `retention`.

Keep `maxDiskSize` well above `maxEntrySize`, and size it by the formula in
[Sizing and volumes](#sizing-and-volumes). Most Git hosts send packs without a
length, so the last case is the one to plan for.

### Clients see a connection closed mid-clone

The connection is closed without a clean ending only after bytes were sent: the
upstream failed or went silent mid-response, the disk failed mid-response, space
ran out for a response larger than `maxEntrySize`, or a stored entry failed its
integrity check while it was being read. If the upstream does not send response
headers within `responseHeaderTimeout`, waiting requests are instead sent to the
upstream directly, and clients see only the delay. In both cases, requests for
the same key go straight to the upstream for one minute.

### `haybale serve` refuses to start

The directory is not owned by the process user or grants group or other access
(for example the root of a freshly mounted volume); `keyEnv` names a variable
that is unset or does not hold 32 base64-encoded bytes; `refsMaxAge` is not less
than `accessRecheck`; or `maxEntrySize` exceeds half of `maxDiskSize`. The error
names which.

### A replica serves ref tips from before a push

A push deletes the repository's cached refs entries on the replica that handled
it. Other replicas keep theirs until `refsMaxAge` passes, which matters only
when `refsMaxAge` is above `0s`.

## Limits and roadmap

In this release:

- only `git-upload-pack` reads of the shapes above are cached;
- the cache is local to one process; replicas do not share entries;
- rotating the cache key empties the local cache at the next start;
- stored content can be older than the upstream's by up to `retention`, and
  shallow clones can miss newer annotated tags for the same time; and
- when the upstream is unavailable, requests fail as they do without the cache.

Planned for later releases, and rejected by the configuration until then:

- a shared remote tier in object storage (`cache.remote`), so replicas share
  entries and `haybale cache purge --remote` reaches them; and
- serving a recently stored response when the upstream is unavailable
  (`cache.staleIfErrorFor`), as an explicit operator opt-in.

When haybale shuts down, fills still running after in-flight requests have
drained are cancelled.
