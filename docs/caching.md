# Response cache

haybale can cache the responses to Git clone and fetch requests on local disk,
so that a fleet of workloads cloning the same repository costs one upstream
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
- collapses concurrent identical requests into one upstream fetch: the first
  request starts a fetch, later requests join it, and every one of them is
  served from the same stored copy at its own pace;
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
advertisements and `ls-refs` responses are served from the cache only if they
are younger than `refsMaxAge`, which defaults to `0s`: every clone asks the
upstream for the current refs and only the pack is cached. See [Request
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
   when a valid entry exists; otherwise it joins or starts a fetch.

For each request haybale authenticates the caller, applies policy, reads the
request body and classifies it, and then looks for an entry. On a miss it
fetches from the upstream with the minted credential, writes the response to
disk and serves every waiting client from that copy. The response is stored only
if it completed cleanly, fit within `maxEntrySize` and contained no in-band
error; a response that does not qualify is still delivered to the clients and is
not stored. A push ends with the repository's cached refs entries being deleted.

With the default settings, fifty concurrent clones of one repository cost one
hundred small upstream requests (the advertisement and `ls-refs` of each clone)
and one pack transfer.

To absorb bursts of ref lookups as well, set `refsMaxAge` to a few seconds.
Clients then receive tips up to that old. `refsMaxAge` must be less than
`accessRecheck` (when both are non-zero), because a refs response served from the
cache does not renew the upstream access check that cached packs depend on;
`haybale serve` refuses to start otherwise.

## Sizing and volumes

The cache holds up to `maxDiskSize` of stored entries and in-progress fetches. A
fetch reserves space up front, usually `maxEntrySize` because packs are sent
without a length. Size the three values together:

```text
maxDiskSize  >=  maxConcurrentFills x maxEntrySize  +  space for stored entries
```

With the defaults (4 fills, 1GiB entries, 10GiB budget) fetches reserve at most
4GiB, leaving 6GiB for stored entries. Set `maxEntrySize` to a small multiple of
the largest repository clone that should be cached, and raise `maxDiskSize` to
match the formula. A request that cannot obtain a fetch slot or space is
proxied without the cache, so undersizing costs hit rate and never correctness.

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

With `cache.dir: /var/cache/haybale/data`, `cache.keyEnv: HAYBALE_CACHE_KEY` and
`maxDiskSize: 10GiB` in the config. Create the key once and share it with every
replica, so the Secret holds one value:

```sh
kubectl create secret generic haybale-cache-key \
  --from-literal=key="$(openssl rand -base64 32)"
```

An `emptyDir` is wiped when the pod is rescheduled and the cache refills, so the
key matters for purging (below) more than for persistence. Without a load
balancer that keeps a client on one replica, a clone's `ls-refs` and `fetch` can
reach different replicas; the cost is a lower hit rate, never incorrect results.
Prefer client affinity where the load balancer offers it.

## Observing the cache

The metrics are described in [`observability.md`](observability.md). To judge the
cache:

- hit rate: `haybale.response_cache.lookups.total` with `result=hit` over all
  lookups of `class=fetch`. Judge the `fetch` class: with the default
  `refsMaxAge`, ref requests are always recorded as misses by design;
- bytes saved: `served_bytes.total` with `tier=disk`, against `fill_bytes.total`,
  which is what was fetched from the upstream;
- coalescing: `collapsed.total` counts requests that joined a fetch already in
  flight;
- fetches that were not stored: `fills.total` with `result=discarded` and its
  `reason`; and
- storage health: `store_errors.total` by `operation`, and the `disk_bytes`
  gauge against `maxDiskSize`.

Each `proxied request` log line of a read carries a `cache` field (`hit`,
`miss` or `bypass`), plus `cacheCollapsed` and `cacheStored` on a miss. To see
the result on a single response, enable `exposeStatus` and read its
`Cache-Status` header; the [security model](security.md#cache-status-disclosure)
explains why that is off by default.

## Purging a repository

Retention keeps entries for `retention` (24 hours by default) even if the
upstream has changed. Purge a repository when its history was rewritten to
remove a secret, when it was deleted or transferred, or when an entry is
suspected to be bad:

```sh
haybale cache purge --config /etc/haybale/haybale.yaml \
  --repo github.com/acme/widgets
```

The command prints `purged N entries`. `--group refs` or `--group pack` limits it
to one kind of entry. It needs three things:

- the same `--config` as the server, so it finds `cache.dir` and the upstream;
- the cache key in the environment variable named by `cache.keyEnv`. Entries are
  addressed by a keyed hash of the repository, so only the key they were sealed
  under finds them. A cache without `keyEnv` uses a key nobody can supply, and
  is emptied by restarting haybale instead; and
- the same user as the server, because the directory must be owned by the
  process user.

It works while the server runs: the server treats a removed entry as a miss.
Fills already in progress are not interrupted and can still store an entry
afterwards, so run the purge after the upstream change, and run it again once
clones that were in flight have finished if the content must not be served at
all.

Each replica has its own directory, so purge on every replica. On Kubernetes,
run the command inside each pod, where the container already has the key:

```sh
for pod in $(kubectl get pods -l app=haybale -o name); do
  kubectl exec "$pod" -- /usr/local/bin/haybale cache purge \
    --config /etc/haybale/haybale.yaml --repo github.com/acme/widgets
done
```

The purge command cannot reach entries sealed under a previous key. After a key
rotation, supply the old key once if such entries must go before they expire.
`--remote` is rejected: purging a remote tier is not supported in this release.

## Troubleshooting

**Clones always miss.**

- Check the `class=fetch` lookups, not the ref requests (see [Observing the
  cache](#observing-the-cache)). Ref requests miss by design while `refsMaxAge`
  is `0s`.
- Look at the `cache` log field. `bypass` means the request was not eligible:
  an incremental fetch, a `want-ref` request, a body over `maxRequestBody`, a
  filter or argument outside the allowlists, or a request without the
  `Git-Protocol` header that Git normally sends.
- Repeated `miss` results for the `fetch` class usually mean the clones ask for
  different commits or use different options. A busy branch changes the
  requested commit with each push, and each combination of options is its own
  entry.
- With several replicas behind a load balancer, each replica has its own cache.

**Hits are rare after a restart.** A process records upstream access in memory
and, without `keyEnv`, loses its entries as well. After a restart the first refs
request for a repository renews the record, and `keyEnv` keeps the entries.

**Some fills are discarded.** The `reason` on `fills.total` says why. `too_large`
means the response exceeded `maxEntrySize`; its key then goes straight to the
upstream until `retention` passes or haybale restarts. `disk_budget` means no
space was available after eviction. `error_packet`, `sideband_error`, `framing`
and `truncated` mean the response was not safe to store, and
`fetch_error` and `upstream_status` mean the upstream did not return a
cacheable `200`. Clients still receive the response in every case except
one: a response of unknown length that outgrows the remaining disk budget
while it is being spooled cannot be served to the clients sharing it, and
those clients see the connection closed (below). Keep `maxDiskSize` well
above `maxConcurrentFills` times `maxEntrySize` to avoid that case.

**Clients see a connection closed mid-clone.** The upstream failed or went
silent during a fetch (`responseHeaderTimeout`, `idleTimeout`), so haybale
closed the connection without a clean ending. The client sees an unexpected
disconnect rather than a truncated pack, and retries. Requests for that key go
straight to the upstream for a short time.

**`haybale serve` refuses to start.** The directory is not owned by the process
user or grants group or other access (for example the root of a freshly mounted
volume); `keyEnv` names a variable that is unset or does not hold 32
base64-encoded bytes; or `refsMaxAge` is not less than `accessRecheck`. The error
names which.

**A replica serves ref tips from before a push.** A push deletes the
repository's cached refs entries on the replica that handled it. Other replicas
keep theirs until `refsMaxAge` passes, which matters only when `refsMaxAge` is
above `0s`.

## Limits and roadmap

In this release:

- only `git-upload-pack` reads of the shapes above are cached;
- the cache is local to one process; replicas do not share entries;
- rotating the cache key empties the cache;
- stored content can be older than the upstream's by up to `retention`, and
  shallow clones can miss newer annotated tags for the same time; and
- when the upstream is unavailable, requests fail as they do without the cache.

Planned for later releases, and rejected by the configuration until then:

- a shared remote tier in object storage (`cache.remote`), so replicas share
  entries and `haybale cache purge --remote` reaches them; and
- serving a recently stored response when the upstream is unavailable
  (`cache.staleIfErrorFor`), as an explicit operator opt-in.

When haybale shuts down, fetches still running after in-flight requests have
drained are cancelled.
