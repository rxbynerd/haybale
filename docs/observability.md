# Observability

haybale exports OpenTelemetry traces, metrics, and logs over OTLP when the
`telemetry` block is configured (see [`configuration.md`](configuration.md)
for how to turn it on and point it at a collector). This document describes
what the enabled pipeline emits. When telemetry is disabled, these signals are
not produced, metric instruments are no-ops, and no exporter is dialled.

All three signals share one OTel Resource, so a backend can correlate them
for a single running process:

| Attribute                | Value                                                         |
|--------------------------|---------------------------------------------------------------|
| `service.name`           | `haybale`                                                     |
| `service.version`        | the build version (`haybale version`)                         |
| `service.instance.id`    | a random 128-bit id, stable for the process lifetime          |
| `service.namespace`      | `telemetry.serviceNamespace` (default `haybale`)              |
| `deployment.environment` | `telemetry.environment` (default `local`)                     |

The instrumentation scope for every signal is `github.com/rxbynerd/haybale`.

## Traces

Each proxied request is a server span (created by the standard `otelhttp`
instrumentation), enriched by haybale with its own view of the request as it
resolves. Health-check probes (`GET /healthz`) are filtered out so they do
not flood the backend.

Span attributes haybale adds:

| Attribute                  | Notes                                                      |
|----------------------------|-------------------------------------------------------------|
| `haybale.host`             | The upstream host key (only once resolved to a configured upstream). |
| `haybale.verb`             | `read` or `write`.                                          |
| `haybale.repo.owner`       | Repository owner. On the span only, never a metric label.  |
| `haybale.repo.name`        | Repository name. On the span only, never a metric label.   |
| `haybale.identity`         | The authenticated identity ID.                             |
| `haybale.issuer`           | The verified JWT issuer, when available.                   |
| `haybale.outcome`          | One of the outcomes listed under [Metrics](#metrics).      |
| `http.response.status_code`| The client-visible status of a proxied request.            |
| `haybale.cache.result`     | `hit`, `miss` or `bypass`, on every read the cache was offered. `stale` is reserved and not emitted. |
| `haybale.cache.collapsed`  | `true` when the request joined a fill already in flight. Present on a miss only. |
| `haybale.cache.stored`     | `true` when the fill committed an entry. Present on a miss only. |

The request span carries these cache attributes. The response cache does not
emit its own lookup or fill spans. The upstream request a fill makes appears as
a root client span, because the fill outlives the request that started it.

Token minting produces a child span, `haybale.mint`, covering the GitHub App
installation lookup and the token POST; each of those two API calls is a
further client span. The span carries `haybale.host/verb/repo.*` and, on
success, the non-secret `haybale.installation_id`. **The minted token itself
never appears on a span, a metric, a log, or an error.**

### Trace propagation

haybale **continues** an inbound trace: a caller that sends a W3C
`traceparent` has haybale's request span nested under its trace.

haybale does **not inject its own** trace context onto the upstream leg: the
reverse-proxy transport uses an empty propagator, so it adds no
`traceparent`, `tracestate`, or `baggage` to requests sent to the Git host.
Client-supplied end-to-end headers remain subject to normal reverse-proxy
forwarding. GitHub API calls made by the credential source also receive no
haybale trace context.

## Metrics

All metric attributes are deliberately **low-cardinality**. `host` is
bounded by the number of configured upstreams and `verb` is `read`/`write`;
`outcome` and `result` are small closed sets. High-cardinality per-request
values (repo owner/name, identity) are **never** metric labels — they would
explode series cardinality on a backend like Mimir — and appear only on
spans.

| Instrument                          | Type              | Attributes                        | Meaning                                                    |
|-------------------------------------|-------------------|-----------------------------------|-------------------------------------------------------------|
| `haybale.requests.total`            | counter           | `host`, `verb`, `outcome`, `status` | Every terminal request outcome. `status` is present on proxied requests. |
| `haybale.request.duration`          | histogram (s)     | `host`, `verb`, `outcome`         | Proxied-request wall-clock latency.                        |
| `haybale.request.bytes_in`          | histogram (bytes) | `host`, `verb`                    | Inbound request-body bytes streamed through.               |
| `haybale.request.bytes_out`         | histogram (bytes) | `host`, `verb`                    | Outbound response bytes streamed through.                  |
| `haybale.requests.in_flight`        | up/down counter   | `host`, `verb`                    | Requests currently being proxied — a live saturation gauge.|
| `haybale.tokens.minted.total`       | counter           | `host`, `verb`                    | GitHub App installation tokens minted (one per real mint). |
| `haybale.token_cache.lookups.total` | counter           | `host`, `verb`, `result`          | Token-cache lookups; `result` is `hit` or `miss`.          |

The response-cache instruments below are always defined and record data only
when the [`cache` block](configuration.md#cache) is enabled. They all use the
`haybale.response_cache.` prefix, which keeps them distinct from the token
cache's `haybale.token_cache.` instruments. Like every other metric they never
carry a repository owner or name.

| Instrument                                    | Type            | Attributes                         | Meaning                                                                 |
|-----------------------------------------------|-----------------|------------------------------------|-------------------------------------------------------------------------|
| `haybale.response_cache.lookups.total`        | counter         | `host`, `class`, `result`          | Response-cache lookups; `result` is `hit`, `miss` or `bypass`. `stale` is reserved: not emitted while `staleIfErrorFor` is unsupported. |
| `haybale.response_cache.fills.total`          | counter         | `host`, `class`, `result`, `reason`| Finished cache fills; `result` is `stored` or `discarded`. `reason` is present only on a discarded fill. |
| `haybale.response_cache.fill_bytes.total`     | counter         | `host`, `class`, `tier`            | Bytes fetched from the upstream by fills, including fills that were discarded and refs fills. `tier` is always `upstream`. |
| `haybale.response_cache.served_bytes.total`   | counter         | `host`, `class`, `tier`            | Response bytes served to clients through the cache path.                |
| `haybale.response_cache.collapsed.total`      | counter         | `host`                             | Requests that joined a fill already in flight instead of fetching upstream. |
| `haybale.response_cache.store_errors.total`   | counter         | `tier`, `operation`                | Cache storage failures.                                                 |
| `haybale.response_cache.evictions.total`      | counter         | (none)                             | Entries evicted to stay within the disk budget or retention.            |
| `haybale.response_cache.uploads.total`        | counter         | `result`                           | Reserved: not emitted while the remote tier is unsupported.             |
| `haybale.response_cache.disk_bytes`           | up/down counter | (none)                             | Bytes currently held by the disk tier: committed entries plus bytes pinned by readers of removed entries. Space reserved for fills in progress is not counted, so the gauge can sit below the `maxDiskSize` budget the cache enforces. |

The `class` attribute is the request class the cache recognised
(`advertisement`, `ls-refs`, `fetch`, or `bypass`). `bypass` is used for
requests the cache did not classify. The other closed sets are:

| Attribute | Values |
|-----------|--------|
| `result` on `lookups.total` | `hit`, `miss`, `bypass`; `stale` is reserved and not emitted |
| `result` on `fills.total` | `stored`, `discarded` |
| `reason` on `fills.total` | `error_packet`, `sideband_error`, `framing`, `truncated`, `too_large`, `disk_budget`, `store_error`, `generation`, `upstream_status`, `fetch_error`, `encoding` |
| `tier` | `disk`, `upstream` (the origin of the bytes; `fill_bytes.total` is always `upstream`); `remote` is reserved and not emitted while the remote tier is unsupported. On `store_errors.total` it names the tier that failed. |
| `operation` on `store_errors.total` | `open`, `create`, `write`, `commit`, `abort`, `delete`, `evict`, `expire`, `sweep` |

A cache hit keeps `outcome=proxied` on `haybale.requests.total` and
`haybale.request.duration`, so existing dashboards and SLOs include hits.
Because `proxied` no longer implies an upstream transfer, panels that track
load on the upstream host should use `fills.total` and `fill_bytes.total` (one
fill is one upstream fetch, however many clients it served) together with the
`bypass` results of `lookups.total`, which are proxied straight to the
upstream.

The `haybale.outcome` values, spanning every terminal path a request can
take, so `sum by (haybale.outcome)` accounts for all traffic:

| Outcome               | HTTP status | Meaning                                                                       |
|-----------------------|-------------|-------------------------------------------------------------------------------|
| `proxied`             | (upstream's)| Authenticated, authorized, and answered on the client's behalf: streamed from the upstream or served from the response cache. |
| `rejected`            | 404         | Malformed request or unknown upstream host — before any auth check.           |
| `authn_failed`        | 401         | The authenticator rejected the credential.                                    |
| `policy_denied`       | 404         | The policy engine denied the request (indistinguishable from a missing repo). |
| `upstream_auth_failed`| 502         | A credential source was unavailable or failed before forwarding.              |

An upstream `401` or `403` rewritten by haybale to `502` has outcome `proxied`
and status `502`, because the request was answered on the client's behalf. It also emits an
`upstream_auth_failed` security event.

A `rejected` outcome deliberately carries **no `host` label**: an
unknown-host rejection's host segment is attacker-controlled, so labelling
with it would let a probe explode metric-series cardinality. The rejected
request's detail is still on its span, which tolerates the cardinality.

Alongside these, the `otelhttp` server instrumentation emits the standard
`http.server.*` metrics (request duration, active requests) for the same
requests — protocol-level companions to the domain metrics above.

## Logs

haybale logs structured records to stderr via `log/slog`. When telemetry is
enabled, the same records are also shipped to the OTLP logs pipeline. The
handler chain is:

```text
SpanContextHandler → ScrubHandler → Fanout{ stderr, OTLP bridge }
```

so both sinks receive identical records that are:

- **scrubbed** — the secret-scrubbing handler sits above the fan-out, so no
  log value leaves the process unredacted regardless of sink (see
  [`security.md`](security.md)); and
- **trace-correlated** — records emitted inside a request span carry
  `trace_id`/`span_id`, so a log line joins to its trace in the backend.

The per-request `proxied request` log line and the security events
(`authn_failed`, `policy_denied`, `upstream_auth_failed`, `token_minted`,
`cache_integrity_failed`) are emitted through this same chain.
`cache_integrity_failed` carries `host`, `owner`, `repo` and `class`, and no key
material or entry path.

Operational cache log lines worth alerting on are listed in the caching guide
under [What to alert on](caching.md#what-to-alert-on).

### Cache field on the request log

When the [`cache` block](configuration.md#cache) is enabled, the `proxied
request` line of a read gains a `cache` field recording how the response cache
handled it:

| `cache` value | Meaning                                                                                  |
|---------------|------------------------------------------------------------------------------------------|
| `hit`         | Served from a stored entry; the upstream was not contacted for the response body.        |
| `miss`        | Not served from a stored entry. The response came from a fill, an upstream fetch, which stored an entry if it completed cleanly (see `cacheStored`). |
| `stale`       | A stale entry was served because the upstream could not answer. Reserved: it is not emitted while `staleIfErrorFor` is unsupported. |
| `bypass`      | Not eligible for the cache; proxied straight to the upstream.                            |

A `miss` line also carries two boolean fields. `cacheCollapsed` is `true` when
the request joined a fill already in flight rather than starting its own, and
`cacheStored` is `true` when that fill committed an entry. The field is absent
when the cache is disabled and on writes. With `cache.exposeStatus` the
`Cache-Status` response header carries the same `hit`, `miss` and `bypass`
values in RFC 9211 form (`hit`, `fwd=miss`, `fwd=bypass`) and adds `collapsed`
for a request that joined an in-flight fill. A read the cache passed through
unserved carries `fwd=bypass`. The header is written before a fill
ends, so it never says whether the entry was stored; only the log does.
