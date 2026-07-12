# Observability

haybale exports OpenTelemetry traces, metrics, and logs over OTLP when the
`telemetry` block is configured (see [`configuration.md`](configuration.md)
for how to turn it on and point it at a collector). This document describes
what the enabled pipeline emits. When telemetry is disabled, none of the
below is produced and haybale behaves exactly as it did before — the metric
instruments are no-ops and no exporter is dialled.

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
| `haybale.identity`         | The authenticated identity id (the Stirrup run id).        |
| `haybale.outcome`          | One of the outcomes listed under [Metrics](#metrics).      |
| `http.response.status_code`| The client-visible status of a proxied request.            |

Token minting produces a child span, `haybale.mint`, covering the GitHub App
installation lookup and the token POST; each of those two API calls is a
further client span. The span carries `haybale.host/verb/repo.*` and, on
success, the non-secret `haybale.installation_id`. **The minted token itself
never appears on a span, a metric, a log, or an error.**

### Trace propagation

haybale **continues** an inbound trace: a caller (a Stirrup sandbox) that
sends a W3C `traceparent` has haybale's request span nested under its trace.

haybale does **not** propagate a trace onto the leg it forwards upstream:
the reverse-proxy transport is given an empty propagator, so no
`traceparent`/`tracestate`/`baggage` is injected into the request sent to
the git host. This preserves haybale's byte-for-byte passthrough invariant
(the upstream leg carries only the headers the client sent, plus the
`Authorization` rewrite) and avoids leaking haybale's internal trace
topology to an external upstream. The same applies to the GitHub API calls
the credential source makes.

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

The `haybale.outcome` values, spanning every terminal path a request can
take, so `sum by (haybale.outcome)` accounts for all traffic:

| Outcome               | HTTP status | Meaning                                                                       |
|-----------------------|-------------|-------------------------------------------------------------------------------|
| `proxied`             | (upstream's)| Authenticated, authorized, and streamed to the upstream.                      |
| `rejected`            | 404         | Malformed request or unknown upstream host — before any auth check.           |
| `authn_failed`        | 401         | The authenticator rejected the credential.                                    |
| `policy_denied`       | 404         | The policy engine denied the request (indistinguishable from a missing repo). |
| `upstream_auth_failed`| 502         | No working upstream credential could be presented.                            |

A `rejected` outcome deliberately carries **no `host` label**: an
unknown-host rejection's host segment is attacker-controlled, so labelling
with it would let a probe explode metric-series cardinality. The rejected
request's detail is still on its span, which tolerates the cardinality.

Alongside these, the `otelhttp` server instrumentation emits the standard
`http.server.*` metrics (request duration, active requests) for the same
requests — protocol-level companions to the domain metrics above.

## Logs

haybale keeps logging structured records to stderr (via `log/slog`) exactly
as before; when telemetry is enabled, the same records are additionally
shipped to the OTLP logs pipeline. The handler chain is:

```
SpanContextHandler → ScrubHandler → Fanout{ stderr, OTLP bridge }
```

so both sinks receive identical records that are:

- **scrubbed** — the secret-scrubbing handler sits above the fan-out, so no
  log value leaves the process unredacted regardless of sink (see
  [`security.md`](security.md)); and
- **trace-correlated** — records emitted inside a request span carry
  `trace_id`/`span_id`, so a log line joins to its trace in the backend.

The per-request `proxied request` log line and the security events
(`authn_failed`, `policy_denied`, `upstream_auth_failed`, `token_minted`)
are emitted through this same chain.
