package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// Metric attribute keys. Kept deliberately low-cardinality: host is bounded
// by the number of configured upstreams, verb is read|write, outcome and
// result are small closed sets. Per-request high-cardinality values (repo
// owner/name, identity) are NEVER used as metric attributes — they would
// explode series cardinality on a backend like Mimir — and appear only on
// spans, which tolerate them.
const (
	attrHost    = "haybale.host"
	attrVerb    = "haybale.verb"
	attrOutcome = "haybale.outcome"
	attrStatus  = "http.response.status_code"
	attrResult  = "haybale.result"
)

// Request outcome values for the attrOutcome label on
// haybale.requests.total and haybale.request.duration. A single closed set
// spanning every terminal path ServeHTTP can take, so one query
// (sum by (haybale.outcome)) accounts for all traffic.
const (
	// OutcomeProxied — the request was authenticated, authorized, and
	// streamed to the upstream (whatever status the upstream returned).
	OutcomeProxied = "proxied"
	// OutcomeRejected — gitproto.ParseRequest rejected the request, or it
	// named an unknown upstream host: a 404 before any auth check.
	OutcomeRejected = "rejected"
	// OutcomeAuthnFailed — the Authenticator rejected the credential: 401.
	OutcomeAuthnFailed = "authn_failed"
	// OutcomePolicyDenied — the policy Engine denied the request: 404.
	OutcomePolicyDenied = "policy_denied"
	// OutcomeUpstreamAuthFailed — no upstream credential could be acquired
	// before forwarding (for example, a mint error): 502. An upstream
	// rejection after forwarding is OutcomeProxied with status 502.
	OutcomeUpstreamAuthFailed = "upstream_auth_failed"
)

// Token-cache result values for the attrResult label on
// haybale.token_cache.total.
const (
	ResultHit  = "hit"
	ResultMiss = "miss"
)

// Metrics holds haybale's OTel metric instruments. When telemetry is
// disabled (NewNoopMetrics), every instrument is backed by
// noop.MeterProvider so call sites record unconditionally with zero
// overhead and no nil checks; provider is nil in that case.
//
// A *Metrics is safe for concurrent use — the underlying OTel instruments
// are — and is passed by pointer to every component that records
// (internal/proxy, internal/upstream). Traces, by contrast, use the global
// TracerProvider and need no such plumbing (see Setup).
type Metrics struct {
	provider *sdkmetric.MeterProvider // nil for the no-op instance

	// RequestsTotal counts every terminal request outcome, tagged by
	// host, verb, outcome, and (for proxied requests) the upstream HTTP
	// status. /healthz is not counted.
	RequestsTotal metric.Int64Counter
	// RequestDuration records wall-clock request latency in seconds,
	// tagged by host, verb, and outcome — the domain-labelled companion to
	// otelhttp's protocol-level http.server.request.duration.
	RequestDuration metric.Float64Histogram
	// RequestBytesIn / RequestBytesOut record per-request body sizes in
	// bytes, tagged by host and verb, counted by the same streaming
	// byte-counters the request log uses (never by buffering).
	RequestBytesIn  metric.Int64Histogram
	RequestBytesOut metric.Int64Histogram
	// InFlight tracks the number of requests currently being proxied,
	// tagged by host and verb — a live gauge for spotting a stuck or
	// saturating upstream.
	InFlight metric.Int64UpDownCounter

	// TokensMinted counts GitHub App installation-token mints, tagged by
	// host and verb. One increment per real upstream mint call (a cache
	// hit does not mint), so the mint-rate against GitHub's REST budget is
	// directly observable.
	TokensMinted metric.Int64Counter
	// TokenCacheLookups counts token-cache lookups tagged by host, verb,
	// and result (hit|miss) — the cache hit ratio that governs how much
	// mint traffic haybale generates.
	TokenCacheLookups metric.Int64Counter
}

// NewNoopMetrics returns a Metrics whose instruments are all no-ops,
// backed by noop.MeterProvider. Used when telemetry is disabled so every
// record call site is unconditional. The returned value's shutdown is a
// no-op.
func NewNoopMetrics() *Metrics {
	m, err := newMetricsFromMeter(noop.NewMeterProvider().Meter(ScopeName), nil)
	if err != nil {
		// noop instruments never fail to construct; a non-nil error here
		// would be a bug in the OTel noop implementation, not a runtime
		// condition, so surfacing it as a panic (rather than returning it
		// and forcing every disabled-telemetry call site to handle an
		// impossible error) is the honest signal.
		panic(fmt.Sprintf("observability: noop metrics construction failed: %v", err))
	}
	return m
}

// NewTestMetrics builds a Metrics backed by an in-memory ManualReader,
// returning both so a test in any package can drive the record methods and
// then Collect and assert the emitted data points without standing up an
// OTLP collector. Production builds go through Setup.
func NewTestMetrics() (*Metrics, *sdkmetric.ManualReader) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := newMetricsFromMeter(provider.Meter(ScopeName), provider)
	if err != nil {
		// Instrument construction cannot fail for a valid meter (see
		// newMetricsFromMeter); a non-nil error here is a bug in this file.
		panic(fmt.Sprintf("observability: test metrics construction failed: %v", err))
	}
	return m, reader
}

// NewMetrics builds a Metrics backed by an OTLP metric exporter dialled per
// cfg, sharing res with the trace and log pipelines so a backend can
// correlate all three signals. Called only from Setup, with an
// already-validated, enabled cfg.
func NewMetrics(ctx context.Context, cfg Config, res *resource.Resource) (*Metrics, error) {
	exporter, err := buildMetricExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		sdkmetric.WithResource(res),
	)
	m, err := newMetricsFromMeter(provider.Meter(ScopeName), provider)
	if err != nil {
		_ = provider.Shutdown(ctx)
		return nil, err
	}
	return m, nil
}

// newMetricsFromMeter constructs every instrument from meter. provider is
// stored for shutdown (nil for the no-op instance). Instrument creation is
// the only place an OTel meter can return an error (a duplicate/invalid
// instrument name); a failure here is a programming error in this file,
// caught at startup.
func newMetricsFromMeter(meter metric.Meter, provider *sdkmetric.MeterProvider) (*Metrics, error) {
	m := &Metrics{provider: provider}
	var err error

	if m.RequestsTotal, err = meter.Int64Counter(
		"haybale.requests.total",
		metric.WithDescription("Total proxied-request outcomes, tagged by host, verb, and outcome."),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}
	if m.RequestDuration, err = meter.Float64Histogram(
		"haybale.request.duration",
		metric.WithDescription("Proxied-request wall-clock latency, tagged by host, verb, and outcome."),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}
	if m.RequestBytesIn, err = meter.Int64Histogram(
		"haybale.request.bytes_in",
		metric.WithDescription("Inbound request-body bytes streamed through the proxy."),
		metric.WithUnit("By"),
	); err != nil {
		return nil, err
	}
	if m.RequestBytesOut, err = meter.Int64Histogram(
		"haybale.request.bytes_out",
		metric.WithDescription("Outbound response bytes streamed through the proxy."),
		metric.WithUnit("By"),
	); err != nil {
		return nil, err
	}
	if m.InFlight, err = meter.Int64UpDownCounter(
		"haybale.requests.in_flight",
		metric.WithDescription("Requests currently being proxied, tagged by host and verb."),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}
	if m.TokensMinted, err = meter.Int64Counter(
		"haybale.tokens.minted.total",
		metric.WithDescription("GitHub App installation tokens minted, tagged by host and verb."),
		metric.WithUnit("{token}"),
	); err != nil {
		return nil, err
	}
	if m.TokenCacheLookups, err = meter.Int64Counter(
		"haybale.token_cache.lookups.total",
		metric.WithDescription("Token-cache lookups, tagged by host, verb, and result (hit|miss)."),
		metric.WithUnit("{lookup}"),
	); err != nil {
		return nil, err
	}
	return m, nil
}

// RecordRejected counts a request rejected before any auth check — a
// gitproto parse failure or an unknown upstream host (both a 404). It
// carries only the outcome label, deliberately no host: an unknown-host
// rejection's host segment is attacker-controlled, so labelling with it
// would let a probe explode metric-series cardinality. The rejected
// request's detail still lands on its trace span, which tolerates it.
func (m *Metrics) RecordRejected(ctx context.Context) {
	m.RequestsTotal.Add(ctx, 1, metric.WithAttributes(attribute.String(attrOutcome, OutcomeRejected)))
}

// RecordFailure counts a request that resolved to a configured upstream
// (so host is a bounded label) but failed before or during forwarding:
// OutcomeAuthnFailed, OutcomePolicyDenied, or OutcomeUpstreamAuthFailed.
func (m *Metrics) RecordFailure(ctx context.Context, host, verb, outcome string) {
	m.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
		attribute.String(attrOutcome, outcome),
	))
}

// RecordProxied records the full set of proxied-request observations in one
// place: the outcome counter (with the upstream HTTP status), the latency
// histogram, and the inbound/outbound byte histograms. status is the
// client-visible status (after any modifyResponse rewrite); bytesIn and
// bytesOut come from the streaming byte-counters, never from buffering.
func (m *Metrics) RecordProxied(ctx context.Context, host, verb string, status int, duration time.Duration, bytesIn, bytesOut int64) {
	hostVerb := []attribute.KeyValue{
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
	}
	m.RequestsTotal.Add(ctx, 1, metric.WithAttributes(append(hostVerb,
		attribute.String(attrOutcome, OutcomeProxied),
		attribute.Int(attrStatus, status),
	)...))
	m.RequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(append(hostVerb,
		attribute.String(attrOutcome, OutcomeProxied),
	)...))
	m.RequestBytesIn.Record(ctx, bytesIn, metric.WithAttributes(hostVerb...))
	m.RequestBytesOut.Record(ctx, bytesOut, metric.WithAttributes(hostVerb...))
}

// InFlightAdd adds delta (+1 entering, -1 leaving) to the in-flight gauge
// for host/verb.
func (m *Metrics) InFlightAdd(ctx context.Context, host, verb string, delta int64) {
	m.InFlight.Add(ctx, delta, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
	))
}

// RecordMint counts one GitHub App installation-token mint for host/verb.
func (m *Metrics) RecordMint(ctx context.Context, host, verb string) {
	m.TokensMinted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
	))
}

// RecordCacheLookup counts one token-cache lookup for host/verb with the
// given result (ResultHit or ResultMiss).
func (m *Metrics) RecordCacheLookup(ctx context.Context, host, verb, result string) {
	m.TokenCacheLookups.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
		attribute.String(attrResult, result),
	))
}

// shutdown flushes and shuts the meter provider down. A no-op on the
// noop-backed instance (nil provider) and on a nil receiver.
func (m *Metrics) shutdown(ctx context.Context) error {
	if m == nil || m.provider == nil {
		return nil
	}
	return m.provider.Shutdown(ctx)
}

// buildMetricExporter dispatches on the configured wire protocol, mirroring
// buildTraceExporter and buildLogExporter.
func buildMetricExporter(ctx context.Context, cfg Config) (sdkmetric.Exporter, error) {
	switch cfg.Protocol {
	case "", ProtocolGRPC:
		opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(stripURLScheme(cfg.Endpoint))}
		if path := urlPath(cfg.Endpoint); path != "" {
			opts = append(opts, otlpmetrichttp.WithURLPath(joinSignalPath(path, "metrics")))
		}
		if isInsecureEndpoint(cfg.Endpoint) {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
		}
		return otlpmetrichttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol %q", cfg.Protocol)
	}
}
