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
	// The response-cache attributes. class is bounded by the request
	// classes the cache recognises, reason by the FillReason* set,
	// tier by the Tier* set, and operation by the cache's store
	// operations; none carries a repository or identity.
	attrClass     = "haybale.class"
	attrReason    = "haybale.reason"
	attrTier      = "haybale.tier"
	attrOperation = "haybale.operation"
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

// Cache lookup result values for the attrResult label. The token cache
// (haybale.token_cache.lookups.total) records only ResultHit and
// ResultMiss; the response cache (haybale.response_cache.lookups.total)
// uses all four.
const (
	ResultHit  = "hit"
	ResultMiss = "miss"
	// ResultStale — a stale entry was served because upstream could not
	// answer.
	ResultStale = "stale"
	// ResultBypass — the request was not eligible for the response cache
	// and went straight upstream.
	ResultBypass = "bypass"
)

// Response-cache fill result values for the attrResult label on
// haybale.response_cache.fills.total.
const (
	// FillResultStored — the fill completed and its entry was committed.
	FillResultStored = "stored"
	// FillResultDiscarded — the response was delivered (or abandoned) but
	// not stored; the attrReason label says why.
	FillResultDiscarded = "discarded"
)

// Response-cache fill reason values for the attrReason label on
// haybale.response_cache.fills.total, set on discarded fills only.
const (
	FillReasonErrorPacket    = "error_packet"
	FillReasonSidebandError  = "sideband_error"
	FillReasonFraming        = "framing"
	FillReasonTruncated      = "truncated"
	FillReasonTooLarge       = "too_large"
	FillReasonDiskBudget     = "disk_budget"
	FillReasonStoreError     = "store_error"
	FillReasonGeneration     = "generation"
	FillReasonUpstreamStatus = "upstream_status"
	FillReasonFetchError     = "fetch_error"
	FillReasonEncoding       = "encoding"
)

// Response-cache storage tier values for the attrTier label. TierUpstream
// labels bytes that came from the upstream rather than a stored entry.
const (
	TierDisk     = "disk"
	TierRemote   = "remote"
	TierUpstream = "upstream"
)

// Response-cache store operation values for the attrOperation label on
// haybale.response_cache.store_errors.total.
const (
	OperationOpen   = "open"
	OperationCreate = "create"
	OperationWrite  = "write"
	OperationCommit = "commit"
	OperationAbort  = "abort"
	OperationDelete = "delete"
	OperationEvict  = "evict"
	OperationExpire = "expire"
	OperationSweep  = "sweep"
)

// ClassBypass is the attrClass value for a response-cache lookup of a
// request the cache did not classify.
const ClassBypass = "bypass"

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

	// ResponseCacheLookups counts response-cache lookups tagged by host,
	// request class, and result (hit|miss|stale|bypass).
	ResponseCacheLookups metric.Int64Counter
	// ResponseCacheFills counts finished cache fills tagged by host,
	// class, result (stored|discarded), and, for a discarded fill, the
	// reason it was not stored.
	ResponseCacheFills metric.Int64Counter
	// ResponseCacheFillBytes counts bytes written into the cache by fills,
	// and ResponseCacheServedBytes counts response bytes served to clients
	// through the cache path; both are tagged by host, class, and the tier
	// the bytes came from (disk|remote|upstream).
	ResponseCacheFillBytes   metric.Int64Counter
	ResponseCacheServedBytes metric.Int64Counter
	// ResponseCacheCollapsed counts subscribers that joined a fill already
	// in flight instead of starting their own upstream request, tagged by
	// host.
	ResponseCacheCollapsed metric.Int64Counter
	// ResponseCacheStoreErrors counts storage failures tagged by tier and
	// the operation that failed.
	ResponseCacheStoreErrors metric.Int64Counter
	// ResponseCacheEvictions counts entries evicted to stay within the
	// disk budget or retention.
	ResponseCacheEvictions metric.Int64Counter
	// ResponseCacheUploads counts uploads of committed entries to the
	// remote tier, tagged by result.
	ResponseCacheUploads metric.Int64Counter
	// ResponseCacheDiskBytes tracks the bytes the disk tier currently
	// holds. It is an up/down counter fed with deltas, like InFlight,
	// because Metrics is built before the cache exists.
	ResponseCacheDiskBytes metric.Int64UpDownCounter
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
	return newResponseCacheInstruments(m, meter)
}

// newResponseCacheInstruments constructs the response-cache instruments on
// m from meter, returning m.
func newResponseCacheInstruments(m *Metrics, meter metric.Meter) (*Metrics, error) {
	var err error
	if m.ResponseCacheLookups, err = meter.Int64Counter(
		"haybale.response_cache.lookups.total",
		metric.WithDescription("Response-cache lookups, tagged by host, class, and result (hit|miss|stale|bypass)."),
		metric.WithUnit("{lookup}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheFills, err = meter.Int64Counter(
		"haybale.response_cache.fills.total",
		metric.WithDescription("Response-cache fills, tagged by host, class, result (stored|discarded), and reason for a discarded fill."),
		metric.WithUnit("{fill}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheFillBytes, err = meter.Int64Counter(
		"haybale.response_cache.fill_bytes.total",
		metric.WithDescription("Bytes written into the response cache by fills, tagged by host, class, and tier."),
		metric.WithUnit("By"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheServedBytes, err = meter.Int64Counter(
		"haybale.response_cache.served_bytes.total",
		metric.WithDescription("Response bytes served through the response cache, tagged by host, class, and tier."),
		metric.WithUnit("By"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheCollapsed, err = meter.Int64Counter(
		"haybale.response_cache.collapsed.total",
		metric.WithDescription("Requests that joined an in-flight cache fill instead of fetching upstream, tagged by host."),
		metric.WithUnit("{request}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheStoreErrors, err = meter.Int64Counter(
		"haybale.response_cache.store_errors.total",
		metric.WithDescription("Response-cache storage failures, tagged by tier and operation."),
		metric.WithUnit("{error}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheEvictions, err = meter.Int64Counter(
		"haybale.response_cache.evictions.total",
		metric.WithDescription("Response-cache entries evicted."),
		metric.WithUnit("{entry}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheUploads, err = meter.Int64Counter(
		"haybale.response_cache.uploads.total",
		metric.WithDescription("Uploads of cache entries to the remote tier, tagged by result."),
		metric.WithUnit("{upload}"),
	); err != nil {
		return nil, err
	}
	if m.ResponseCacheDiskBytes, err = meter.Int64UpDownCounter(
		"haybale.response_cache.disk_bytes",
		metric.WithDescription("Bytes currently held by the response cache's disk tier."),
		metric.WithUnit("By"),
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

// RecordTokenCacheLookup counts one token-cache lookup for host/verb with the
// given result (ResultHit or ResultMiss).
func (m *Metrics) RecordTokenCacheLookup(ctx context.Context, host, verb, result string) {
	m.TokenCacheLookups.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrVerb, verb),
		attribute.String(attrResult, result),
	))
}

// RecordResponseCacheLookup counts one response-cache lookup for host and
// request class with the given result (ResultHit, ResultMiss, ResultStale
// or ResultBypass).
func (m *Metrics) RecordResponseCacheLookup(ctx context.Context, host, class, result string) {
	m.ResponseCacheLookups.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrClass, class),
		attribute.String(attrResult, result),
	))
}

// RecordResponseCacheFill counts one finished cache fill with the given
// result (FillResultStored or FillResultDiscarded). reason is one of the
// FillReason* values for a discarded fill and empty for a stored one, in
// which case the reason label is omitted.
func (m *Metrics) RecordResponseCacheFill(ctx context.Context, host, class, result, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String(attrHost, host),
		attribute.String(attrClass, class),
		attribute.String(attrResult, result),
	}
	if reason != "" {
		attrs = append(attrs, attribute.String(attrReason, reason))
	}
	m.ResponseCacheFills.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordResponseCacheFillBytes counts n bytes written into the cache for
// host and class, read from tier (TierRemote or TierUpstream).
func (m *Metrics) RecordResponseCacheFillBytes(ctx context.Context, host, class, tier string, n int64) {
	m.ResponseCacheFillBytes.Add(ctx, n, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrClass, class),
		attribute.String(attrTier, tier),
	))
}

// RecordResponseCacheServedBytes counts n response bytes served to a client
// for host and class from tier (TierDisk, TierRemote or TierUpstream).
func (m *Metrics) RecordResponseCacheServedBytes(ctx context.Context, host, class, tier string, n int64) {
	m.ResponseCacheServedBytes.Add(ctx, n, metric.WithAttributes(
		attribute.String(attrHost, host),
		attribute.String(attrClass, class),
		attribute.String(attrTier, tier),
	))
}

// RecordResponseCacheCollapsed counts one request for host that joined a
// fill already in flight.
func (m *Metrics) RecordResponseCacheCollapsed(ctx context.Context, host string) {
	m.ResponseCacheCollapsed.Add(ctx, 1, metric.WithAttributes(attribute.String(attrHost, host)))
}

// RecordResponseCacheStoreError counts one storage failure in tier
// (TierDisk or TierRemote) during operation.
func (m *Metrics) RecordResponseCacheStoreError(ctx context.Context, tier, operation string) {
	m.ResponseCacheStoreErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrTier, tier),
		attribute.String(attrOperation, operation),
	))
}

// RecordResponseCacheEvictions counts n cache entries evicted.
func (m *Metrics) RecordResponseCacheEvictions(ctx context.Context, n int64) {
	m.ResponseCacheEvictions.Add(ctx, n)
}

// RecordResponseCacheUpload counts one upload to the remote tier with the
// given result.
func (m *Metrics) RecordResponseCacheUpload(ctx context.Context, result string) {
	m.ResponseCacheUploads.Add(ctx, 1, metric.WithAttributes(attribute.String(attrResult, result)))
}

// ResponseCacheDiskBytesAdd adds delta (positive when an entry is
// committed, negative when one is removed) to the disk-tier size gauge.
func (m *Metrics) ResponseCacheDiskBytesAdd(ctx context.Context, delta int64) {
	m.ResponseCacheDiskBytes.Add(ctx, delta)
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
