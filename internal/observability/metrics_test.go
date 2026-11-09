package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestMetrics builds a Metrics backed by an in-memory ManualReader so a
// test can drive the recording methods and then Collect and assert the
// emitted data points, without an OTLP collector.
func newTestMetrics(t *testing.T) (*Metrics, *sdkmetric.ManualReader) {
	t.Helper()
	m, reader := NewTestMetrics()
	t.Cleanup(func() { _ = m.shutdown(context.Background()) })
	return m, reader
}

// collectSum finds the named Sum[int64] metric and returns its data points
// keyed by their attribute set (rendered as a stable string).
func collectSum(t *testing.T, reader *sdkmetric.ManualReader, name string) []metricdata.DataPoint[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != name {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q is %T, want Sum[int64]", name, md.Data)
			}
			return sum.DataPoints
		}
	}
	return nil
}

// hasAttr reports whether set contains key.
func hasAttr(set attribute.Set, key string) bool {
	_, ok := set.Value(attribute.Key(key))
	return ok
}

// attrString returns the string value of key in set, or "" if absent.
func attrString(set attribute.Set, key string) string {
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return v.String()
}

func TestRecordRejectedHasNoHostLabel(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordRejected(context.Background())

	points := collectSum(t, reader, "haybale.requests.total")
	if len(points) != 1 {
		t.Fatalf("got %d data points, want 1", len(points))
	}
	dp := points[0]
	if dp.Value != 1 {
		t.Errorf("value = %d, want 1", dp.Value)
	}
	if got := attrString(dp.Attributes, attrOutcome); got != OutcomeRejected {
		t.Errorf("outcome = %q, want %q", got, OutcomeRejected)
	}
	// The cardinality guarantee: a rejected request (which may carry an
	// attacker-controlled host segment) must never be labelled with host.
	if hasAttr(dp.Attributes, attrHost) {
		t.Error("rejected request carries a host label; must not (cardinality/security)")
	}
}

func TestRecordFailureLabels(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordFailure(context.Background(), "github.com", "write", OutcomePolicyDenied)

	points := collectSum(t, reader, "haybale.requests.total")
	if len(points) != 1 {
		t.Fatalf("got %d data points, want 1", len(points))
	}
	dp := points[0]
	if got := attrString(dp.Attributes, attrHost); got != "github.com" {
		t.Errorf("host = %q, want github.com", got)
	}
	if got := attrString(dp.Attributes, attrVerb); got != "write" {
		t.Errorf("verb = %q, want write", got)
	}
	if got := attrString(dp.Attributes, attrOutcome); got != OutcomePolicyDenied {
		t.Errorf("outcome = %q, want %q", got, OutcomePolicyDenied)
	}
}

func TestRecordProxiedEmitsAllInstruments(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordProxied(context.Background(), "github.com", "read", 200, 150*time.Millisecond, 42, 4096)

	// The outcome counter carries the status code.
	points := collectSum(t, reader, "haybale.requests.total")
	if len(points) != 1 {
		t.Fatalf("requests.total: got %d points, want 1", len(points))
	}
	if got := attrString(points[0].Attributes, attrOutcome); got != OutcomeProxied {
		t.Errorf("outcome = %q, want %q", got, OutcomeProxied)
	}
	if got := attrString(points[0].Attributes, attrStatus); got != "200" {
		t.Errorf("status = %q, want 200", got)
	}

	// Duration + byte histograms exist with the expected sums.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			seen[md.Name] = true
		}
	}
	for _, name := range []string{"haybale.request.duration", "haybale.request.bytes_in", "haybale.request.bytes_out"} {
		if !seen[name] {
			t.Errorf("missing histogram %q after RecordProxied", name)
		}
	}
}

func TestRecordMintAndCacheLookup(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordMint(context.Background(), "github.com", "read")
	m.RecordTokenCacheLookup(context.Background(), "github.com", "read", ResultHit)
	m.RecordTokenCacheLookup(context.Background(), "github.com", "read", ResultMiss)

	mints := collectSum(t, reader, "haybale.tokens.minted.total")
	if len(mints) != 1 || mints[0].Value != 1 {
		t.Fatalf("tokens.minted: %+v, want one point valued 1", mints)
	}

	lookups := collectSum(t, reader, "haybale.token_cache.lookups.total")
	if len(lookups) != 2 {
		t.Fatalf("token_cache.lookups: got %d points, want 2 (hit + miss)", len(lookups))
	}
	results := map[string]int64{}
	for _, dp := range lookups {
		results[attrString(dp.Attributes, attrResult)] = dp.Value
	}
	if results[ResultHit] != 1 || results[ResultMiss] != 1 {
		t.Errorf("cache results = %v, want one hit and one miss", results)
	}
}

func TestInFlightGaugeAddsAndSubtracts(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.InFlightAdd(context.Background(), "github.com", "read", 1)
	m.InFlightAdd(context.Background(), "github.com", "read", 1)
	m.InFlightAdd(context.Background(), "github.com", "read", -1)

	points := collectSum(t, reader, "haybale.requests.in_flight")
	if len(points) != 1 {
		t.Fatalf("in_flight: got %d points, want 1", len(points))
	}
	if points[0].Value != 1 {
		t.Errorf("in_flight value = %d, want 1 (2 up, 1 down)", points[0].Value)
	}
}

func TestNewNoopMetricsRecordsWithoutPanicOrProvider(t *testing.T) {
	t.Parallel()
	m := NewNoopMetrics()
	if m.provider != nil {
		t.Error("NewNoopMetrics provider != nil, want nil")
	}
	// Exercising every method on the noop instance must be safe.
	ctx := context.Background()
	m.RecordRejected(ctx)
	m.RecordFailure(ctx, "h", "read", OutcomeAuthnFailed)
	m.RecordProxied(ctx, "h", "read", 200, time.Second, 1, 2)
	m.InFlightAdd(ctx, "h", "read", 1)
	m.RecordMint(ctx, "h", "read")
	m.RecordTokenCacheLookup(ctx, "h", "read", ResultHit)
	if err := m.shutdown(ctx); err != nil {
		t.Errorf("noop shutdown() error = %v, want nil", err)
	}
}

// onlyPoint collects the named Sum[int64] metric and returns its single data
// point, failing the test if there is not exactly one.
func onlyPoint(t *testing.T, reader *sdkmetric.ManualReader, name string) metricdata.DataPoint[int64] {
	t.Helper()
	points := collectSum(t, reader, name)
	if len(points) != 1 {
		t.Fatalf("%s: got %d data points, want 1", name, len(points))
	}
	return points[0]
}

// wantAttrs fails the test unless set holds exactly the want key/value
// pairs: no missing label and no extra one, so a stray high-cardinality
// label cannot slip in.
func wantAttrs(t *testing.T, name string, set attribute.Set, want map[string]string) {
	t.Helper()
	if set.Len() != len(want) {
		t.Errorf("%s: %d attributes (%v), want %d (%v)", name, set.Len(), set.ToSlice(), len(want), want)
	}
	for key, value := range want {
		if got := attrString(set, key); got != value {
			t.Errorf("%s: attribute %s = %q, want %q", name, key, got, value)
		}
	}
}

func TestRecordResponseCacheLookup(t *testing.T) {
	t.Parallel()
	for _, result := range []string{ResultHit, ResultMiss, ResultStale, ResultBypass} {
		t.Run(result, func(t *testing.T) {
			t.Parallel()
			m, reader := newTestMetrics(t)
			m.RecordResponseCacheLookup(context.Background(), "github.com", "fetch", result)

			dp := onlyPoint(t, reader, "haybale.response_cache.lookups.total")
			if dp.Value != 1 {
				t.Errorf("value = %d, want 1", dp.Value)
			}
			wantAttrs(t, "lookups", dp.Attributes, map[string]string{
				attrHost: "github.com", attrClass: "fetch", attrResult: result,
			})
		})
	}
}

func TestRecordResponseCacheFill(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result string
		reason string
		want   map[string]string
	}{
		{
			name: "stored omits reason", result: FillResultStored,
			want: map[string]string{attrHost: "github.com", attrClass: "fetch", attrTier: TierUpstream, attrResult: FillResultStored},
		},
		{
			name: "discarded carries reason", result: FillResultDiscarded, reason: FillReasonTruncated,
			want: map[string]string{attrHost: "github.com", attrClass: "fetch", attrTier: TierUpstream, attrResult: FillResultDiscarded, attrReason: FillReasonTruncated},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, reader := newTestMetrics(t)
			m.RecordResponseCacheFill(context.Background(), "github.com", "fetch", TierUpstream, tt.result, tt.reason)

			dp := onlyPoint(t, reader, "haybale.response_cache.fills.total")
			if dp.Value != 1 {
				t.Errorf("value = %d, want 1", dp.Value)
			}
			wantAttrs(t, "fills", dp.Attributes, tt.want)
		})
	}
}

func TestRecordResponseCacheBytes(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	ctx := context.Background()
	m.RecordResponseCacheFillBytes(ctx, "github.com", "fetch", TierUpstream, 1000)
	m.RecordResponseCacheFillBytes(ctx, "github.com", "fetch", TierUpstream, 24)
	m.RecordResponseCacheServedBytes(ctx, "github.com", "advertisement", TierDisk, 4096)

	fill := onlyPoint(t, reader, "haybale.response_cache.fill_bytes.total")
	if fill.Value != 1024 {
		t.Errorf("fill_bytes value = %d, want 1024", fill.Value)
	}
	wantAttrs(t, "fill_bytes", fill.Attributes, map[string]string{
		attrHost: "github.com", attrClass: "fetch", attrTier: TierUpstream,
	})

	served := onlyPoint(t, reader, "haybale.response_cache.served_bytes.total")
	if served.Value != 4096 {
		t.Errorf("served_bytes value = %d, want 4096", served.Value)
	}
	wantAttrs(t, "served_bytes", served.Attributes, map[string]string{
		attrHost: "github.com", attrClass: "advertisement", attrTier: TierDisk,
	})
}

func TestRecordResponseCacheCollapsed(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordResponseCacheCollapsed(context.Background(), "github.com")
	m.RecordResponseCacheCollapsed(context.Background(), "github.com")

	dp := onlyPoint(t, reader, "haybale.response_cache.collapsed.total")
	if dp.Value != 2 {
		t.Errorf("value = %d, want 2", dp.Value)
	}
	wantAttrs(t, "collapsed", dp.Attributes, map[string]string{attrHost: "github.com"})
}

func TestRecordResponseCacheStoreError(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordResponseCacheStoreError(context.Background(), TierDisk, "open")

	dp := onlyPoint(t, reader, "haybale.response_cache.store_errors.total")
	if dp.Value != 1 {
		t.Errorf("value = %d, want 1", dp.Value)
	}
	wantAttrs(t, "store_errors", dp.Attributes, map[string]string{attrTier: TierDisk, attrOperation: "open"})
}

func TestRecordResponseCacheEvictionsHasNoLabels(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordResponseCacheEvictions(context.Background(), 3)
	m.RecordResponseCacheEvictions(context.Background(), 2)

	dp := onlyPoint(t, reader, "haybale.response_cache.evictions.total")
	if dp.Value != 5 {
		t.Errorf("value = %d, want 5", dp.Value)
	}
	wantAttrs(t, "evictions", dp.Attributes, map[string]string{})
}

func TestRecordResponseCacheUpload(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	m.RecordResponseCacheUpload(context.Background(), UploadResultUploaded)

	dp := onlyPoint(t, reader, "haybale.response_cache.uploads.total")
	if dp.Value != 1 {
		t.Errorf("value = %d, want 1", dp.Value)
	}
	wantAttrs(t, "uploads", dp.Attributes, map[string]string{attrResult: UploadResultUploaded})
}

func TestResponseCacheDiskBytesAddsAndSubtracts(t *testing.T) {
	t.Parallel()
	m, reader := newTestMetrics(t)
	ctx := context.Background()
	m.ResponseCacheDiskBytesAdd(ctx, 5000)
	m.ResponseCacheDiskBytesAdd(ctx, 2000)
	m.ResponseCacheDiskBytesAdd(ctx, -3000)

	dp := onlyPoint(t, reader, "haybale.response_cache.disk_bytes")
	if dp.Value != 4000 {
		t.Errorf("disk_bytes value = %d, want 4000 (7000 added, 3000 removed)", dp.Value)
	}
}

// TestResponseCacheNoopMetricsRecordWithoutPanic confirms the no-op
// instance covers every response-cache instrument, so call sites need no
// nil or enabled checks.
func TestResponseCacheNoopMetricsRecordWithoutPanic(t *testing.T) {
	t.Parallel()
	m := NewNoopMetrics()
	ctx := context.Background()
	m.RecordResponseCacheLookup(ctx, "h", "fetch", ResultBypass)
	m.RecordResponseCacheFill(ctx, "h", "fetch", TierUpstream, FillResultDiscarded, FillReasonFetchError)
	m.RecordResponseCacheFillBytes(ctx, "h", "fetch", TierUpstream, 1)
	m.RecordResponseCacheServedBytes(ctx, "h", "fetch", TierDisk, 1)
	m.RecordResponseCacheCollapsed(ctx, "h")
	m.RecordResponseCacheStoreError(ctx, TierRemote, OperationGet)
	m.RecordResponseCacheEvictions(ctx, 1)
	m.RecordResponseCacheUpload(ctx, UploadResultDropped)
	m.ResponseCacheDiskBytesAdd(ctx, 1)
}
