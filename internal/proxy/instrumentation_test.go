package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/policy"
)

// proxyWithMetrics builds a Proxy over the given upstream map wired to an
// in-memory metrics reader, so a test can drive requests and assert the
// emitted instruments.
func proxyWithMetrics(t *testing.T, byHost map[string]string, auth identity.Authenticator, pol policy.Engine) (*Proxy, *sdkmetric.ManualReader) {
	t.Helper()
	upstreams := newUpstreamMap(t, byHost)
	metrics, reader := observability.NewTestMetrics()
	p, err := New(upstreams, credentialsForHosts(upstreams), auth, pol, discardLogger(), metrics)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p, reader
}

func outcomeCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != "haybale.requests.total" {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("requests.total is %T, want Sum[int64]", md.Data)
			}
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value(attribute.Key("haybale.outcome")); ok {
					counts[v.String()] += dp.Value
				}
			}
		}
	}
	return counts
}

func metricNames(t *testing.T, reader *sdkmetric.ManualReader) map[string]bool {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			names[md.Name] = true
		}
	}
	return names
}

// TestProxyRecordsProxiedMetrics drives one successful upload-pack request
// and asserts the full proxied-request instrument set fires: the outcome
// counter (proxied) plus the duration and byte histograms.
func TestProxyRecordsProxiedMetrics(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p, reader := proxyWithMetrics(t, map[string]string{"testhost": upstreamSrv.URL}, allowAllAuthenticator{}, allowAllPolicy{})
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if got := outcomeCounts(t, reader)["proxied"]; got != 1 {
		t.Errorf("proxied outcome count = %d, want 1", got)
	}
	names := metricNames(t, reader)
	for _, name := range []string{"haybale.request.duration", "haybale.request.bytes_out", "haybale.requests.in_flight"} {
		if !names[name] {
			t.Errorf("expected instrument %q to have recorded after a proxied request", name)
		}
	}
}

// TestProxyRecordsOutcomeMetrics pins the outcome label for each terminal
// path a request can take before or instead of being forwarded.
func TestProxyRecordsOutcomeMetrics(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()
	hosts := map[string]string{"testhost": upstreamSrv.URL}

	tests := []struct {
		name        string
		auth        identity.Authenticator
		pol         policy.Engine
		path        string
		wantOutcome string
	}{
		{
			name:        "rejected on malformed path",
			auth:        allowAllAuthenticator{},
			pol:         allowAllPolicy{},
			path:        "/testhost/not-a-valid-git-path",
			wantOutcome: "rejected",
		},
		{
			name:        "rejected on unknown host",
			auth:        allowAllAuthenticator{},
			pol:         allowAllPolicy{},
			path:        "/otherhost/acme/widgets.git/info/refs?service=git-upload-pack",
			wantOutcome: "rejected",
		},
		{
			name:        "authn_failed",
			auth:        denyAllAuthenticator{},
			pol:         allowAllPolicy{},
			path:        "/testhost/acme/widgets.git/info/refs?service=git-upload-pack",
			wantOutcome: "authn_failed",
		},
		{
			name:        "policy_denied",
			auth:        allowAllAuthenticator{},
			pol:         denyAllPolicy{},
			path:        "/testhost/acme/widgets.git/info/refs?service=git-upload-pack",
			wantOutcome: "policy_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, reader := proxyWithMetrics(t, hosts, tt.auth, tt.pol)
			srv := httptest.NewServer(p)
			defer srv.Close()

			resp, err := http.Get(srv.URL + tt.path)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			_ = resp.Body.Close()

			counts := outcomeCounts(t, reader)
			if counts[tt.wantOutcome] != 1 {
				t.Errorf("outcome %q count = %d, want 1 (all counts: %v)", tt.wantOutcome, counts[tt.wantOutcome], counts)
			}
		})
	}
}

// TestUpstreamReceivesNoTraceparent is the tracing counterpart of
// TestClientXForwardedHeadersAreSuppressed: even with a real, sampling
// TracerProvider installed and the proxy wrapped in otelhttp so an inbound
// server span exists, haybale must never inject its own W3C traceparent
// into the request it forwards upstream. The reverse-proxy transport is
// deliberately given an empty propagator (see New); this pins that choice
// so a future refactor can't silently start leaking haybale's trace
// topology onto the upstream leg.
func TestUpstreamReceivesNoTraceparent(t *testing.T) {
	// Install a real sampling tracer + W3C propagator globally for the
	// duration of the test, then restore the prior globals so other tests
	// see the default no-op providers.
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p, _ := proxyWithMetrics(t, map[string]string{"testhost": upstreamSrv.URL}, allowAllAuthenticator{}, allowAllPolicy{})
	// Wrap exactly as serve.go's instrumentedHandler does, so an inbound
	// server span is created and would normally be propagated onward.
	handler := otelhttp.NewHandler(p, "haybale.request")
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	_, _, _, headers, _ := up.snapshot()
	for _, h := range []string{"Traceparent", "Tracestate", "Baggage"} {
		if got := headers.Get(h); got != "" {
			t.Errorf("upstream saw %s = %q, want it absent (passthrough invariant)", h, got)
		}
	}
}

// TestNewFallsBackToDefaultLoggerAndNoopMetrics covers New's documented
// nil-handling: a nil logger falls back to slog.Default() and nil metrics
// to a noop-backed Metrics, so the proxy is usable and records into no-ops
// without panicking. Every other call site passes both explicitly.
func TestNewFallsBackToDefaultLoggerAndNoopMetrics(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
	p, err := New(upstreams, credentialsForHosts(upstreams), allowAllAuthenticator{}, allowAllPolicy{}, nil, nil)
	if err != nil {
		t.Fatalf("New(nil logger, nil metrics) error = %v", err)
	}
	srv := httptest.NewServer(p)
	defer srv.Close()

	// A real request must flow through without panicking on the fallback
	// logger/metrics.
	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
