package observability

import (
	"context"
	"reflect"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

// withRestoredGlobals saves the global TracerProvider / MeterProvider /
// propagator and restores them when the test ends, so a test that calls the
// enabled Setup (which sets those globals) doesn't leak state into other
// tests in the binary.
func withRestoredGlobals(t *testing.T) {
	t.Helper()
	tp := otel.GetTracerProvider()
	mp := otel.GetMeterProvider()
	prop := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(tp)
		otel.SetMeterProvider(mp)
		otel.SetTextMapPropagator(prop)
	})
}

func TestConfigEnabled(t *testing.T) {
	t.Parallel()
	if (Config{}).Enabled() {
		t.Error("empty Config.Enabled() = true, want false")
	}
	if !(Config{Endpoint: "localhost:4317"}).Enabled() {
		t.Error("Config with endpoint Enabled() = false, want true")
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "disabled is always valid", cfg: Config{}},
		{name: "disabled with junk protocol still valid", cfg: Config{Protocol: "carrier-pigeon"}},
		{name: "enabled default protocol", cfg: Config{Endpoint: "localhost:4317"}},
		{name: "enabled grpc", cfg: Config{Endpoint: "localhost:4317", Protocol: ProtocolGRPC}},
		{name: "enabled http", cfg: Config{Endpoint: "https://x/otlp", Protocol: ProtocolHTTP}},
		{name: "enabled bad protocol", cfg: Config{Endpoint: "localhost:4317", Protocol: "carrier-pigeon"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestSetupDisabledIsNoop(t *testing.T) {
	t.Parallel()
	providers, err := Setup(context.Background(), Config{})
	if err != nil {
		t.Fatalf("Setup(disabled) error = %v", err)
	}
	if providers == nil {
		t.Fatal("Setup(disabled) returned nil Providers")
	}
	if providers.Metrics == nil {
		t.Error("Setup(disabled) Metrics = nil, want noop-backed Metrics")
	}
	if providers.LogHandler != nil {
		t.Error("Setup(disabled) LogHandler != nil, want nil (stderr-only)")
	}
	// The disabled Metrics must be usable — every record call site is
	// unconditional, so a no-op instance must not panic.
	providers.Metrics.RecordRejected(context.Background())
	providers.Metrics.RecordProxied(context.Background(), "h", "read", 200, 0, 0, 0)
	// Shutdown must be a clean no-op, including on a nil receiver.
	if err := providers.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(disabled) error = %v, want nil", err)
	}
	if err := (*Providers)(nil).Shutdown(context.Background()); err != nil {
		t.Errorf("nil Providers.Shutdown() error = %v, want nil", err)
	}
}

// TestSetupEnabledBuildsRealPipeline exercises the enabled Setup path for
// both wire protocols. The OTLP exporters dial lazily, so no collector need
// be listening; the endpoint points at a closed port. It asserts the real
// (non-noop) pipeline is built, the globals are installed, and Shutdown
// returns promptly under a bounded context even though no collector ever
// answered.
func TestSetupEnabledBuildsRealPipeline(t *testing.T) {
	protocols := []struct {
		name     string
		protocol string
		endpoint string
	}{
		{name: "grpc", protocol: ProtocolGRPC, endpoint: "localhost:1"},
		{name: "http/protobuf", protocol: ProtocolHTTP, endpoint: "http://localhost:1"},
	}
	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			withRestoredGlobals(t)
			defaultTP := otel.GetTracerProvider()

			providers, err := Setup(context.Background(), Config{Endpoint: p.endpoint, Protocol: p.protocol})
			if err != nil {
				t.Fatalf("Setup(enabled) error = %v", err)
			}
			if providers.Metrics == nil || providers.Metrics.provider == nil {
				t.Error("enabled Setup Metrics.provider = nil, want a real (non-noop) meter provider")
			}
			if providers.LogHandler == nil {
				t.Error("enabled Setup LogHandler = nil, want the OTLP bridge handler")
			}
			if otel.GetTracerProvider() == defaultTP {
				t.Error("global TracerProvider unchanged after Setup, want the SDK provider installed")
			}

			// Shutdown must return promptly under a bounded context even
			// though nothing is listening — the concurrent, deadline-bounded
			// teardown must not hang on the dead collector.
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- providers.Shutdown(ctx) }()
			select {
			case <-done:
				// Returned within the bound (error or nil both acceptable —
				// a dead collector may surface a flush error).
			case <-time.After(6 * time.Second):
				t.Fatal("Providers.Shutdown did not return within the bounded window")
			}
		})
	}
}

// TestSetupUnsupportedProtocolReturnsError confirms Setup fails fast on a
// bad protocol (via Config.Validate) without mutating any global provider.
func TestSetupUnsupportedProtocolReturnsError(t *testing.T) {
	withRestoredGlobals(t)
	before := otel.GetTracerProvider()

	providers, err := Setup(context.Background(), Config{Endpoint: "localhost:1", Protocol: "carrier-pigeon"})
	if err == nil {
		t.Fatal("Setup(bad protocol) error = nil, want an error")
	}
	if providers != nil {
		t.Errorf("Setup(bad protocol) providers = %v, want nil", providers)
	}
	if otel.GetTracerProvider() != before {
		t.Error("global TracerProvider changed despite Setup failing; want it untouched")
	}
}

// TestSetupRejectsHeadersOnInsecureEndpoint confirms the CWE-319 guard:
// Setup refuses to start when OTLP headers (a collector auth token) would
// be sent to a non-https endpoint.
func TestSetupRejectsHeadersOnInsecureEndpoint(t *testing.T) {
	withRestoredGlobals(t)
	_, err := Setup(context.Background(), Config{
		Endpoint: "otel-collector.internal:4317", // scheme-less => insecure
		Headers:  map[string]string{"authorization": "Bearer secret"},
	})
	if err == nil {
		t.Fatal("Setup(headers + insecure endpoint) error = nil, want a cleartext-headers rejection")
	}
}

func TestConfigValidateCleartextHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "headers over scheme-less endpoint rejected",
			cfg:     Config{Endpoint: "collector:4317", Headers: map[string]string{"authorization": "Bearer x"}},
			wantErr: true,
		},
		{
			name:    "headers over http rejected",
			cfg:     Config{Endpoint: "http://collector/otlp", Protocol: ProtocolHTTP, Headers: map[string]string{"authorization": "Bearer x"}},
			wantErr: true,
		},
		{
			name: "headers over https allowed",
			cfg:  Config{Endpoint: "https://collector/otlp", Protocol: ProtocolHTTP, Headers: map[string]string{"authorization": "Bearer x"}},
		},
		{
			name: "no headers over insecure endpoint allowed",
			cfg:  Config{Endpoint: "collector:4317"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestExporterBuildersRejectUnknownProtocol covers the default branch of
// each per-signal builder directly — Setup's own Validate() now rejects a
// bad protocol before these are reached, so they are exercised here to keep
// that defensive branch alive.
func TestExporterBuildersRejectUnknownProtocol(t *testing.T) {
	t.Parallel()
	cfg := Config{Endpoint: "localhost:1", Protocol: "bogus"}
	if _, err := buildTraceExporter(context.Background(), cfg); err == nil {
		t.Error("buildTraceExporter(bogus) error = nil, want an error")
	}
	if _, err := buildMetricExporter(context.Background(), cfg); err == nil {
		t.Error("buildMetricExporter(bogus) error = nil, want an error")
	}
	if _, err := buildLogExporter(context.Background(), cfg); err == nil {
		t.Error("buildLogExporter(bogus) error = nil, want an error")
	}
}

func TestStripURLScheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"localhost:4317", "localhost:4317"},
		{"http://localhost:4318", "localhost:4318"},
		{"https://otlp.example.com", "otlp.example.com"},
		{"https://otlp.example.com/otlp", "otlp.example.com"},
		{"https://otlp.example.com:443/otlp/v1/traces", "otlp.example.com:443"},
		{"host:4317/path", "host:4317"},
	}
	for _, tt := range tests {
		if got := stripURLScheme(tt.in); got != tt.want {
			t.Errorf("stripURLScheme(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestURLPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"localhost:4317", ""},
		{"https://otlp.example.com", ""},
		{"https://otlp.example.com/otlp", "/otlp"},
		{"http://host:4318/otlp/base", "/otlp/base"},
	}
	for _, tt := range tests {
		if got := urlPath(tt.in); got != tt.want {
			t.Errorf("urlPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestJoinSignalPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		base, signal, want string
	}{
		{"/otlp", "traces", "/otlp/v1/traces"},
		{"/otlp/", "metrics", "/otlp/v1/metrics"},
		{"/base", "logs", "/base/v1/logs"},
	}
	for _, tt := range tests {
		if got := joinSignalPath(tt.base, tt.signal); got != tt.want {
			t.Errorf("joinSignalPath(%q, %q) = %q, want %q", tt.base, tt.signal, got, tt.want)
		}
	}
}

func TestIsInsecureEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"https://otlp.example.com", false},
		{"http://localhost:4318", true},
		{"localhost:4317", true}, // scheme-less: the local-collector default
	}
	for _, tt := range tests {
		if got := isInsecureEndpoint(tt.in); got != tt.want {
			t.Errorf("isInsecureEndpoint(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseOTLPHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "single", in: "authorization=Bearer abc", want: map[string]string{"authorization": "Bearer abc"}},
		{name: "multiple with spaces", in: "authorization=Bearer abc, x-tenant = acme", want: map[string]string{"authorization": "Bearer abc", "x-tenant": "acme"}},
		{name: "value contains equals", in: "authorization=Bearer a=b=c", want: map[string]string{"authorization": "Bearer a=b=c"}},
		{name: "trailing comma skipped", in: "k=v,", want: map[string]string{"k": "v"}},
		{name: "pair without equals skipped", in: "novalue,k=v", want: map[string]string{"k": "v"}},
		{name: "empty key skipped", in: "=v,k=v", want: map[string]string{"k": "v"}},
		{name: "all junk yields nil", in: ",,novalue,=x", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseOTLPHeaders(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseOTLPHeaders(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
