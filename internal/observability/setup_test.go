package observability

import (
	"context"
	"reflect"
	"testing"
)

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
