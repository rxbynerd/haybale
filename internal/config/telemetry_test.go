package config

import (
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/observability"
)

// TestOTLPProtocolConstantsMatchObservability is the round-trip check the
// config.go doc comment relies on: internal/config deliberately hard-codes
// the OTLP protocol strings rather than importing observability's
// constants (to keep the OTel SDK out of config's production dependency
// graph), so this test-only cross-check pins the two definitions together.
// If observability renames or revalues a protocol, this fails rather than
// letting a config that parses cleanly reach a Setup that rejects it.
func TestOTLPProtocolConstantsMatchObservability(t *testing.T) {
	t.Parallel()
	if otlpProtocolGRPC != observability.ProtocolGRPC {
		t.Errorf("otlpProtocolGRPC = %q, observability.ProtocolGRPC = %q; they must match", otlpProtocolGRPC, observability.ProtocolGRPC)
	}
	if otlpProtocolHTTP != observability.ProtocolHTTP {
		t.Errorf("otlpProtocolHTTP = %q, observability.ProtocolHTTP = %q; they must match", otlpProtocolHTTP, observability.ProtocolHTTP)
	}
}

func TestTelemetryConfigEnabled(t *testing.T) {
	t.Parallel()
	if (TelemetryConfig{}).Enabled() {
		t.Error("empty TelemetryConfig.Enabled() = true, want false")
	}
	if !(TelemetryConfig{Endpoint: "localhost:4317"}).Enabled() {
		t.Error("TelemetryConfig with endpoint Enabled() = false, want true")
	}
}

func TestTelemetryConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tel     TelemetryConfig
		wantErr string
	}{
		{name: "disabled is valid", tel: TelemetryConfig{}},
		{name: "disabled ignores protocol", tel: TelemetryConfig{Protocol: "nonsense"}},
		{name: "enabled default protocol", tel: TelemetryConfig{Endpoint: "localhost:4317"}},
		{name: "enabled grpc", tel: TelemetryConfig{Endpoint: "localhost:4317", Protocol: otlpProtocolGRPC}},
		{name: "enabled http", tel: TelemetryConfig{Endpoint: "https://otlp/otlp", Protocol: otlpProtocolHTTP}},
		{
			name:    "enabled bad protocol",
			tel:     TelemetryConfig{Endpoint: "localhost:4317", Protocol: "carrier-pigeon"},
			wantErr: "protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.tel.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() error = nil, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestValidateRejectsBadTelemetryProtocol confirms a bad telemetry
// protocol fails the whole Config.Validate (i.e. the telemetry block is
// wired into the top-level fail-fast path), so a typo refuses startup
// rather than surfacing on the first export.
func TestValidateRejectsBadTelemetryProtocol(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	cfg := Config{
		Listen:    ":8466",
		LogLevel:  "info",
		Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
		Policy:    PolicyConfig{Path: policyPath},
		Upstreams: []Upstream{{Host: "github.com", BaseURL: "https://github.com", Credential: validCredential}},
		Telemetry: TelemetryConfig{Endpoint: "localhost:4317", Protocol: "carrier-pigeon"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want a telemetry protocol error")
	}
	if !strings.Contains(err.Error(), "telemetry") {
		t.Errorf("Validate() error = %q, want it to mention telemetry", err.Error())
	}
}
