package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/rxbynerd/haybale/internal/config"
)

// fakeTokenDigestHex is a structurally valid (64 hex char) SHA-256
// digest good enough for a test identities.yaml fixture, which only
// needs to parse — it never needs to correspond to any real token.
const fakeTokenDigestHex = "1122334411223344112233441122334411223344112233441122334411223344"

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo}, // unreachable via a Validate()'d config, defaults safely
	}
	for _, tt := range tests {
		if got := parseLogLevel(tt.level); got != tt.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestBuildUpstreams(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identities.yaml")
	identityContent := "identities:\n  - id: run-1\n    tokenDigest: sha256:" + fakeTokenDigestHex + "\n"
	if err := os.WriteFile(identityPath, []byte(identityContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile(identities.yaml): %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(policy.yaml): %v", err)
	}

	cfg := &config.Config{
		LogLevel: "info",
		Identity: config.IdentityConfig{Type: "static-token-file", Path: identityPath},
		Policy:   config.PolicyConfig{Path: policyPath},
		Upstreams: []config.Upstream{
			{Host: "github.com", BaseURL: "https://github.com"},
			{Host: "git.internal.example", BaseURL: "https://git.internal.example:8443"},
		},
	}
	// buildUpstreams reuses the *url.URL Validate() parsed onto each
	// Upstream (R1) rather than re-parsing BaseURL itself, so Validate()
	// must run first here — exactly as runServe already does via
	// config.Load.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	upstreams, err := buildUpstreams(cfg)
	if err != nil {
		t.Fatalf("buildUpstreams: %v", err)
	}
	if len(upstreams) != 2 {
		t.Fatalf("len(upstreams) = %d, want 2", len(upstreams))
	}
	if got := upstreams["github.com"].String(); got != "https://github.com" {
		t.Errorf(`upstreams["github.com"] = %q, want %q`, got, "https://github.com")
	}
	if got := upstreams["git.internal.example"].String(); got != "https://git.internal.example:8443" {
		t.Errorf(`upstreams["git.internal.example"] = %q, want %q`, got, "https://git.internal.example:8443")
	}
}
