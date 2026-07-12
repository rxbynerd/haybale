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

// buildTestConfig returns a *config.Config with two upstreams, each
// carrying a "static" credential block that Validate() can build
// successfully once tokenEnv's environment variable is set (see
// t.Setenv in callers) — the shared fixture TestBuildUpstreams and
// TestBuildCredentialSources both validate before exercising their
// respective build function.
func buildTestConfig(t *testing.T, tokenEnv string) *config.Config {
	t.Helper()
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

	return &config.Config{
		LogLevel: "info",
		Identity: config.IdentityConfig{Type: "static-token-file", Path: identityPath},
		Policy:   config.PolicyConfig{Path: policyPath},
		Upstreams: []config.Upstream{
			{Host: "github.com", BaseURL: "https://github.com", Credential: config.CredentialConfig{Type: "static", TokenEnv: tokenEnv}},
			{Host: "git.internal.example", BaseURL: "https://git.internal.example:8443", Credential: config.CredentialConfig{Type: "static", Username: "git", TokenEnv: tokenEnv}},
		},
	}
}

func TestBuildUpstreams(t *testing.T) {
	const tokenEnv = "HAYBALE_SERVE_TEST_TOKEN" //nolint:gosec // G101: this is an environment-variable *name*, not a credential value — the actual test token is the separate, non-secret literal passed to t.Setenv below
	t.Setenv(tokenEnv, "test-token-value")
	cfg := buildTestConfig(t, tokenEnv)
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

// TestBuildCredentialSources mirrors TestBuildUpstreams for the
// credential-source map: buildCredentialSources must reuse the
// upstream.CredentialSource Validate() already built for each Upstream,
// keyed by the same host.
func TestBuildCredentialSources(t *testing.T) {
	const tokenEnv = "HAYBALE_SERVE_TEST_TOKEN" //nolint:gosec // G101: this is an environment-variable *name*, not a credential value — the actual test token is the separate, non-secret literal passed to t.Setenv below
	t.Setenv(tokenEnv, "test-token-value")
	cfg := buildTestConfig(t, tokenEnv)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	sources, err := buildCredentialSources(cfg)
	if err != nil {
		t.Fatalf("buildCredentialSources: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("len(sources) = %d, want 2", len(sources))
	}
	for _, host := range []string{"github.com", "git.internal.example"} {
		if sources[host] == nil {
			t.Errorf("sources[%q] = nil, want a CredentialSource", host)
		}
	}
}

// TestBuildCredentialSourcesRejectsUnvalidatedConfig asserts
// buildCredentialSources fails loudly (rather than building a map with a
// nil entry) if handed a Config whose Upstreams never went through
// Validate() — mirroring buildUpstreams' own ParsedBaseURL nil check.
func TestBuildCredentialSourcesRejectsUnvalidatedConfig(t *testing.T) {
	cfg := &config.Config{
		Upstreams: []config.Upstream{{Host: "github.com", BaseURL: "https://github.com"}},
	}
	if _, err := buildCredentialSources(cfg); err == nil {
		t.Fatal("buildCredentialSources() = nil error, want an error for an unvalidated config")
	}
}
