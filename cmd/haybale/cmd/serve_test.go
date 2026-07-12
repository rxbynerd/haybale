package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/config"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/upstream"
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

// newFakeGitHubAppServer stands up a minimal httptest stand-in for the
// two GitHub REST endpoints upstream.GitHubAppSource calls, resolving to
// installationID and always minting token — good enough to observe
// wireCredentialSourceLoggers actually took effect (see
// TestWireCredentialSourceLoggers below), not to re-test
// GitHubAppSource's own behavior (internal/upstream's own tests cover
// that).
func newFakeGitHubAppServer(t *testing.T, installationID int64, token string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id": %d}`, installationID)
	})
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token": %q, "expires_at": %q}`, token, time.Now().Add(time.Hour).Format(time.RFC3339))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// writeTestRSAKeyPEM generates a throwaway RSA private key (never
// committed anywhere — generated fresh every test run) PEM-encoded, good
// enough to construct a GitHubAppSource in these tests.
func writeTestRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// TestWireCredentialSourceLoggers asserts wireCredentialSourceLoggers
// installs logger into every *upstream.GitHubAppSource in sources (so its
// security.EventTokenMinted events go through the same ScrubHandler-
// wrapped logger as everything else in the process — see the function's
// own doc comment for why GitHubAppSource can't just take that logger at
// construction time) and leaves a StaticSource untouched.
func TestWireCredentialSourceLoggers(t *testing.T) {
	fakeURL := newFakeGitHubAppServer(t, 42, "fake-minted-token")
	ghSrc, err := upstream.NewGitHubAppSource(upstream.GitHubAppConfig{
		AppID: 1, PrivateKeyPEM: writeTestRSAKeyPEM(t), APIBaseURL: fakeURL,
	})
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}
	staticSrc, err := upstream.NewStaticSource("x-access-token", "static-token") //nolint:gosec // G101: fixed, fake test-only credential
	if err != nil {
		t.Fatalf("NewStaticSource: %v", err)
	}

	sources := map[string]upstream.CredentialSource{
		"github.com":           ghSrc,
		"git.internal.example": staticSrc,
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	wireCredentialSourceLoggers(sources, logger)

	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	if _, err := ghSrc.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), `"event":"token_minted"`) {
		t.Errorf("log output = %q, want a token_minted event logged through the installed logger", buf.String())
	}

	// staticSrc has no SetLogger method at all — wireCredentialSourceLoggers
	// must simply skip it (via the type assertion), not panic.
	if _, err := staticSrc.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
}
