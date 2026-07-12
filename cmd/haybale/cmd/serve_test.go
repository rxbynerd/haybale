package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/config"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/proxy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// discardLogger is the *slog.Logger tests in this file hand to
// newServer/serveWithGracefulDrain/proxy.New when the log output itself
// isn't what the test asserts on — mirroring internal/proxy and
// internal/e2e's own discardLogger helpers.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeTestTLSCertKeyFiles generates a throwaway, self-signed ECDSA
// certificate/key pair (never committed anywhere — generated fresh every
// test run) and writes them PEM-encoded to two files under t.TempDir(),
// returning their paths — mirrors internal/config/config_test.go's
// helper of the same name/purpose.
func writeTestTLSCertKeyFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "haybale-serve-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// TestNewServerTLSEnabled dials this certificate by IP
		// (127.0.0.1), not by hostname, so it needs an IP SAN — a
		// CommonName alone is not checked by Go's TLS client verifier.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("os.WriteFile(cert.pem): %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("os.WriteFile(key.pem): %v", err)
	}
	return certPath, keyPath
}

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

// TestNewServerPlainHTTP asserts newServer builds a plain-HTTP server
// (nil TLSConfig, "http" scheme) for a Config whose "tls" block is left
// entirely empty — the default, documented (docs/security.md) as safe
// only for a cluster-internal deployment.
func TestNewServerPlainHTTP(t *testing.T) {
	const tokenEnv = "HAYBALE_SERVE_TEST_PLAIN_TOKEN" //nolint:gosec // G101: this is an environment-variable *name*, not a credential value
	t.Setenv(tokenEnv, "test-token-value")
	cfg := buildTestConfig(t, tokenEnv)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	srv, listenAndServe, scheme := newServer(cfg, http.NotFoundHandler())
	if scheme != "http" {
		t.Errorf("scheme = %q, want %q", scheme, "http")
	}
	if srv.TLSConfig != nil {
		t.Error("srv.TLSConfig != nil for a Config with TLS disabled")
	}
	if srv.Addr != cfg.Listen {
		t.Errorf("srv.Addr = %q, want cfg.Listen %q", srv.Addr, cfg.Listen)
	}
	if srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("srv.ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if listenAndServe == nil {
		t.Fatal("listenAndServe = nil")
	}
}

// TestNewServerTLSEnabled asserts newServer wires srv.TLSConfig from the
// certificate config.Validate() already loaded, with the documented
// MinVersion floor, and that the result actually serves a working TLS
// handshake — not merely that the fields are set to the expected shape.
func TestNewServerTLSEnabled(t *testing.T) {
	const tokenEnv = "HAYBALE_SERVE_TEST_TLS_TOKEN" //nolint:gosec // G101: this is an environment-variable *name*, not a credential value
	t.Setenv(tokenEnv, "test-token-value")
	cfg := buildTestConfig(t, tokenEnv)
	certPath, keyPath := writeTestTLSCertKeyFiles(t)
	cfg.TLS = config.TLSConfig{CertPath: certPath, KeyPath: keyPath}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	srv, _, scheme := newServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if scheme != "https" {
		t.Errorf("scheme = %q, want %q", scheme, "https")
	}
	if srv.TLSConfig == nil {
		t.Fatal("srv.TLSConfig = nil, want a populated TLS config")
	}
	if len(srv.TLSConfig.Certificates) != 1 {
		t.Fatalf("len(srv.TLSConfig.Certificates) = %d, want 1", len(srv.TLSConfig.Certificates))
	}
	if srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("srv.TLSConfig.MinVersion = %#x, want tls.VersionTLS12 (%#x)", srv.TLSConfig.MinVersion, tls.VersionTLS12)
	}

	// Prove the wiring actually works: serve on a real listener wrapped in
	// srv.TLSConfig (srv.Serve, not the listenAndServe closure, so this
	// test controls the listener/port directly rather than guessing which
	// ephemeral port ListenAndServeTLS would have bound), then dial it
	// with a client trusting exactly the self-signed cert under test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	t.Cleanup(func() { _ = srv.Close() })

	certPEM, err := os.ReadFile(certPath) //nolint:gosec // certPath is a path this test itself just wrote, not attacker input
	if err != nil {
		t.Fatalf("os.ReadFile(cert): %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test certificate")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("client.Get over TLS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServeWithGracefulDrainWaitsForInFlightRequest is the automated
// equivalent of M5's "kill -TERM mid-clone" acceptance criterion: a
// request that's already streaming a response (standing in for a large
// git clone/push still in flight) must be allowed to finish once a
// shutdown signal arrives, while srv.Shutdown blocks until it does — and
// only after that, no new connection is accepted.
func TestServeWithGracefulDrainWaitsForInFlightRequest(t *testing.T) {
	release := make(chan struct{})
	reachedUpstream := make(chan struct{})
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reachedUpstream)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		_, _ = w.Write([]byte("rest"))
	}))
	defer upstreamSrv.Close()

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-drain-test"
	token, digestHex, err := identity.NewToken()
	if err != nil {
		t.Fatalf("identity.NewToken(): %v", err)
	}
	auth, err := identity.NewStaticTokenAuthenticator(map[string]string{testID: "sha256:" + digestHex})
	if err != nil {
		t.Fatalf("identity.NewStaticTokenAuthenticator(): %v", err)
	}
	eng, err := policy.NewGlobEngine([]policy.Rule{
		{Identities: []string{testID}, Repos: []string{"host/owner/repo"}, Permissions: []policy.Permission{policy.PermissionRead}},
	})
	if err != nil {
		t.Fatalf("policy.NewGlobEngine(): %v", err)
	}
	credSrc, err := upstream.NewStaticSource("x-access-token", "upstream-secret") //nolint:gosec // G101: fixed, fake test-only credential
	if err != nil {
		t.Fatalf("upstream.NewStaticSource(): %v", err)
	}
	p, err := proxy.New(map[string]*url.URL{"host": upstreamURL}, map[string]upstream.CredentialSource{"host": credSrc}, auth, eng, discardLogger())
	if err != nil {
		t.Fatalf("proxy.New(): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := &http.Server{Handler: p}

	ctx, cancel := context.WithCancel(context.Background())
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- serveWithGracefulDrain(ctx, srv, p, 0, func() error { return srv.Serve(ln) }, discardLogger())
	}()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/host/owner/repo.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("haybale-test", token)

	type result struct {
		body []byte
		err  error
	}
	reqDone := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqDone <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		reqDone <- result{body: body, err: err}
	}()

	// Wait until the request is genuinely in flight — accepted by
	// haybale, authenticated, authorized, and proxied through to the fake
	// upstream, which is now itself blocked mid-response — before
	// simulating the SIGTERM/SIGINT runServe's signal.NotifyContext would
	// have caught.
	<-reachedUpstream
	cancel()

	// srv.Shutdown (invoked inside serveWithGracefulDrain's ctx.Done()
	// branch) blocks until the in-flight request above finishes — it must
	// not return, and drainDone must not fire, while the upstream (and so
	// the client's own request) is still waiting on release.
	select {
	case err := <-drainDone:
		t.Fatalf("serveWithGracefulDrain returned (err=%v) before the in-flight request finished — Shutdown must wait for it, not cut it off", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	if err := <-drainDone; err != nil {
		t.Errorf("serveWithGracefulDrain() error = %v, want nil", err)
	}

	res := <-reqDone
	if res.err != nil {
		t.Fatalf("in-flight request error = %v, want it to complete successfully despite the shutdown signal", res.err)
	}
	if string(res.body) != "partial-rest" {
		t.Errorf("in-flight request body = %q, want %q (the full streamed response, not truncated by shutdown)", res.body, "partial-rest")
	}

	// Only now, after Shutdown has fully returned, assert a fresh
	// connection attempt is refused — proving new connections stopped
	// being accepted once the drain completed.
	if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Error("net.DialTimeout succeeded after Shutdown returned, want connection refused")
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
