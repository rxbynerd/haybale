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
	"errors"
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

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rxbynerd/haybale/internal/config"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
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

// newJWTTestAuth builds a single-issuer, file-backed JWTAuthenticator and
// mints a matching, currently-valid ES256 token whose `sub` is id. The signing
// key is generated for the test and never leaves it.
func newJWTTestAuth(t *testing.T, id string) (identity.Authenticator, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk, err := jwkset.NewJWKFromKey(key.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "k1", ALG: jwkset.AlgES256, USE: jwkset.UseSig},
	})
	if err != nil {
		t.Fatalf("jwkset.NewJWKFromKey: %v", err)
	}
	store := jwkset.NewMemoryStorage()
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		t.Fatalf("store.KeyWrite: %v", err)
	}
	raw, err := store.JSONPublic(context.Background())
	if err != nil {
		t.Fatalf("store.JSONPublic: %v", err)
	}
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, raw, 0o600); err != nil {
		t.Fatalf("os.WriteFile(jwks.json): %v", err)
	}

	auth, err := identity.NewJWTAuthenticator(context.Background(), []identity.IssuerConfig{{
		Issuer:           "https://issuer.example",
		JWKSFile:         jwksPath,
		Algorithms:       []string{"ES256"},
		Audiences:        []string{"https://haybale.internal"},
		Leeway:           time.Minute,
		IdentityTemplate: "{sub}",
	}}, discardLogger())
	if err != nil {
		t.Fatalf("identity.NewJWTAuthenticator: %v", err)
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "https://haybale.internal",
		"sub": id,
		"jti": "test-jti",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return auth, signed
}

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
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(policy.yaml): %v", err)
	}

	// The jwksFile need not exist: these tests only exercise Validate()
	// (which is structural for the identity block — it does not read the
	// JWKS) plus buildUpstreams/buildCredentialSources. The live JWKS
	// fetch happens in BuildAuthenticator, which these tests never call.
	return &config.Config{
		LogLevel: "info",
		Identity: config.IdentityConfig{Type: "jwt", Issuers: []config.IssuerConfig{{
			Issuer:           "https://issuer.example",
			JWKSFile:         filepath.Join(dir, "jwks.json"),
			Audiences:        config.StringList{"https://haybale.internal"},
			IdentityTemplate: "{sub}",
		}}},
		Policy: config.PolicyConfig{Path: policyPath},
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
	// buildUpstreams reuses the *url.URL Validate() parsed onto each Upstream
	// rather than re-parsing BaseURL, so validation must run first.
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

	srv, listenAndServe, scheme, err := newServer(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("newServer() unexpected error: %v", err)
	}
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

	srv, _, scheme, err := newServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("newServer() unexpected error: %v", err)
	}
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

// TestNewServerRejectsUnvalidatedTLSConfig asserts newServer fails
// cleanly (an error, not a nil-pointer panic on *cfg.TLS.Certificate())
// when handed a Config whose "tls" block is enabled but was never run
// through config.Validate() — the same "caller forgot to call
// Validate()" caller-bug scenario
// TestBuildCredentialSourcesRejectsUnvalidatedConfig already covers for
// buildCredentialSources, and buildUpstreams for ParsedBaseURL.
func TestNewServerRejectsUnvalidatedTLSConfig(t *testing.T) {
	cfg := &config.Config{
		Upstreams: []config.Upstream{{Host: "github.com", BaseURL: "https://github.com"}},
		TLS:       config.TLSConfig{CertPath: "/etc/haybale/tls.crt", KeyPath: "/etc/haybale/tls.key"},
	}
	// Deliberately not calling cfg.Validate(): TLS.Enabled() is true
	// (both CertPath/KeyPath are set) but TLS.Certificate() stays nil,
	// since only Validate() ever populates it.

	srv, listenAndServe, scheme, err := newServer(cfg, http.NotFoundHandler())
	if err == nil {
		t.Fatal("newServer() = nil error, want an error for an unvalidated TLS config")
	}
	if srv != nil {
		t.Errorf("newServer() srv = %v, want nil alongside a non-nil error", srv)
	}
	if listenAndServe != nil {
		t.Error("newServer() listenAndServe != nil, want nil alongside a non-nil error")
	}
	if scheme != "" {
		t.Errorf("newServer() scheme = %q, want %q alongside a non-nil error", scheme, "")
	}
}

// TestServeWithGracefulDrainWaitsForInFlightRequest confirms a
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
	auth, token := newJWTTestAuth(t, testID)
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
	p, err := proxy.New(map[string]*url.URL{"host": upstreamURL}, map[string]upstream.CredentialSource{"host": credSrc}, auth, eng, discardLogger(), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("proxy.New(): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := &http.Server{Handler: p} //nolint:gosec // G112: this test's whole point is exercising Shutdown against a controlled localhost listener with a single client goroutine, not an internet-facing server — a ReadHeaderTimeout is production's own newServer's job (see TestNewServerPlainHTTP/TestNewServerTLSEnabled)

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

// TestServeWithGracefulDrainExceedsFiniteTimeout confirms a finite drain
// timeout logs a warning and returns ErrDrainTimeoutExceeded without waiting
// indefinitely for an in-flight request.
func TestServeWithGracefulDrainExceedsFiniteTimeout(t *testing.T) {
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

	const testID = "run-drain-timeout-test"
	auth, token := newJWTTestAuth(t, testID)
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
	p, err := proxy.New(map[string]*url.URL{"host": upstreamURL}, map[string]upstream.CredentialSource{"host": credSrc}, auth, eng, discardLogger(), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("proxy.New(): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := &http.Server{Handler: p} //nolint:gosec // G112: same justification as TestServeWithGracefulDrainWaitsForInFlightRequest — this test's whole point is exercising Shutdown against a controlled localhost listener with a single client goroutine

	// A real (non-discard) logger, mutex-free but safe here: only the
	// serveWithGracefulDrain goroutine below ever writes to it, and this
	// test only reads logBuf.String() after receiving from drainDone,
	// which happens-after every log call serveWithGracefulDrain makes —
	// see the log-buffer-race memory note for why that ordering matters.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const shortDrainTimeout = 50 * time.Millisecond
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- serveWithGracefulDrain(ctx, srv, p, shortDrainTimeout, func() error { return srv.Serve(ln) }, logger)
	}()

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/host/owner/repo.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("haybale-test", token)

	reqDone := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqDone <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		reqDone <- err
	}()

	// Wait until the request is genuinely in flight, then simulate the
	// SIGTERM/SIGINT runServe's signal.NotifyContext would have caught —
	// exactly as TestServeWithGracefulDrainWaitsForInFlightRequest does.
	// Unlike that test, release is never closed here before asserting on
	// drainDone: the whole point of this test is that shortDrainTimeout
	// elapses while the request is still genuinely stuck.
	<-reachedUpstream
	cancel()

	select {
	case err := <-drainDone:
		if !errors.Is(err, ErrDrainTimeoutExceeded) {
			t.Fatalf("serveWithGracefulDrain() error = %v, want ErrDrainTimeoutExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveWithGracefulDrain did not return within 5s of shortDrainTimeout elapsing — it must not wait indefinitely once a finite, configured drainTimeout is exceeded")
	}

	if !strings.Contains(logBuf.String(), "drainTimeout exceeded") {
		t.Errorf("log output = %q, want a warning mentioning the exceeded drainTimeout", logBuf.String())
	}

	// Only now unblock the still-in-flight request: srv.Shutdown doesn't
	// force-close it (see serveWithGracefulDrain's own doc comment), so
	// it completes normally once release closes — proving
	// ErrDrainTimeoutExceeded really was returned without waiting for
	// it, not merely coincidentally soon before it finished anyway.
	close(release)
	select {
	case err := <-reqDone:
		if err != nil {
			t.Errorf("in-flight request error = %v, want nil once unblocked", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete after unblocking release")
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

// TestWireCredentialSourceMetrics is the metrics counterpart of
// TestWireCredentialSourceLoggers: it asserts wireCredentialSourceMetrics
// installs the metrics into every *upstream.GitHubAppSource (so its mints
// are counted) and skips a StaticSource without panicking.
func TestWireCredentialSourceMetrics(t *testing.T) {
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

	metrics, reader := observability.NewTestMetrics()
	wireCredentialSourceMetrics(sources, metrics)

	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	if _, err := ghSrc.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	// staticSrc must be skipped by the type assertion, not panic.
	if _, err := staticSrc.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("static Credentials() unexpected error: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var minted int64
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != "haybale.tokens.minted.total" {
				continue
			}
			if sum, ok := md.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					minted += dp.Value
				}
			}
		}
	}
	if minted != 1 {
		t.Errorf("tokens.minted total = %d, want 1 (the GitHubAppSource mint should be counted)", minted)
	}
}

// TestInstrumentedHandlerWrapsOnlyWhenEnabled asserts instrumentedHandler
// returns the handler untouched when telemetry is disabled (so a disabled
// deployment carries none of otelhttp's per-request wrapping) and wraps it
// when enabled.
func TestInstrumentedHandlerWrapsOnlyWhenEnabled(t *testing.T) {
	mux := http.NewServeMux() // a comparable, concrete http.Handler

	disabled := &config.Config{}
	if got := instrumentedHandler(disabled, mux); got != http.Handler(mux) {
		t.Error("disabled telemetry: instrumentedHandler wrapped the handler; want it returned unchanged")
	}

	enabled := &config.Config{Telemetry: config.TelemetryConfig{Endpoint: "localhost:4317"}}
	if got := instrumentedHandler(enabled, mux); got == http.Handler(mux) {
		t.Error("enabled telemetry: instrumentedHandler returned the handler unchanged; want it wrapped by otelhttp")
	}
}

// TestTelemetryConfigTranslation asserts the config->observability.Config
// bridge maps every field and resolves the OTLP header secret from the
// environment variable named by headersEnv (never from the YAML).
func TestTelemetryConfigTranslation(t *testing.T) {
	t.Setenv("HB_TEST_OTLP_HEADERS", "authorization=Bearer tok,x-tenant=acme")
	cfg := &config.Config{Telemetry: config.TelemetryConfig{
		Endpoint:         "https://collector/otlp",
		Protocol:         "http/protobuf",
		Environment:      "prod",
		ServiceNamespace: "team-a",
		HeadersEnv:       "HB_TEST_OTLP_HEADERS",
	}}

	got := telemetryConfig(cfg)
	if got.Endpoint != "https://collector/otlp" {
		t.Errorf("Endpoint = %q, want https://collector/otlp", got.Endpoint)
	}
	if got.Protocol != "http/protobuf" {
		t.Errorf("Protocol = %q, want http/protobuf", got.Protocol)
	}
	if got.Resource.Environment != "prod" || got.Resource.ServiceNamespace != "team-a" {
		t.Errorf("Resource = %+v, want Environment=prod ServiceNamespace=team-a", got.Resource)
	}
	if got.Resource.Version != version {
		t.Errorf("Resource.Version = %q, want the build version %q", got.Resource.Version, version)
	}
	if got.Headers["authorization"] != "Bearer tok" || got.Headers["x-tenant"] != "acme" {
		t.Errorf("Headers = %v, want the parsed headersEnv value", got.Headers)
	}
}

// TestTelemetryConfigNoHeadersEnv confirms an unset headersEnv yields nil
// headers (not a spurious empty map, and no env read).
func TestTelemetryConfigNoHeadersEnv(t *testing.T) {
	cfg := &config.Config{Telemetry: config.TelemetryConfig{Endpoint: "localhost:4317"}}
	if got := telemetryConfig(cfg); got.Headers != nil {
		t.Errorf("Headers = %v, want nil when headersEnv is unset", got.Headers)
	}
}
