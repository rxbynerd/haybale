package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/proxy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// discardLogger is the *slog.Logger every test in this package hands to
// proxy.New: haybale's own request/security logging isn't what these
// tests assert on (unlike internal/proxy's unit tests), so it's
// discarded rather than cluttering `go test -v` output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testJWTIssuer is the issuer string every minted e2e token carries; it
// is arbitrary (a file-backed JWKS is used, so nothing is fetched), but
// must match between the authenticator and the token.
const testJWTIssuer = "https://control-plane.e2e.internal"

// testJWTAudience is the audience every minted e2e token carries.
const testJWTAudience = "https://haybale.e2e.internal"

// mintTestToken builds a real, file-backed JWTAuthenticator and mints a
// fresh, currently-valid ES256 token whose identity (via a "{sub}"
// template) is id — exercising the production JWT verifier, not a stub,
// since this harness's whole purpose is running production code against a
// real git subprocess. It returns the Authenticator alongside the compact
// token a git remote URL's Basic-auth password should carry. A per-call
// signing key is generated fresh and its public half written to a JWKS
// file the authenticator trusts.
func mintTestToken(t *testing.T, id string) (identity.Authenticator, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(): %v", err)
	}
	jwk, err := jwkset.NewJWKFromKey(key.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "e2e-key", ALG: jwkset.AlgES256, USE: jwkset.UseSig},
	})
	if err != nil {
		t.Fatalf("jwkset.NewJWKFromKey(): %v", err)
	}
	store := jwkset.NewMemoryStorage()
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		t.Fatalf("store.KeyWrite(): %v", err)
	}
	raw, err := store.JSONPublic(context.Background())
	if err != nil {
		t.Fatalf("store.JSONPublic(): %v", err)
	}
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, raw, 0o600); err != nil {
		t.Fatalf("os.WriteFile(jwks.json): %v", err)
	}

	auth, err := identity.NewJWTAuthenticator(context.Background(), []identity.IssuerConfig{{
		Issuer:           testJWTIssuer,
		JWKSFile:         jwksPath,
		Algorithms:       []string{"ES256"},
		Audiences:        []string{testJWTAudience},
		Leeway:           time.Minute,
		IdentityTemplate: "{sub}",
	}}, discardLogger())
	if err != nil {
		t.Fatalf("identity.NewJWTAuthenticator(): %v", err)
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": testJWTIssuer,
		"aud": testJWTAudience,
		"sub": id,
		"jti": "e2e-" + id,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "e2e-key"
	token, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return auth, token
}

// newPolicy builds a real policy.GlobEngine (not a stub) from rules,
// failing the test immediately on an invalid rule rather than
// surfacing a confusing failure deeper in the test.
func newPolicy(t *testing.T, rules []policy.Rule) policy.Engine {
	t.Helper()
	engine, err := policy.NewGlobEngine(rules)
	if err != nil {
		t.Fatalf("policy.NewGlobEngine(): %v", err)
	}
	return engine
}

// repoKey returns the "{host}/{owner}/{repo}" string a policy.Rule's
// Repos patterns match against — the same joining internal/policy uses
// internally, duplicated here (it's unexported there) so tests can
// build rules scoped to exactly one repo without hardcoding the "/"
// join in three different test files.
func repoKey(host, owner, name string) string {
	return host + "/" + owner + "/" + name
}

// mustNewProxy builds a *proxy.Proxy via proxy.New, failing the test
// immediately if construction returns an error — mirrors the
// fail-fast-on-a-test-bug style mintTestToken/newPolicy already use for
// this harness's other constructors.
func mustNewProxy(t *testing.T, upstreams map[string]*url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(upstreams, credentialSources, authenticator, policyEngine, logger, observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	return p
}

// newStaticCredentialSource builds an upstream.StaticSource, failing the
// test immediately on the (in practice unreachable, since every call
// site here passes a non-empty username/password) constructor error.
func newStaticCredentialSource(t *testing.T, username, password string) upstream.CredentialSource {
	t.Helper()
	src, err := upstream.NewStaticSource(username, password)
	if err != nil {
		t.Fatalf("upstream.NewStaticSource() error = %v", err)
	}
	return src
}

// credentialsForHost builds the single-entry credentialSources map
// mustNewProxy expects, mapping hostKey to a StaticSource returning
// username/password — the shape every e2e test in this package uses,
// since haybale only ever routes to the one fake upstream hostKey names.
func credentialsForHost(t *testing.T, hostKey, username, password string) map[string]upstream.CredentialSource {
	t.Helper()
	return map[string]upstream.CredentialSource{hostKey: newStaticCredentialSource(t, username, password)}
}

// syncBuffer is safe for the concurrent access created when haybale's request
// goroutine writes its post-response log
// line only after the client can already see the completed response —
// an ordinary streaming-HTTP race, not a haybale bug — so a plain
// bytes.Buffer trips `go test -race` here exactly as it does in
// internal/proxy's own test suite. See waitForLogSubstring below for the
// accompanying TOCTOU fix.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLogSubstring polls buf until its contents contain want or a
// short deadline elapses, then returns whatever it has — closing the gap
// between haybale's own goroutine finishing its post-response log call
// and the test goroutine's HTTP client call already having returned.
func waitForLogSubstring(buf *syncBuffer, want string) string {
	deadline := time.Now().Add(2 * time.Second)
	for {
		s := buf.String()
		if strings.Contains(s, want) || time.Now().After(deadline) {
			return s
		}
		time.Sleep(time.Millisecond)
	}
}

// withToken returns rawURL with token embedded as the Basic-auth
// password. The username is arbitrary — identity's credential extraction
// ignores it, and so does git — so a fixed placeholder is used
// throughout rather than plumbing a meaningless value through every
// call site.
func withToken(t *testing.T, rawURL, token string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	u.User = url.UserPassword("haybale-e2e", token)
	return u.String()
}
