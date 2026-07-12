package e2e

import (
	"bytes"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/identity"
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

// mintTestToken mints a fresh identity token for id via the real
// identity.NewToken/NewStaticTokenAuthenticator — not a test stub, since
// this harness's whole purpose is exercising production code against a
// real git subprocess — and returns an Authenticator backed by only that
// one identity, alongside the raw token a git remote URL's Basic-auth
// password should carry.
func mintTestToken(t *testing.T, id string) (identity.Authenticator, string) {
	t.Helper()
	token, digestHex, err := identity.NewToken()
	if err != nil {
		t.Fatalf("identity.NewToken(): %v", err)
	}
	auth, err := identity.NewStaticTokenAuthenticator(map[string]string{id: "sha256:" + digestHex})
	if err != nil {
		t.Fatalf("identity.NewStaticTokenAuthenticator(): %v", err)
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
	p, err := proxy.New(upstreams, credentialSources, authenticator, policyEngine, logger)
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

// syncBuffer is a mutex-guarded byte buffer safe for the concurrent
// access pattern the M3 credential tests exercise: haybale's own
// goroutine (serving the proxied request) writes its post-response log
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
// password. The username is arbitrary — identity.StaticTokenAuthenticator
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
