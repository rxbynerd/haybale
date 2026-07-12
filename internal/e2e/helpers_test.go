package e2e

import (
	"io"
	"log/slog"
	"net/url"
	"testing"

	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
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
