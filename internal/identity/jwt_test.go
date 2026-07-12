package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

// discardLogger is the logger every test here hands to NewJWTAuthenticator
// — the package logs auth failures at Debug and refresh warnings at Warn,
// none of which a passing test needs to see.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// signer is one in-test issuer's key material: a private key, its kid, and
// the golang-jwt SigningMethod tokens are minted with.
type signer struct {
	key    crypto.Signer
	pub    crypto.PublicKey
	kid    string
	method jwt.SigningMethod
	alg    jwkset.ALG
}

// newES256Signer mints a fresh ES256 signer with the given kid.
func newES256Signer(t *testing.T, kid string) signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return signer{key: key, pub: key.Public(), kid: kid, method: jwt.SigningMethodES256, alg: jwkset.AlgES256}
}

// newRS256Signer mints a fresh RS256 signer with the given kid.
func newRS256Signer(t *testing.T, kid string) signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return signer{key: key, pub: key.Public(), kid: kid, method: jwt.SigningMethodRS256, alg: jwkset.AlgRS256}
}

// jwksJSON builds a public JWKS document containing every signer's public
// key, each tagged with its kid and alg.
func jwksJSON(t *testing.T, signers ...signer) []byte {
	t.Helper()
	store := jwkset.NewMemoryStorage()
	for _, s := range signers {
		jwk, err := jwkset.NewJWKFromKey(s.pub, jwkset.JWKOptions{
			Metadata: jwkset.JWKMetadataOptions{KID: s.kid, ALG: s.alg, USE: jwkset.UseSig},
		})
		if err != nil {
			t.Fatalf("build jwk for kid %q: %v", s.kid, err)
		}
		if err := store.KeyWrite(context.Background(), jwk); err != nil {
			t.Fatalf("write jwk for kid %q: %v", s.kid, err)
		}
	}
	raw, err := store.JSONPublic(context.Background())
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// jwksFile writes the signers' public JWKS to a temp file and returns its
// path — the file-backed key source most tests here use (deterministic,
// no network).
func jwksFile(t *testing.T, signers ...signer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwksJSON(t, signers...), 0o600); err != nil {
		t.Fatalf("write jwks file: %v", err)
	}
	return path
}

// mint signs claims into a compact JWT with s's method and kid. An empty
// overrideAlg leaves the header alg as the method's own; a non-empty one
// forges the alg header (for algorithm-confusion tests) without changing
// the actual signature.
func mint(t *testing.T, s signer, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(s.method, claims)
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// baseClaims returns a fresh, currently-valid claim set for iss/aud.
func baseClaims(iss, aud string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": "run-123",
		"jti": "id-abc",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// basicAuthReq builds a request presenting token as the Basic-auth
// password (git's mechanism — the username is arbitrary).
func basicAuthReq(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/github.com/o/r.git/info/refs?service=git-upload-pack", nil)
	r.SetBasicAuth("git", token)
	return r
}

// contractIssuer is the issuer string the majority of tests verify against.
const contractIssuer = "https://control-plane.example.internal"

// newAuth builds a single-issuer file-backed authenticator for s, with the
// given identityTemplate and (optional) extra IssuerConfig tweaks applied.
func newAuth(t *testing.T, s signer, tmpl string, tweak func(*IssuerConfig)) *JWTAuthenticator {
	t.Helper()
	ic := IssuerConfig{
		Issuer:           contractIssuer,
		JWKSFile:         jwksFile(t, s),
		Algorithms:       []string{"ES256", "RS256"},
		Audiences:        []string{"https://haybale.internal"},
		Leeway:           60 * time.Second,
		IdentityTemplate: tmpl,
	}
	if tweak != nil {
		tweak(&ic)
	}
	a, err := NewJWTAuthenticator(context.Background(), []IssuerConfig{ic}, discardLogger())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	return a
}

func TestAuthenticateHappyPathContract(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", nil)

	id, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, baseClaims(contractIssuer, "https://haybale.internal"))))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.ID != "run-123" {
		t.Errorf("ID = %q, want %q", id.ID, "run-123")
	}
	if id.Issuer != contractIssuer {
		t.Errorf("Issuer = %q, want %q", id.Issuer, contractIssuer)
	}
	if id.RepoScope != nil {
		t.Errorf("RepoScope = %v, want nil", id.RepoScope)
	}
}

func TestAuthenticateHappyPathGitHubShaped(t *testing.T) {
	s := newRS256Signer(t, "gha-key")
	a := newAuth(t, s, "gha:{repository}", func(ic *IssuerConfig) {
		ic.Issuer = "https://token.actions.githubusercontent.com"
		ic.ClaimBindings = map[string][]string{
			"repository_owner": {"rxbynerd"},
		}
	})

	claims := baseClaims("https://token.actions.githubusercontent.com", "https://haybale.internal")
	claims["repository"] = "rxbynerd/haybale"
	claims["repository_owner"] = "rxbynerd"

	id, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, claims)))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.ID != "gha:rxbynerd/haybale" {
		t.Errorf("ID = %q, want %q", id.ID, "gha:rxbynerd/haybale")
	}
}

func TestAuthenticateBearerHeader(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", nil)

	r := httptest.NewRequest(http.MethodGet, "/github.com/o/r.git/info/refs?service=git-upload-pack", nil)
	r.Header.Set("Authorization", "Bearer "+mint(t, s, baseClaims(contractIssuer, "https://haybale.internal")))
	if _, err := a.Authenticate(context.Background(), r); err != nil {
		t.Fatalf("Authenticate via Bearer: %v", err)
	}
}

// TestAuthenticateAttackMatrix is the security acceptance bar: every named
// rejection case maps to at least one RFC 8725 MUST. All must return
// ErrAuthenticationFailed with no successful identity.
func TestAuthenticateAttackMatrix(t *testing.T) {
	good := newES256Signer(t, "k1")
	// A second, untrusted key with the SAME kid as the trusted one, for
	// the "right kid, wrong key" signature-confusion case.
	imposter := newES256Signer(t, "k1")

	tests := []struct {
		name  string
		token func(t *testing.T) string
		tweak func(*IssuerConfig)
	}{
		{
			name: "alg none",
			token: func(t *testing.T) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(contractIssuer, "https://haybale.internal"))
				tok.Header["kid"] = "k1"
				s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none: %v", err)
				}
				return s
			},
		},
		{
			name: "HMAC signed with the public key (algorithm confusion)",
			token: func(t *testing.T) string {
				// Forge an HS256 token whose MAC key is the trusted EC
				// public key's marshaled bytes — the classic confusion
				// attack an asymmetric-only allowlist must defeat (an
				// attacker who knows the public key can compute a valid
				// HMAC if the verifier is tricked into treating it as one).
				pubBytes, err := x509.MarshalPKIXPublicKey(good.pub)
				if err != nil {
					t.Fatalf("marshal public key: %v", err)
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(contractIssuer, "https://haybale.internal"))
				tok.Header["kid"] = "k1"
				s, err := tok.SignedString(pubBytes)
				if err != nil {
					t.Fatalf("sign hs256: %v", err)
				}
				return s
			},
		},
		{
			name: "signed by an untrusted key with the trusted kid",
			token: func(t *testing.T) string {
				return mint(t, imposter, baseClaims(contractIssuer, "https://haybale.internal"))
			},
		},
		{
			name: "missing aud",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				delete(c, "aud")
				return mint(t, good, c)
			},
		},
		{
			name: "wrong aud",
			token: func(t *testing.T) string {
				return mint(t, good, baseClaims(contractIssuer, "https://someone-else.example"))
			},
		},
		{
			name: "expired beyond leeway",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
				return mint(t, good, c)
			},
		},
		{
			name: "missing exp",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				delete(c, "exp")
				return mint(t, good, c)
			},
		},
		{
			name: "nbf in the future beyond leeway",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["nbf"] = time.Now().Add(2 * time.Minute).Unix()
				return mint(t, good, c)
			},
		},
		{
			name: "iat in the future beyond leeway",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["iat"] = time.Now().Add(2 * time.Minute).Unix()
				return mint(t, good, c)
			},
		},
		{
			name: "unknown issuer",
			token: func(t *testing.T) string {
				return mint(t, good, baseClaims("https://not-configured.example", "https://haybale.internal"))
			},
		},
		{
			name: "missing iss",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				delete(c, "iss")
				return mint(t, good, c)
			},
		},
		{
			name: "malformed compact serialization",
			token: func(t *testing.T) string {
				return "not.a.jwt"
			},
		},
		{
			name: "claim binding miss",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["repository_owner"] = "someone-else"
				return mint(t, good, c)
			},
			tweak: func(ic *IssuerConfig) {
				ic.ClaimBindings = map[string][]string{"repository_owner": {"rxbynerd"}}
			},
		},
		{
			name: "template references absent claim",
			token: func(t *testing.T) string {
				return mint(t, good, baseClaims(contractIssuer, "https://haybale.internal"))
			},
			tweak: func(ic *IssuerConfig) {
				ic.IdentityTemplate = "{repository}" // not present on a contract token
			},
		},
		{
			name: "template references non-string claim",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["sub"] = 12345 // number, not a string
				return mint(t, good, c)
			},
		},
		{
			name: "repo scope claim wrong type",
			token: func(t *testing.T) string {
				c := baseClaims(contractIssuer, "https://haybale.internal")
				c["haybale.dev/repos"] = "github.com/rxbynerd/haybale" // string, not array
				return mint(t, good, c)
			},
			tweak: func(ic *IssuerConfig) {
				ic.RepoScopeClaim = "haybale.dev/repos"
			},
		},
		{
			name: "oversized token",
			token: func(t *testing.T) string {
				return "eyJ" + strings.Repeat("A", maxTokenBytes)
			},
		},
		{
			name: "unexpected typ header",
			token: func(t *testing.T) string {
				tok := jwt.NewWithClaims(good.method, baseClaims(contractIssuer, "https://haybale.internal"))
				tok.Header["kid"] = good.kid
				tok.Header["typ"] = "JWT"
				s, err := tok.SignedString(good.key)
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				return s
			},
			tweak: func(ic *IssuerConfig) {
				ic.Typ = "at+jwt"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuth(t, good, "{sub}", tc.tweak)
			id, err := a.Authenticate(context.Background(), basicAuthReq(t, tc.token(t)))
			if err == nil {
				t.Fatalf("Authenticate succeeded (id=%+v), want ErrAuthenticationFailed", id)
			}
			if err != ErrAuthenticationFailed {
				t.Errorf("err = %v, want ErrAuthenticationFailed", err)
			}
			if id != nil {
				t.Errorf("id = %+v, want nil", id)
			}
		})
	}
}

func TestAuthenticateNoCredential(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", nil)
	r := httptest.NewRequest(http.MethodGet, "/github.com/o/r.git/info/refs?service=git-upload-pack", nil)
	if _, err := a.Authenticate(context.Background(), r); err != ErrAuthenticationFailed {
		t.Errorf("err = %v, want ErrAuthenticationFailed", err)
	}
}

// TestAuthenticateWithinLeeway confirms a token just barely expired, but
// inside the configured leeway, is still accepted — the boundary partner
// of the "expired beyond leeway" rejection.
func TestAuthenticateWithinLeeway(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", func(ic *IssuerConfig) { ic.Leeway = 60 * time.Second })
	c := baseClaims(contractIssuer, "https://haybale.internal")
	c["exp"] = time.Now().Add(-30 * time.Second).Unix() // expired 30s ago, within 60s leeway
	if _, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, c))); err != nil {
		t.Errorf("Authenticate within leeway: %v", err)
	}
}

func TestAuthenticateRepoScopeExtracted(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", func(ic *IssuerConfig) { ic.RepoScopeClaim = "haybale.dev/repos" })

	c := baseClaims(contractIssuer, "https://haybale.internal")
	c["haybale.dev/repos"] = []any{"github.com/rxbynerd/haybale", "github.com/rxbynerd/stirrup"}
	id, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, c)))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := []string{"github.com/rxbynerd/haybale", "github.com/rxbynerd/stirrup"}
	if len(id.RepoScope) != len(want) || id.RepoScope[0] != want[0] || id.RepoScope[1] != want[1] {
		t.Errorf("RepoScope = %v, want %v", id.RepoScope, want)
	}
}

// TestAuthenticateRepoScopeEmptyArrayIsNonNil confirms an explicit empty
// scope array yields a non-nil empty slice (deny everything), distinct
// from an absent claim (nil, policy decides).
func TestAuthenticateRepoScopeEmptyArrayIsNonNil(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", func(ic *IssuerConfig) { ic.RepoScopeClaim = "haybale.dev/repos" })

	c := baseClaims(contractIssuer, "https://haybale.internal")
	c["haybale.dev/repos"] = []any{}
	id, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, c)))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.RepoScope == nil {
		t.Fatal("RepoScope = nil, want non-nil empty slice (deny all)")
	}
	if len(id.RepoScope) != 0 {
		t.Errorf("RepoScope = %v, want empty", id.RepoScope)
	}
}

func TestAuthenticateRepoScopeAbsentIsNil(t *testing.T) {
	s := newES256Signer(t, "k1")
	a := newAuth(t, s, "{sub}", func(ic *IssuerConfig) { ic.RepoScopeClaim = "haybale.dev/repos" })

	id, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, s, baseClaims(contractIssuer, "https://haybale.internal"))))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.RepoScope != nil {
		t.Errorf("RepoScope = %v, want nil (absent claim)", id.RepoScope)
	}
}

// TestCrossIssuerRoutingIsolation stands up two issuers and confirms a
// token whose iss selects issuer A is verified only against A's keys: a
// token claiming iss=A but signed by B's key is rejected, never
// cross-checked against B's key set.
func TestCrossIssuerRoutingIsolation(t *testing.T) {
	issA := "https://a.example"
	issB := "https://b.example"
	keyA := newES256Signer(t, "a1")
	keyB := newES256Signer(t, "b1")

	a, err := NewJWTAuthenticator(context.Background(), []IssuerConfig{
		{Issuer: issA, JWKSFile: jwksFile(t, keyA), Algorithms: []string{"ES256"}, Audiences: []string{"aud"}, Leeway: time.Minute, IdentityTemplate: "{sub}"},
		{Issuer: issB, JWKSFile: jwksFile(t, keyB), Algorithms: []string{"ES256"}, Audiences: []string{"aud"}, Leeway: time.Minute, IdentityTemplate: "{sub}"},
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	// iss=A, but signed by B's key (and carrying B's kid). A's verifier
	// has no b1 key, so verification must fail.
	forged := mint(t, keyB, baseClaims(issA, "aud"))
	if _, err := a.Authenticate(context.Background(), basicAuthReq(t, forged)); err != ErrAuthenticationFailed {
		t.Errorf("cross-issuer forged token: err = %v, want ErrAuthenticationFailed", err)
	}

	// Sanity: a genuine A token still works.
	if _, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, keyA, baseClaims(issA, "aud")))); err != nil {
		t.Errorf("genuine issuer-A token: %v", err)
	}
}

// TestURLKeySourceRotation exercises the URL-backed source end to end: a
// live httptest JWKS endpoint, an initial fail-fast fetch, and picking up
// a newly-rotated key the endpoint begins serving (unknown-kid refetch).
func TestURLKeySourceRotation(t *testing.T) {
	k1 := newES256Signer(t, "k1")
	k2 := newES256Signer(t, "k2")

	// The endpoint serves only k1 initially; flipping rotated makes it
	// serve both k1 and k2, simulating an overlap key rotation.
	var mu sync.Mutex
	rotated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if rotated {
			_, _ = w.Write(jwksJSON(t, k1, k2))
			return
		}
		_, _ = w.Write(jwksJSON(t, k1))
	}))
	defer srv.Close()

	a, err := NewJWTAuthenticator(context.Background(), []IssuerConfig{{
		Issuer:           contractIssuer,
		JWKSURL:          srv.URL,
		Algorithms:       []string{"ES256"},
		Audiences:        []string{"https://haybale.internal"},
		Leeway:           time.Minute,
		IdentityTemplate: "{sub}",
	}}, discardLogger())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator (initial fetch): %v", err)
	}

	// k1 is trusted from the initial fetch.
	if _, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, k1, baseClaims(contractIssuer, "https://haybale.internal")))); err != nil {
		t.Fatalf("k1 before rotation: %v", err)
	}

	// Publish k2 (overlap rotation: k2 alongside k1). The first token
	// bearing k2's previously-unseen kid triggers the unknown-kid refetch
	// (the rate limiter's initial burst permits one immediately), so it is
	// picked up and accepted. Deliberately no k2-before-rotation
	// assertion here: presenting k2 while unpublished would spend that
	// one-shot refetch budget and leave the post-rotation refetch
	// rate-limited — the unpublished-key rejection is already covered by
	// the imposter and cross-issuer cases above.
	mu.Lock()
	rotated = true
	mu.Unlock()

	if _, err := a.Authenticate(context.Background(), basicAuthReq(t, mint(t, k2, baseClaims(contractIssuer, "https://haybale.internal")))); err != nil {
		t.Errorf("k2 after rotation: %v", err)
	}
}

// TestNewURLKeySourceFailFast confirms an unreachable JWKS URL fails
// construction (fail-fast cold start) rather than deferring the error to
// the first request.
func TestNewURLKeySourceFailFast(t *testing.T) {
	// A server that always 500s: the initial fetch must fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := NewJWTAuthenticator(context.Background(), []IssuerConfig{{
		Issuer:           contractIssuer,
		JWKSURL:          srv.URL,
		Algorithms:       []string{"ES256"},
		Audiences:        []string{"https://haybale.internal"},
		Leeway:           time.Minute,
		IdentityTemplate: "{sub}",
	}}, discardLogger())
	if err == nil {
		t.Fatal("NewJWTAuthenticator succeeded against a failing JWKS endpoint, want error")
	}
}

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		tmpl    string
		wantErr bool
	}{
		{"{sub}", false},
		{"gha:{repository}", false},
		{"prefix-{a}-{b}-suffix", false},
		{"", true},
		{"{unclosed", true},
		{"unopened}", true},
		{"{}", true},
		{"{a{b}}", true},
	}
	for _, tc := range tests {
		t.Run(tc.tmpl, func(t *testing.T) {
			err := ValidateIdentityTemplate(tc.tmpl)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateIdentityTemplate(%q) err = %v, wantErr = %v", tc.tmpl, err, tc.wantErr)
			}
		})
	}
}
