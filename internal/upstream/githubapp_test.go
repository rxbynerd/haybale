package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/security"
)

// testRSAKeyPEM returns a throwaway, in-test-generated RSA private key
// in PEM form, memoized across the whole test binary run (key generation
// is the slow part of most of these tests, and nothing here depends on
// a fresh key per test) — never committed anywhere, generated fresh
// every test run.
var testRSAKeyPEM = sync.OnceValue(func() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate test RSA key: %v", err))
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
})

// capturedMint is one observed POST /app/installations/{id}/access_tokens
// call: its decoded body and the Authorization header it arrived with.
type capturedMint struct {
	body           mintRequest
	authHeader     string
	installationID string
}

// githubFake stands in for the GitHub REST API: installation lookup and
// scoped-mint endpoints, with configurable responses so tests can drive
// success, failure, and slow-response paths without touching a real
// GitHub API.
type githubFake struct {
	mu sync.Mutex

	installationID int64

	installationLookups int
	installationStatus  int    // 0 defaults to 200
	installationBody    []byte // nil defaults to {"id": installationID}

	mints        []capturedMint
	mintStatus   int    // 0 defaults to 201
	mintBody     []byte // nil defaults to a generated success body
	mintToken    string // token to embed in the generated success body
	mintExpires  time.Time
	mintDelay    time.Duration
	mintBodyFunc func(capturedMint) []byte // overrides mintBody per-call if set
}

func newGitHubFake(installationID int64) *githubFake {
	return &githubFake{
		installationID: installationID,
		mintToken:      "test-minted-token",
		mintExpires:    time.Now().Add(time.Hour),
	}
}

func (f *githubFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return srv
}

func (f *githubFake) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/installation"):
		f.handleInstallation(w, r)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
		f.handleMint(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *githubFake) handleInstallation(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.installationLookups++
	status := f.installationStatus
	body := f.installationBody
	id := f.installationID
	f.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}
	if body == nil {
		body, _ = json.Marshal(installationLookupResponse{ID: id})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (f *githubFake) handleMint(w http.ResponseWriter, r *http.Request) {
	var reqBody mintRequest
	_ = json.NewDecoder(r.Body).Decode(&reqBody)

	// The installation ID this call was made against is the trailing
	// path segment between "/app/installations/" and "/access_tokens".
	installationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app/installations/"), "/access_tokens")

	captured := capturedMint{body: reqBody, authHeader: r.Header.Get("Authorization"), installationID: installationID}

	f.mu.Lock()
	f.mints = append(f.mints, captured)
	status := f.mintStatus
	body := f.mintBody
	bodyFunc := f.mintBodyFunc
	delay := f.mintDelay
	token := f.mintToken
	expires := f.mintExpires
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}

	if status == 0 {
		status = http.StatusCreated
	}
	if bodyFunc != nil {
		body = bodyFunc(captured)
	}
	if body == nil {
		body, _ = json.Marshal(mintResponse{Token: token, ExpiresAt: expires})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (f *githubFake) mintCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mints)
}

func (f *githubFake) lastMint() capturedMint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints[len(f.mints)-1]
}

func (f *githubFake) installationLookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installationLookups
}

func newTestSource(t *testing.T, fake *githubFake) *GitHubAppSource {
	t.Helper()
	srv := fake.server(t)
	src, err := NewGitHubAppSource(GitHubAppConfig{
		AppID:         12345,
		PrivateKeyPEM: testRSAKeyPEM(),
		APIBaseURL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGitHubAppSource() unexpected error: %v", err)
	}
	return src
}

// TestNewGitHubAppSourceValidation covers NewGitHubAppSource's
// fail-fast-at-construction contract: appID and a parseable RSA private
// key are both required before anything is ever minted.
func TestNewGitHubAppSourceValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GitHubAppConfig
		wantErr string
	}{
		{
			name:    "missing appID",
			cfg:     GitHubAppConfig{PrivateKeyPEM: testRSAKeyPEM()},
			wantErr: "appID is required",
		},
		{
			name:    "missing private key",
			cfg:     GitHubAppConfig{AppID: 1},
			wantErr: "private key is required",
		},
		{
			name:    "malformed private key",
			cfg:     GitHubAppConfig{AppID: 1, PrivateKeyPEM: []byte("not a pem key at all")},
			wantErr: "parse private key",
		},
		{
			name: "not-RSA PEM block",
			cfg: GitHubAppConfig{AppID: 1, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: []byte("not actually a certificate either"),
			})},
			wantErr: "parse private key",
		},
		{
			name: "valid key",
			cfg:  GitHubAppConfig{AppID: 1, PrivateKeyPEM: testRSAKeyPEM()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := NewGitHubAppSource(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewGitHubAppSource() unexpected error: %v", err)
				}
				if src == nil {
					t.Fatal("NewGitHubAppSource() = nil, want non-nil")
				}
				return
			}
			if err == nil {
				t.Fatal("NewGitHubAppSource() = nil error, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewGitHubAppSource() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestMintScopesLeastPrivilege is the single most important assertion in
// M4: a read verb must mint a token scoped to exactly the one repo with
// "contents": "read", and a write verb the same repo with "contents":
// "write" — never a broader scope, regardless of what other repos or
// permissions the installation itself might have.
func TestMintScopesLeastPrivilege(t *testing.T) {
	tests := []struct {
		name           string
		verb           gitproto.Verb
		wantPermission string
	}{
		{name: "read", verb: gitproto.Read, wantPermission: "read"},
		{name: "write", verb: gitproto.Write, wantPermission: "write"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newGitHubFake(999)
			src := newTestSource(t, fake)
			repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

			if _, err := src.Credentials(context.Background(), repo, tt.verb); err != nil {
				t.Fatalf("Credentials() unexpected error: %v", err)
			}

			if fake.mintCallCount() != 1 {
				t.Fatalf("mint calls = %d, want 1", fake.mintCallCount())
			}
			got := fake.lastMint().body
			if len(got.Repositories) != 1 || got.Repositories[0] != "widgets" {
				t.Errorf("mint request repositories = %v, want exactly [\"widgets\"]", got.Repositories)
			}
			if got.Permissions.Contents != tt.wantPermission {
				t.Errorf("mint request permissions.contents = %q, want %q", got.Permissions.Contents, tt.wantPermission)
			}
			wantInstallationID := strconv.Itoa(999)
			if fake.lastMint().installationID != wantInstallationID {
				t.Errorf("mint request installation ID = %q, want %q", fake.lastMint().installationID, wantInstallationID)
			}
		})
	}
}

// TestMintNeverScopesToAnotherRepo is a second angle on the same
// least-privilege guarantee: minting for one repo must never leak
// another repo's name into the scoped request, even when two different
// repos are requested from the same installation in sequence.
func TestMintNeverScopesToAnotherRepo(t *testing.T) {
	fake := newGitHubFake(1)
	src := newTestSource(t, fake)

	if _, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if _, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "gadgets"}, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}

	if fake.mintCallCount() != 2 {
		t.Fatalf("mint calls = %d, want 2", fake.mintCallCount())
	}
	first, second := fake.mints[0].body, fake.mints[1].body
	if len(first.Repositories) != 1 || first.Repositories[0] != "widgets" {
		t.Errorf("first mint repositories = %v, want [\"widgets\"]", first.Repositories)
	}
	if len(second.Repositories) != 1 || second.Repositories[0] != "gadgets" {
		t.Errorf("second mint repositories = %v, want [\"gadgets\"]", second.Repositories)
	}
}

// TestCredentialsReturnsMintedToken asserts the end-to-end path: a
// successful mint against the fake produces a BasicAuth with the
// GitHub-convention "x-access-token" username and the fake's minted
// token as the password.
func TestCredentialsReturnsMintedToken(t *testing.T) {
	fake := newGitHubFake(42)
	fake.mintToken = "ghs_faketoken123"
	src := newTestSource(t, fake)

	cred, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	if err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if cred.Username != "x-access-token" {
		t.Errorf("Credentials().Username = %q, want %q", cred.Username, "x-access-token")
	}
	if cred.Password != "ghs_faketoken123" {
		t.Errorf("Credentials().Password = %q, want the fake's minted token", cred.Password)
	}
}

// TestCredentialsCachesAcrossCalls asserts GitHubAppSource's Credentials
// method benefits from the embedded tokenCache: a second call for the
// same repo/verb is served from cache, not a second mint.
func TestCredentialsCachesAcrossCalls(t *testing.T) {
	fake := newGitHubFake(42)
	src := newTestSource(t, fake)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	if _, err := src.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if _, err := src.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if fake.mintCallCount() != 1 {
		t.Fatalf("mint calls = %d, want 1 (second call should be served from tokenCache)", fake.mintCallCount())
	}
}

// TestInstallationLookupIsCached asserts the installation ID resolution
// (GET .../installation) happens once and is reused across multiple
// mints for the same repo — read and write verbs each mint their own
// token, but neither should re-resolve an installation ID that's already
// known.
func TestInstallationLookupIsCached(t *testing.T) {
	fake := newGitHubFake(7)
	src := newTestSource(t, fake)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	if _, err := src.Credentials(context.Background(), repo, gitproto.Read); err != nil {
		t.Fatalf("Credentials(read) unexpected error: %v", err)
	}
	if _, err := src.Credentials(context.Background(), repo, gitproto.Write); err != nil {
		t.Fatalf("Credentials(write) unexpected error: %v", err)
	}

	if fake.mintCallCount() != 2 {
		t.Fatalf("mint calls = %d, want 2 (read and write each mint their own scoped token)", fake.mintCallCount())
	}
	if fake.installationLookupCount() != 1 {
		t.Fatalf("installation lookup calls = %d, want 1 (cached across both mints)", fake.installationLookupCount())
	}
}

// TestMintUsesAppJWTAuthentication asserts both REST calls authenticate
// as the App itself (a Bearer JWT from ghinstallation.AppsTransport),
// not as an installation (which would require a token GitHubAppSource
// doesn't have yet — that's the whole point of this call).
func TestMintUsesAppJWTAuthentication(t *testing.T) {
	fake := newGitHubFake(1)
	src := newTestSource(t, fake)

	if _, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}

	auth := fake.lastMint().authHeader
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("mint request Authorization = %q, want a Bearer JWT", auth)
	}
}

// TestMintFailurePropagatesAsError asserts a non-201 mint response
// surfaces as a Go error (which internal/proxy maps to 502, never a
// panic or a silently-empty credential) — and that the error text never
// contains the fake's response body, which is the mechanism by which no
// token or other response content can leak into an operator's error
// logs.
func TestMintFailurePropagatesAsError(t *testing.T) {
	fake := newGitHubFake(1)
	fake.mintStatus = http.StatusInternalServerError
	fake.mintBody = []byte(`{"message":"nope","secret_leak":"ghs_shouldneverappearinerrors"}`)
	src := newTestSource(t, fake)

	_, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	if err == nil {
		t.Fatal("Credentials() = nil error, want an error from the failed mint")
	}
	if strings.Contains(err.Error(), "ghs_shouldneverappearinerrors") {
		t.Errorf("Credentials() error = %q, must never contain the upstream response body", err.Error())
	}
}

// TestInstallationLookupFailurePropagatesAsError mirrors
// TestMintFailurePropagatesAsError for the installation-lookup leg.
func TestInstallationLookupFailurePropagatesAsError(t *testing.T) {
	fake := newGitHubFake(1)
	fake.installationStatus = http.StatusNotFound
	src := newTestSource(t, fake)

	_, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	if err == nil {
		t.Fatal("Credentials() = nil error, want an error from the failed installation lookup")
	}
	if fake.mintCallCount() != 0 {
		t.Errorf("mint calls = %d, want 0 (mint must not be attempted when installation lookup fails)", fake.mintCallCount())
	}
}

// TestCredentialsHonorsContextDeadline asserts a caller-imposed context
// deadline is honored on the mint network call, per the CredentialSource
// interface's doc contract — GitHubAppSource must not block past it.
func TestCredentialsHonorsContextDeadline(t *testing.T) {
	fake := newGitHubFake(1)
	fake.mintDelay = 2 * time.Second
	src := newTestSource(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := src.Credentials(ctx, gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Credentials() = nil error, want a deadline-exceeded error")
	}
	if elapsed > time.Second {
		t.Errorf("Credentials() took %v to return, want it to honor the ~50ms context deadline instead of the fake's 2s delay", elapsed)
	}
}

// TestTokenMintedEventLogged asserts a successful mint emits
// security.EventTokenMinted with host/owner/repo/verb/installation
// context and, critically, never the minted token itself anywhere in
// the log line.
func TestTokenMintedEventLogged(t *testing.T) {
	fake := newGitHubFake(55)
	fake.mintToken = "ghs_verysecrettoken"
	src := newTestSource(t, fake)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	src.SetLogger(logger)

	if _, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Write); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}

	line := buf.String()
	for _, want := range []string{
		`"event":"` + security.EventTokenMinted + `"`,
		`"host":"github.com"`, `"owner":"acme"`, `"repo":"widgets"`, `"verb":"write"`,
		`"installationID":55`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log line = %q, want it to contain %q", line, want)
		}
	}
	if strings.Contains(line, "ghs_verysecrettoken") {
		t.Errorf("log line = %q, must never contain the minted token", line)
	}
}

// TestSetLoggerNilIsNoop asserts SetLogger(nil) leaves the
// slog.Default() fallback from construction in place, matching
// internal/proxy.New's own "a nil logger falls back to slog.Default()"
// convention — a caller passing a nil logger by accident must not panic
// on the next mint.
func TestSetLoggerNilIsNoop(t *testing.T) {
	fake := newGitHubFake(1)
	src := newTestSource(t, fake)
	src.SetLogger(nil)

	if _, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read); err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
}

// TestGitHubAppSourceSingleflightCollapsesConcurrentMints mirrors
// tokenCache's own singleflight test, but exercised through the full
// GitHubAppSource (including installation lookup) rather than a fake
// mintFunc — N concurrent Credentials() calls for the same repo/verb
// must reach the fake exactly once. Run under `go test -race`.
func TestGitHubAppSourceSingleflightCollapsesConcurrentMints(t *testing.T) {
	fake := newGitHubFake(1)
	fake.mintDelay = 100 * time.Millisecond
	src := newTestSource(t, fake)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	const n = 20
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			_, errs[i] = src.Credentials(context.Background(), repo, gitproto.Read)
		}(i)
	}
	start.Done()
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Credentials() goroutine %d unexpected error: %v", i, err)
		}
	}
	if fake.mintCallCount() != 1 {
		t.Fatalf("mint calls = %d, want exactly 1 for %d concurrent Credentials() calls sharing the same key", fake.mintCallCount(), n)
	}
}
