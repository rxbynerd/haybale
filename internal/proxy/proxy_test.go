package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// newUpstreamMap parses raw upstream URLs into the map New expects,
// failing the test on a bad URL rather than every call site checking
// the error.
func newUpstreamMap(t *testing.T, byHost map[string]string) map[string]*url.URL {
	t.Helper()
	out := make(map[string]*url.URL, len(byHost))
	for host, raw := range byHost {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		out[host] = u
	}
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// defaultTestCredential is the upstream.BasicAuth mustNew injects for
// every upstream host, unless a test builds its own credential map and
// calls mustNewWithCredentials instead. Tests that care about the exact
// injected value (e.g. TestCredentialInjectionReplacesAuthorization)
// assert against these constants directly.
var defaultTestCredential = upstream.BasicAuth{Username: "test-upstream-user", Password: "test-upstream-secret"}

// fixedCredentialSource is a CredentialSource stub that always returns
// cred, regardless of repo/verb, and never fails.
type fixedCredentialSource struct{ cred upstream.BasicAuth }

func (f fixedCredentialSource) Credentials(context.Context, gitproto.Repo, gitproto.Verb) (upstream.BasicAuth, error) {
	return f.cred, nil
}

// erroringCredentialSource is a CredentialSource stub that always fails
// with err, for exercising the "credential source error -> 502" path.
type erroringCredentialSource struct{ err error }

func (e erroringCredentialSource) Credentials(context.Context, gitproto.Repo, gitproto.Verb) (upstream.BasicAuth, error) {
	return upstream.BasicAuth{}, e.err
}

// credentialsForHosts builds a map[string]upstream.CredentialSource
// covering every host in upstreams, each returning defaultTestCredential
// — the default credential map mustNew uses.
func credentialsForHosts(upstreams map[string]*url.URL) map[string]upstream.CredentialSource {
	creds := make(map[string]upstream.CredentialSource, len(upstreams))
	for host := range upstreams {
		creds[host] = fixedCredentialSource{cred: defaultTestCredential}
	}
	return creds
}

// mustNew builds a Proxy via New, failing the test immediately if
// construction returns an error. Every test in this file (other than
// TestNewRejectsNilAuthenticator/TestNewRejectsNilPolicyEngine, which
// exercise that error path directly, and the credential-specific tests,
// which use mustNewWithCredentials for a custom credential map) passes
// well-formed dependencies, so an error here would indicate a test bug
// rather than the behaviour under test. It injects defaultTestCredential
// for every configured upstream host — tests that don't care about the
// exact credential-injection behaviour (most of this file) never need to
// know that.
func mustNew(t *testing.T, upstreams map[string]*url.URL, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger) *Proxy {
	t.Helper()
	return mustNewWithCredentials(t, upstreams, credentialsForHosts(upstreams), authenticator, policyEngine, logger)
}

// mustNewWithCredentials is mustNew's counterpart for tests that need
// precise control over the credentialSources map — a missing host entry,
// an erroringCredentialSource, or a specific injected credential to
// assert against.
func mustNewWithCredentials(t *testing.T, upstreams map[string]*url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger) *Proxy {
	t.Helper()
	p, err := New(upstreams, credentialSources, authenticator, policyEngine, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p
}

// testIdentityID is the Identity every allowAllAuthenticator call
// returns, so tests that don't care about identity/policy semantics
// (most of the tests in this file, which predate M2 and exercise the
// passthrough path) can assert on a stable, known identity where
// relevant.
const testIdentityID = "test-identity"

// allowAllAuthenticator authenticates any request as testIdentityID
// regardless of what credential (if any) is presented. Tests that only
// care about routing/streaming behaviour use this rather than standing
// up a real identity.StaticTokenAuthenticator fixture.
type allowAllAuthenticator struct{}

func (allowAllAuthenticator) Authenticate(context.Context, *http.Request) (*identity.Identity, error) {
	return &identity.Identity{ID: testIdentityID}, nil
}

// denyAllAuthenticator fails every Authenticate call, for exercising the
// 401 path.
type denyAllAuthenticator struct{}

func (denyAllAuthenticator) Authenticate(context.Context, *http.Request) (*identity.Identity, error) {
	return nil, identity.ErrAuthenticationFailed
}

// allowAllPolicy grants every request, regardless of identity, repo, or
// verb.
type allowAllPolicy struct{}

func (allowAllPolicy) Authorize(identity.Identity, gitproto.Repo, gitproto.Verb) policy.Decision {
	return policy.Decision{Allowed: true, Reason: "test: allow all"}
}

// denyAllPolicy denies every request, for exercising the policy-denied
// 404 path. matchedRule is nil, mirroring a true default-deny (no
// matching rule) rather than "a rule matched but didn't grant this
// verb".
type denyAllPolicy struct{}

func (denyAllPolicy) Authorize(identity.Identity, gitproto.Repo, gitproto.Verb) policy.Decision {
	return policy.Decision{Allowed: false, Rule: nil, Reason: "test: deny all"}
}

func TestHealthz(t *testing.T) {
	p := mustNew(t, newUpstreamMap(t, nil), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestInvalidRequestMaps404(t *testing.T) {
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"dumb protocol object fetch", "GET", "/github.com/acme/widgets.git/objects/ab/cdef"},
		{"malformed too few segments", "GET", "/github.com/acme"},
		{"path traversal", "POST", "/github.com/acme/../git-upload-pack"},
		{"missing service param", "GET", "/github.com/acme/widgets.git/info/refs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, srv.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

// TestUpstreamUnreachableMaps502 pins the current (unasserted-until-now)
// baseline for what happens when a request's host resolves to a
// configured upstream, but the upstream itself is unreachable (dial
// failure). httputil.ReverseProxy's default ErrorHandler maps this to a
// 502 today; this is the seam M3 tightens (upstream 401/403 -> 502,
// WWW-Authenticate stripped) per the plan's security invariants, so it
// needs a pinned baseline before that logic lands on top.
func TestUpstreamUnreachableMaps502(t *testing.T) {
	// Stand up a server and close it immediately: its URL is well-formed
	// but nothing is listening, so any request against it fails to dial
	// rather than merely returning a non-2xx status.
	deadSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL, err := url.Parse(deadSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", deadSrv.URL, err)
	}
	deadSrv.Close()

	p := mustNew(t, map[string]*url.URL{"testhost": deadURL}, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d for an unreachable upstream", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestUnknownHostMaps404(t *testing.T) {
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gitlab.example/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d for an unconfigured host", resp.StatusCode, http.StatusNotFound)
	}
}

// recordingUpstream is a fake git smart-HTTP upstream that records the
// request it received (method, path, query, and headers) and echoes the
// request body back verbatim in the response, so tests can assert both
// header forwarding and byte-for-byte body streaming in one place.
type recordingUpstream struct {
	mu      sync.Mutex
	method  string
	path    string
	query   string
	headers http.Header
	body    []byte
}

func (u *recordingUpstream) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		u.mu.Lock()
		u.method = r.Method
		u.path = r.URL.Path
		u.query = r.URL.RawQuery
		u.headers = r.Header.Clone()
		u.body = body
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func (u *recordingUpstream) snapshot() (method, path, query string, headers http.Header, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.method, u.path, u.query, u.headers, u.body
}

func TestForwardsToUpstreamStrippingHostSegment(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	payload := []byte("0032want deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n0000")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-upload-pack", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Equal(respBody, payload) {
		t.Errorf("response body = %q, want echoed payload %q", respBody, payload)
	}

	method, path, _, headers, body := up.snapshot()
	if method != http.MethodPost {
		t.Errorf("upstream saw method %q, want POST", method)
	}
	// The host-in-path segment ("testhost") must be stripped; the
	// owner/repo/endpoint suffix must reach upstream unchanged.
	if path != "/acme/widgets.git/git-upload-pack" {
		t.Errorf("upstream saw path %q, want %q", path, "/acme/widgets.git/git-upload-pack")
	}
	if !bytes.Equal(body, payload) {
		t.Errorf("upstream received body %q, want %q", body, payload)
	}

	// Critical: Git-Protocol must never be dropped, or protocol v2
	// silently downgrades to v1.
	if got := headers.Get("Git-Protocol"); got != "version=2" {
		t.Errorf("upstream saw Git-Protocol = %q, want %q", got, "version=2")
	}
	if got := headers.Get("Content-Type"); got != "application/x-git-upload-pack-request" {
		t.Errorf("upstream saw Content-Type = %q, want %q", got, "application/x-git-upload-pack-request")
	}
	if got := headers.Get("Accept"); got != "application/x-git-upload-pack-result" {
		t.Errorf("upstream saw Accept = %q, want %q", got, "application/x-git-upload-pack-result")
	}
	if got := headers.Get("Accept-Encoding"); got != "gzip" {
		t.Errorf("upstream saw Accept-Encoding = %q, want %q", got, "gzip")
	}
}

// TestClientXForwardedHeadersAreSuppressed pins the intentional security
// posture documented on rewrite(): haybale must never inject client
// IP/host/proto upstream. A client-supplied X-Forwarded-For (or
// X-Forwarded-Host/X-Forwarded-Proto) must not reach the upstream —
// neither the client's original value nor a haybale-originated
// replacement. This guards against a future refactor "fixing" the
// absence of pr.SetXForwarded() the way the original R9 finding
// suggested, which would leak client IP/host/proto to the upstream.
func TestClientXForwardedHeadersAreSuppressed(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "https")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	_, _, _, headers, _ := up.snapshot()
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if got := headers.Get(h); got != "" {
			t.Errorf("upstream saw %s = %q, want it absent", h, got)
		}
	}
}

// TestInboundAuthorizationHeaderIsReplacedByInjectedCredential exercises
// B-1 (M2) and its M3 continuation: the client's inbound Authorization
// header — the haybale auth token Authenticate just checked, whether
// presented as HTTP Basic or as an `Authorization: Bearer <token>`
// header — must never reach the upstream. httputil.ReverseProxy only
// strips the RFC hop-by-hop header set by default, and Authorization is
// end-to-end, not hop-by-hop, so without an explicit strip it clones
// straight through, letting anything with visibility into the upstream
// leg replay the haybale credential directly against haybale itself. As
// of M3 the header isn't merely absent afterwards — rewrite() replaces
// it with the credential the configured CredentialSource returned, so
// this test also pins that the upstream sees exactly that injected
// value and nothing derived from the client's own token.
func TestInboundAuthorizationHeaderIsReplacedByInjectedCredential(t *testing.T) {
	tests := []struct {
		name    string
		setAuth func(*http.Request)
	}{
		{
			name: "basic auth",
			setAuth: func(r *http.Request) {
				r.SetBasicAuth("ignored-username", "haybale-secret-token")
			},
		},
		{
			name: "bearer token",
			setAuth: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer haybale-secret-token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &recordingUpstream{}
			upstreamSrv := httptest.NewServer(up.handler())
			defer upstreamSrv.Close()

			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
			srv := httptest.NewServer(p)
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			tt.setAuth(req)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			_, _, _, headers, _ := up.snapshot()
			got := headers.Get("Authorization")
			if strings.Contains(got, "haybale-secret-token") {
				t.Errorf("upstream saw Authorization = %q, must never contain the client's haybale token", got)
			}
			wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(defaultTestCredential.Username+":"+defaultTestCredential.Password))
			if got != wantAuth {
				t.Errorf("upstream saw Authorization = %q, want the injected credential %q", got, wantAuth)
			}
		})
	}
}

func TestForwardsQueryStringAndInfoRefs(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	method, path, query, _, _ := up.snapshot()
	if method != http.MethodGet {
		t.Errorf("upstream saw method %q, want GET", method)
	}
	if path != "/acme/widgets.git/info/refs" {
		t.Errorf("upstream saw path %q, want %q", path, "/acme/widgets.git/info/refs")
	}
	if query != "service=git-upload-pack" {
		t.Errorf("upstream saw query %q, want %q", query, "service=git-upload-pack")
	}
}

func TestForwardsContentEncoding(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-receive-pack", strings.NewReader("0000"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	_, _, _, headers, _ := up.snapshot()
	if got := headers.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("upstream saw Content-Encoding = %q, want %q", got, "gzip")
	}
}

func TestStreamsLargeBodyUnmodified(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	// A few MB stands in for pack data at a scale that would surface a
	// buffering bug (e.g. an accidental io.ReadAll of the whole body
	// before forwarding) without making the test slow.
	payload := make([]byte, 4*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-receive-pack", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(respBody, payload) {
		t.Errorf("streamed payload corrupted: got %d bytes, want %d bytes matching", len(respBody), len(payload))
	}
}

// syncBuffer is a mutex-guarded byte buffer safe for the concurrent
// access pattern this file's logging tests exercise: the proxy's own
// goroutine (serving an httptest.Server request) writes its post-request
// log line via slog only after streaming the full response, while the
// test's goroutine can return from its HTTP client call — and then try
// to read the log buffer — as soon as the last response byte is on the
// wire, which can be before that trailing log call runs. That's an
// ordinary streaming-HTTP race, not a bug in the proxy; a plain
// bytes.Buffer is merely unsafe for it under `go test -race`. syncBuffer
// serializes both sides; waitForLogLines (below) closes the remaining
// TOCTOU gap by polling until the expected line count has actually been
// written, rather than reading whatever happens to be there yet.
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

// logLines splits a JSON-lines log buffer into its non-empty lines.
func logLines(buf *syncBuffer) []string {
	trimmed := strings.TrimSpace(buf.String())
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// waitForLogLines polls buf until logLines returns at least minLines
// lines or a short deadline elapses, then returns whatever it has. See
// syncBuffer's doc comment for why this polling is necessary rather than
// a single read immediately after the test's HTTP client call returns.
func waitForLogLines(t *testing.T, buf *syncBuffer, minLines int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		lines := logLines(buf)
		if len(lines) >= minLines || time.Now().After(deadline) {
			return lines
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRejectedRequestIsLogged(t *testing.T) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/github.com/acme/widgets.git/objects/ab/cdef")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], `"level":"WARN"`) {
		t.Errorf("log record = %q, want level WARN", lines[0])
	}
	// The static reason gitproto produces for this request shape — never
	// the raw path/query.
	if !strings.Contains(lines[0], "not a smart-HTTP endpoint") {
		t.Errorf("log record = %q, want it to contain the static rejection reason", lines[0])
	}
}

func TestUnknownHostIsLogged(t *testing.T) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gitlab.example/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], `"level":"WARN"`) {
		t.Errorf("log record = %q, want level WARN", lines[0])
	}
	if !strings.Contains(lines[0], "unknown upstream host") {
		t.Errorf("log record = %q, want it to contain the rejection reason", lines[0])
	}
}

func TestProxiedRequestLogsRepoVerbStatus(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	line := lines[0]
	for _, want := range []string{
		`"level":"INFO"`,
		`"identity":"` + testIdentityID + `"`,
		`"host":"testhost"`,
		`"owner":"acme"`,
		`"repo":"widgets"`,
		`"verb":"read"`,
		`"status":` + strconv.Itoa(http.StatusOK),
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log record = %q, want it to contain %q", line, want)
		}
	}
}

// TestAuthenticationFailureMaps401 exercises the M2 authn gate: a
// request whose Authenticate call fails must get a 401 with a
// WWW-Authenticate challenge, so a git client knows to (re)prompt for
// credentials rather than treating the response as a generic error.
func TestAuthenticationFailureMaps401(t *testing.T) {
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), denyAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != wwwAuthenticateChallenge {
		t.Errorf("WWW-Authenticate = %q, want %q", got, wwwAuthenticateChallenge)
	}
}

func TestAuthenticationFailureIsLogged(t *testing.T) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), denyAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("someuser", "super-secret-token-value")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	line := lines[0]
	for _, want := range []string{
		`"level":"WARN"`,
		`"event":"authn_failed"`,
		`"host":"testhost"`,
		`"owner":"acme"`,
		`"repo":"widgets"`,
		`"verb":"read"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log record = %q, want it to contain %q", line, want)
		}
	}
	if strings.Contains(line, "super-secret-token-value") {
		t.Errorf("log record = %q, must never contain the presented credential", line)
	}
}

// TestPolicyDenialMaps404 exercises the M2 authz gate: an authenticated
// request Authorize denies must get a 404 — never a 403, which would let
// a caller distinguish "exists but denied" from "does not exist".
func TestPolicyDenialMaps404(t *testing.T) {
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), allowAllAuthenticator{}, denyAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestPolicyDenialIsLogged(t *testing.T) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), allowAllAuthenticator{}, denyAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	line := lines[0]
	for _, want := range []string{
		`"level":"WARN"`,
		`"event":"policy_denied"`,
		`"identity":"` + testIdentityID + `"`,
		`"host":"testhost"`,
		`"owner":"acme"`,
		`"repo":"widgets"`,
		`"verb":"read"`,
		`"matchedRule":"none"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log record = %q, want it to contain %q", line, want)
		}
	}
}

// TestPolicyDenialResponseMatchesUnknownHost404 pins the core M2
// security invariant: a policy-denied request must produce a response
// byte-identical (status, body, and the headers http.NotFound sets) to
// an unknown-host 404. Both branches call the exact same http.NotFound
// helper with nothing written to the ResponseWriter beforehand, so a
// caller holding a valid credential cannot distinguish "this repo exists
// but I'm denied" from "haybale doesn't even recognise this host" — no
// existence oracle.
func TestPolicyDenialResponseMatchesUnknownHost404(t *testing.T) {
	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})

	denyingProxy := mustNew(t, upstreams, allowAllAuthenticator{}, denyAllPolicy{}, discardLogger())
	denySrv := httptest.NewServer(denyingProxy)
	defer denySrv.Close()

	unknownHostProxy := mustNew(t, upstreams, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	unknownSrv := httptest.NewServer(unknownHostProxy)
	defer unknownSrv.Close()

	denyResp, err := http.Get(denySrv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET (policy-denied): %v", err)
	}
	defer func() { _ = denyResp.Body.Close() }()
	denyBody, err := io.ReadAll(denyResp.Body)
	if err != nil {
		t.Fatalf("ReadAll (policy-denied): %v", err)
	}

	unknownResp, err := http.Get(unknownSrv.URL + "/some-other-host/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET (unknown host): %v", err)
	}
	defer func() { _ = unknownResp.Body.Close() }()
	unknownBody, err := io.ReadAll(unknownResp.Body)
	if err != nil {
		t.Fatalf("ReadAll (unknown host): %v", err)
	}

	if denyResp.StatusCode != unknownResp.StatusCode {
		t.Errorf("status: policy-denied = %d, unknown-host = %d, want equal", denyResp.StatusCode, unknownResp.StatusCode)
	}
	if !bytes.Equal(denyBody, unknownBody) {
		t.Errorf("body: policy-denied = %q, unknown-host = %q, want byte-identical", denyBody, unknownBody)
	}
	for _, h := range []string{"Content-Type", "X-Content-Type-Options"} {
		if got, want := denyResp.Header.Get(h), unknownResp.Header.Get(h); got != want {
			t.Errorf("header %s: policy-denied = %q, unknown-host = %q, want equal", h, got, want)
		}
	}
}

func TestAuthenticationFailureNeverReachesUpstream(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), denyAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	method, _, _, _, _ := up.snapshot()
	if method != "" {
		t.Errorf("upstream saw a request (method %q) for an authentication failure, want none", method)
	}
}

func TestPolicyDenialNeverReachesUpstream(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, denyAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	method, _, _, _, _ := up.snapshot()
	if method != "" {
		t.Errorf("upstream saw a request (method %q) for a policy denial, want none", method)
	}
}

// TestNewRejectsNilAuthenticator exercises H-2: New must fail at
// construction time when handed a nil Authenticator, rather than
// succeeding and panicking on the first non-/healthz request that
// reaches it.
func TestNewRejectsNilAuthenticator(t *testing.T) {
	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})
	p, err := New(upstreams, credentialsForHosts(upstreams), nil, allowAllPolicy{}, discardLogger())
	if err == nil {
		t.Fatal("New() = nil error, want an error for a nil authenticator")
	}
	if p != nil {
		t.Errorf("New() = %v, want nil Proxy alongside the error", p)
	}
	if !strings.Contains(err.Error(), "authenticator") {
		t.Errorf("New() error = %q, want it to mention the missing authenticator", err.Error())
	}
}

// TestNewRejectsNilPolicyEngine mirrors TestNewRejectsNilAuthenticator
// for the other required dependency New's H-2 fix guards: a nil
// policy.Engine must also fail at construction time.
func TestNewRejectsNilPolicyEngine(t *testing.T) {
	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})
	p, err := New(upstreams, credentialsForHosts(upstreams), allowAllAuthenticator{}, nil, discardLogger())
	if err == nil {
		t.Fatal("New() = nil error, want an error for a nil policyEngine")
	}
	if p != nil {
		t.Errorf("New() = %v, want nil Proxy alongside the error", p)
	}
	if !strings.Contains(err.Error(), "policyEngine") {
		t.Errorf("New() error = %q, want it to mention the missing policyEngine", err.Error())
	}
}

// TestCredentialSourceErrorMaps502 exercises the M3 invariant that a
// CredentialSource.Credentials error — e.g. M4's mint failure, or a
// misconfigured static token — must surface as a 502, never a 401: the
// client has no upstream credential of its own to supply, so a 401
// would just make git hang on (or fail) a credential prompt it cannot
// answer.
func TestCredentialSourceErrorMaps502(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
	creds := map[string]upstream.CredentialSource{"testhost": erroringCredentialSource{err: errors.New("mint failed")}}
	p := mustNewWithCredentials(t, upstreams, creds, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	method, _, _, _, _ := up.snapshot()
	if method != "" {
		t.Errorf("upstream saw a request (method %q) for a credential-source error, want none", method)
	}
}

// TestMissingCredentialSourceMaps502 covers the defensive backstop in
// ServeHTTP: a host present in upstreams but absent from
// credentialSources (a caller-assembled pair that got out of sync — not
// a path config.Validate() output should ever produce) must still map
// to 502, never panic and never 401.
func TestMissingCredentialSourceMaps502(t *testing.T) {
	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})
	p := mustNewWithCredentials(t, upstreams, map[string]upstream.CredentialSource{}, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestUpstreamAuthFailedEventLoggedOnCredentialSourceError(t *testing.T) {
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))

	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})
	creds := map[string]upstream.CredentialSource{"testhost": erroringCredentialSource{err: errors.New("mint failed: super-secret-detail")}}
	p := mustNewWithCredentials(t, upstreams, creds, allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	line := strings.Join(waitForLogLines(t, buf, 1), "\n")
	for _, want := range []string{
		`"event":"upstream_auth_failed"`,
		`"host":"testhost"`,
		`"owner":"acme"`,
		`"repo":"widgets"`,
		`"verb":"read"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log output = %q, want it to contain %q", line, want)
		}
	}
	// The underlying error's text must never reach the log — only the
	// fixed, generic reason.
	if strings.Contains(line, "super-secret-detail") {
		t.Errorf("log output = %q, must never contain the credential source's own error detail", line)
	}
}

// respondingUpstreamHandler returns a handler that always responds with
// a fixed status, optionally a WWW-Authenticate challenge, and a body
// that must never survive to the client once modifyResponse rewrites a
// 401/403 to a 502.
func respondingUpstreamHandler(status int, setWWWAuthenticate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if setWWWAuthenticate {
			w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("upstream error body containing details that must never reach the client"))
	}
}

// TestPostInjectionUpstream401Maps502AndStripsWWWAuthenticate exercises
// the core M3 response-mapping invariant: rewrite() always injects a
// credential before every proxied request reaches upstream, so a 401
// arriving back means the upstream rejected haybale's own injected
// credential — not something the client did. That must never surface to
// the client as an ordinary 401 (which would make git re-prompt for a
// credential the sandbox has no way to supply); it must be a 502 with no
// WWW-Authenticate header and none of the upstream's own response body.
func TestPostInjectionUpstream401Maps502AndStripsWWWAuthenticate(t *testing.T) {
	upstreamSrv := httptest.NewServer(respondingUpstreamHandler(http.StatusUnauthorized, true))
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want it stripped so git never re-prompts", got)
	}
	if strings.Contains(string(body), "upstream error body") {
		t.Errorf("response body = %q, must not contain the upstream's own error body", body)
	}
}

// TestPostInjectionUpstream401StripsAllUpstreamHeaders exercises the H1
// hardening: modifyResponse must not merely delete WWW-Authenticate from
// the upstream's 401 response, it must reset the client-visible headers
// to a minimal known-safe set. A compromised, misconfigured, or
// lookalike upstream could set Set-Cookie or any other header on its
// 401/403 page; none of it may survive onto the synthetic 502.
func TestPostInjectionUpstream401StripsAllUpstreamHeaders(t *testing.T) {
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
		w.Header().Set("Set-Cookie", "session=upstream-secret-cookie; Path=/")
		w.Header().Set("X-Upstream-Custom", "must-not-leak")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("upstream error body containing details that must never reach the client"))
	}))
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	for _, h := range []string{"WWW-Authenticate", "Set-Cookie", "X-Upstream-Custom"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("%s = %q, want it stripped from the synthetic 502 (headers must be reset wholesale, not selectively deleted)", h, got)
		}
	}
	if strings.Contains(string(body), "upstream error body") || strings.Contains(string(body), "must-not-leak") {
		t.Errorf("response body = %q, must not contain any upstream-controlled content", body)
	}
}

// TestPostInjectionUpstream401DrainsBodyForConnectionReuse exercises the
// other half of H1: the discarded upstream 401 body must be drained to
// EOF before its reader is closed, so the proxy's Transport can return
// the proxy->upstream connection to its keep-alive pool. net/http's
// Transport treats a response body that is closed before being read to
// completion as unreusable and redials on the next request — a bad or
// expired credential is a sustained failure mode (every request to this
// upstream repeats it), so this matters most exactly when it's least
// convenient. This is verified indirectly: the upstream's ConnState hook
// counts how many distinct TCP connections it accepts across two
// sequential requests through the same Proxy (and therefore the same
// underlying http.Transport) — one connection for two requests proves
// the body was drained, not merely that nothing panicked.
func TestPostInjectionUpstream401DrainsBodyForConnectionReuse(t *testing.T) {
	var newConns atomic.Int32
	upstreamSrv := httptest.NewUnstartedServer(respondingUpstreamHandler(http.StatusUnauthorized, true))
	upstreamSrv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	upstreamSrv.Start()
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	for i := 0; i < 2; i++ {
		resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("request %d status = %d, want %d", i, resp.StatusCode, http.StatusBadGateway)
		}
	}

	if got := newConns.Load(); got != 1 {
		t.Errorf("upstream accepted %d new TCP connections for 2 sequential requests, want 1 — the discarded 401 body must be drained to EOF so the proxy's Transport can reuse the connection instead of redialing", got)
	}
}

// TestPostInjectionUpstream403Maps502 mirrors the 401 case for 403 — the
// plan's invariant covers both statuses identically.
func TestPostInjectionUpstream403Maps502(t *testing.T) {
	upstreamSrv := httptest.NewServer(respondingUpstreamHandler(http.StatusForbidden, true))
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want it stripped", got)
	}
}

func TestUpstreamAuthFailedEventLoggedOnPostInjectionFailure(t *testing.T) {
	upstreamSrv := httptest.NewServer(respondingUpstreamHandler(http.StatusUnauthorized, true))
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	line := strings.Join(waitForLogLines(t, buf, 1), "\n")
	for _, want := range []string{
		`"event":"upstream_auth_failed"`,
		`"host":"testhost"`,
		`"owner":"acme"`,
		`"repo":"widgets"`,
		`"verb":"read"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("log output = %q, want it to contain %q", line, want)
		}
	}
	if strings.Contains(line, defaultTestCredential.Password) {
		t.Errorf("log output = %q, must never contain the injected credential", line)
	}
}

// TestUpstreamSuccessResponseIsUnmodified pins the other half of
// modifyResponse's contract: a genuine upstream success (or any status
// other than 401/403) must stream through completely unmodified — no
// stripped headers, no rewritten body, no status change.
func TestUpstreamSuccessResponseIsUnmodified(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-git-upload-pack-result" {
		t.Errorf("Content-Type = %q, want the upstream's own value preserved", got)
	}
}

// TestByteCountingAndDurationLogged exercises the byte-counting request
// log: bytesIn/bytesOut must reflect the actual request/response body
// sizes (counted by wrapping the reader/writer, never by buffering), and
// durationMs must be present.
func TestByteCountingAndDurationLogged(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	payload := []byte("0032want deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n0000")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-upload-pack", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	lines := waitForLogLines(t, buf, 1)
	if len(lines) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %q", len(lines), buf.String())
	}
	line := lines[0]
	if want := `"bytesIn":` + strconv.Itoa(len(payload)); !strings.Contains(line, want) {
		t.Errorf("log record = %q, want it to contain %q", line, want)
	}
	if want := `"bytesOut":` + strconv.Itoa(len(respBody)); !strings.Contains(line, want) {
		t.Errorf("log record = %q, want it to contain %q", line, want)
	}
	if !strings.Contains(line, `"durationMs":`) {
		t.Errorf("log record = %q, want it to contain durationMs", line)
	}
}
