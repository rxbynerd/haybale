package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
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

// mustNew builds a Proxy via New, failing the test immediately if
// construction returns an error. Every test in this file (other than
// TestNewRejectsNilAuthenticator/TestNewRejectsNilPolicyEngine, which
// exercise that error path directly) passes well-formed dependencies, so
// an error here would indicate a test bug rather than the behaviour
// under test.
func mustNew(t *testing.T, upstreams map[string]*url.URL, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger) *Proxy {
	t.Helper()
	p, err := New(upstreams, authenticator, policyEngine, logger)
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

// TestInboundAuthorizationHeaderIsStripped exercises B-1: the client's
// inbound Authorization header — the haybale auth token Authenticate
// just checked, whether presented as HTTP Basic or as an
// `Authorization: Bearer <token>` header — must never reach the
// upstream. httputil.ReverseProxy only strips the RFC hop-by-hop header
// set by default, and Authorization is end-to-end, not hop-by-hop, so
// without an explicit strip it clones straight through, letting anything
// with visibility into the upstream leg replay the haybale credential
// directly against haybale itself. M3 will inject its own
// upstream-appropriate Authorization in this same spot; until then, the
// correct behaviour is simply "absent", which is what this test pins.
func TestInboundAuthorizationHeaderIsStripped(t *testing.T) {
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
			if got := headers.Get("Authorization"); got != "" {
				t.Errorf("upstream saw Authorization = %q, want it absent", got)
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

// logLines splits a JSON-lines log buffer into its non-empty lines.
func logLines(buf *bytes.Buffer) []string {
	trimmed := strings.TrimSpace(buf.String())
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestRejectedRequestIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/github.com/acme/widgets.git/objects/ab/cdef")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := logLines(&buf)
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
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), allowAllAuthenticator{}, allowAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gitlab.example/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := logLines(&buf)
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

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
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

	lines := logLines(&buf)
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
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
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

	lines := logLines(&buf)
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
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), allowAllAuthenticator{}, denyAllPolicy{}, logger)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	lines := logLines(&buf)
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
	p, err := New(newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), nil, allowAllPolicy{}, discardLogger())
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
	p, err := New(newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"}), allowAllAuthenticator{}, nil, discardLogger())
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
