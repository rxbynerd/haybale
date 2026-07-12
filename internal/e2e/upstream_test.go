package e2e

import (
	"net/http"
	"net/http/cgi" //nolint:gosec // G504: the CVE this flags (httpoxy, CVE-2016-5386) was fixed in Go 1.6.3; go.mod requires go 1.26.1, and this is a test-only CGI upstream, not internet-facing
	"net/http/httptest"
	"sync"
	"testing"
)

// upstreamBasicAuthUsername and upstreamBasicAuthToken are the Basic-auth
// credential newUpstream's middleware requires on every request — the
// "real" upstream credential haybale must inject (never the client's own
// haybale token) for a proxied request to succeed at all. M3 e2e
// requirement: the upstream now genuinely enforces auth, so a successful
// clone/push through haybale is proof injection works, not a passthrough
// that happened to work because the upstream never checked anything.
const (
	upstreamBasicAuthUsername = "x-access-token"
	upstreamBasicAuthToken    = "e2e-upstream-token"
)

// headerRecorder captures headers seen on the first request the
// upstream receives, so a test can assert haybale forwarded something
// (Git-Protocol in particular) without the recording logic living
// inside git-http-backend itself.
type headerRecorder struct {
	mu      sync.Mutex
	headers http.Header
	seen    bool
}

func (r *headerRecorder) record(h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.seen {
		r.headers = h.Clone()
		r.seen = true
	}
}

// GitProtocol returns the Git-Protocol header value from the first
// request the upstream received, or "" if none arrived yet.
func (r *headerRecorder) GitProtocol() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headers == nil {
		return ""
	}
	return r.headers.Get("Git-Protocol")
}

// Authorization returns the Authorization header value from the first
// request the upstream received, or "" if none arrived yet — used by
// the M3 leak assertions to confirm the upstream sees haybale's injected
// credential rather than anything derived from the client's own token.
func (r *headerRecorder) Authorization() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headers == nil {
		return ""
	}
	return r.headers.Get("Authorization")
}

// newUpstream stands up a real git smart-HTTP server: an httptest server
// backed by git-http-backend via net/http/cgi, serving whatever bare
// repos live under projectRoot. A Basic-auth-requiring middleware sits
// in front of a headerRecorder middleware sits in front of the CGI
// handler, so a test can assert both that haybale's injected credential
// (rather than the client's own token) is what reaches upstream, and
// that the upstream genuinely enforces auth rather than accepting
// anything (or nothing) at all — a request presenting anything other
// than upstreamBasicAuthUsername/upstreamBasicAuthToken gets a 401 with
// a WWW-Authenticate challenge, exactly the shape a real git host's auth
// failure takes.
func newUpstream(t *testing.T, httpBackendPath, projectRoot string) (*httptest.Server, *headerRecorder) {
	t.Helper()

	backend := &cgi.Handler{
		Path: httpBackendPath,
		Root: "/",
		Dir:  projectRoot,
		Env: []string{
			"GIT_PROJECT_ROOT=" + projectRoot,
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}

	rec := &headerRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != upstreamBasicAuthUsername || password != upstreamBasicAuthToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="e2e-upstream"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		rec.record(r.Header)
		backend.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rec
}
