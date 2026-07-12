package e2e

import (
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"sync"
	"testing"
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

// newUpstream stands up a real git smart-HTTP server: an httptest server
// backed by git-http-backend via net/http/cgi, serving whatever bare
// repos live under projectRoot. A headerRecorder middleware sits in
// front of the CGI handler so the test can assert on headers the
// request arrived with (this is the "upstream middleware" the M1 e2e
// requirement calls for), independent of whatever git-http-backend
// itself does with them.
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
		rec.record(r.Header)
		backend.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rec
}
