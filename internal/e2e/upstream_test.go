package e2e

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/cgi" //nolint:gosec // G504: the CVE this flags (httpoxy, CVE-2016-5386) was fixed in Go 1.6.3; go.mod requires go 1.26.1, and this is a test-only CGI upstream, not internet-facing
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// upstreamBasicAuthUsername and upstreamBasicAuthToken are the Basic-auth
// credential newUpstream's middleware requires on every request — the
// upstream credential haybale must inject, rather than the client JWT, for a
// proxied request to succeed.
const (
	upstreamBasicAuthUsername = "x-access-token"
	upstreamBasicAuthToken    = "e2e-upstream-token" //nolint:gosec // G101: a fixed, fake test-only credential this package's own fake upstream requires — never a real secret
)

// endpoint classifies a smart-HTTP request for the recorder's counters.
type endpoint string

const (
	// endpointInfoRefs is GET info/refs for either service.
	endpointInfoRefs endpoint = "info/refs"
	// endpointLsRefs is a POST git-upload-pack carrying command=ls-refs.
	endpointLsRefs endpoint = "ls-refs"
	// endpointFetch is a POST git-upload-pack carrying a fetch: a v2
	// command=fetch or v0 want lines.
	endpointFetch endpoint = "fetch"
	// endpointReceivePack is a POST git-receive-pack.
	endpointReceivePack endpoint = "receive-pack"
	endpointOther       endpoint = "other"
)

// requestRecorder records the headers of the first request it sees, how
// many requests reached each endpoint, the Content-Encoding each
// upload-pack POST carried, and how many fetch POSTs carried have lines.
// It is placed in front of the upstream and in front of haybale, so a
// test can compare what the client sent with what the upstream saw.
type requestRecorder struct {
	mu        sync.Mutex
	headers   http.Header
	seen      bool
	counts    map[endpoint]int
	encodings map[endpoint][]string
	haves     int
}

func newRequestRecorder() *requestRecorder {
	return &requestRecorder{counts: make(map[endpoint]int), encodings: make(map[endpoint][]string)}
}

// observe classifies r, records it, and replaces r.Body with the bytes it
// read so the next handler sees the request unchanged. It returns the
// endpoint and whether a fetch carried have lines.
func (r *requestRecorder) observe(req *http.Request) endpoint {
	ep := endpointOther
	var hasHave bool
	switch {
	case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/info/refs"):
		ep = endpointInfoRefs
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/git-receive-pack"):
		ep = endpointReceivePack
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/git-upload-pack"):
		raw, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		decoded := raw
		if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") {
			if zr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
				if d, err := io.ReadAll(zr); err == nil {
					decoded = d
				}
			}
		}
		if bytes.Contains(decoded, []byte("command=ls-refs")) {
			ep = endpointLsRefs
		} else {
			ep = endpointFetch
			hasHave = bytes.Contains(decoded, []byte("have "))
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.seen {
		r.headers = req.Header.Clone()
		r.seen = true
	}
	r.counts[ep]++
	if ep == endpointLsRefs || ep == endpointFetch {
		r.encodings[ep] = append(r.encodings[ep], req.Header.Get("Content-Encoding"))
	}
	if hasHave {
		r.haves++
	}
	return ep
}

// handler wraps next so every request is observed first.
func (r *requestRecorder) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.observe(req)
		next.ServeHTTP(w, req)
	})
}

// Count returns how many requests reached ep.
func (r *requestRecorder) Count(ep endpoint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[ep]
}

// Encodings returns the Content-Encoding of every upload-pack POST to ep,
// in arrival order; "" is an identity body.
func (r *requestRecorder) Encodings(ep endpoint) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.encodings[ep]...)
}

// Haves returns how many fetch POSTs carried have lines.
func (r *requestRecorder) Haves() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.haves
}

// GitProtocol returns the Git-Protocol header value from the first
// request the upstream received, or "" if none arrived yet.
func (r *requestRecorder) GitProtocol() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headers == nil {
		return ""
	}
	return r.headers.Get("Git-Protocol")
}

// Authorization returns the Authorization header value from the first
// request the upstream received, or "" if none arrived yet.
func (r *requestRecorder) Authorization() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headers == nil {
		return ""
	}
	return r.headers.Get("Authorization")
}

// upstreamFaults injects failures into the fake upstream's responses.
type upstreamFaults struct {
	// truncateFetch makes every fetch response carry only the first half
	// of upload-pack's output, with a Content-Length that matches what is
	// sent, so the HTTP exchange is clean but the pkt-line stream is cut.
	truncateFetch atomic.Bool
}

// newUpstream stands up a real git smart-HTTP server: an httptest server
// backed by git-http-backend via net/http/cgi, serving whatever bare
// repos live under projectRoot. A Basic-auth-requiring middleware sits
// in front of a requestRecorder in front of the CGI handler, so a test
// can assert both that haybale's injected credential (rather than the
// client's own token) is what reaches upstream, and that the upstream
// genuinely enforces auth rather than accepting anything (or nothing) at
// all — a request presenting anything other than
// upstreamBasicAuthUsername/upstreamBasicAuthToken gets a 401 with a
// WWW-Authenticate challenge, exactly the shape a real git host's auth
// failure takes.
func newUpstream(t *testing.T, httpBackendPath, projectRoot string) (*httptest.Server, *requestRecorder) {
	t.Helper()
	srv, rec, _ := newFaultyUpstream(t, httpBackendPath, projectRoot)
	return srv, rec
}

// newFaultyUpstream is newUpstream with a handle to inject faults.
func newFaultyUpstream(t *testing.T, httpBackendPath, projectRoot string) (*httptest.Server, *requestRecorder, *upstreamFaults) {
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

	rec := newRequestRecorder()
	faults := &upstreamFaults{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != upstreamBasicAuthUsername || password != upstreamBasicAuthToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="e2e-upstream"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		ep := rec.observe(r)
		if ep == endpointFetch && faults.truncateFetch.Load() {
			truncateResponse(w, r, backend)
			return
		}
		backend.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rec, faults
}

// truncateResponse runs next into a buffer and relays its status and
// headers with only the first half of its body, declaring that length.
func truncateResponse(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := httptest.NewRecorder()
	next.ServeHTTP(buf, r)
	body := buf.Body.Bytes()[:buf.Body.Len()/2]
	for k, vs := range buf.Header() {
		if k != "Content-Length" && k != "Transfer-Encoding" {
			w.Header()[k] = vs
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(buf.Code)
	_, _ = w.Write(body)
}
