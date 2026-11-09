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
	"time"
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
	// gzipFetch gzips every fetch response and says so with
	// Content-Encoding, whatever Accept-Encoding the request carried.
	gzipFetch atomic.Bool
	// holdReceivePack delays every receive-pack response, headers
	// included, by this many nanoseconds after the backend has run.
	holdReceivePack atomic.Int64
	// rejectCredentials answers every request 401, as an upstream does
	// when haybale's credential has been revoked.
	rejectCredentials atomic.Bool
	// unavailable answers every authenticated request 503.
	unavailable atomic.Bool

	mu   sync.Mutex
	held *heldFetch
}

// heldFetch makes one fetch response pause after its first half: started
// is closed once the half has been flushed and the rest follows once
// release is closed.
type heldFetch struct {
	started chan struct{}
	release chan struct{}
}

// holdNextFetch arranges for the next fetch response to pause halfway.
func (f *upstreamFaults) holdNextFetch() *heldFetch {
	h := &heldFetch{started: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.held = h
	f.mu.Unlock()
	return h
}

// takeHeld returns the pending hold, if any, and clears it.
func (f *upstreamFaults) takeHeld() *heldFetch {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.held
	f.held = nil
	return h
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
	handler, rec, faults := newUpstreamHandler(httpBackendPath, projectRoot)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, rec, faults
}

// newUpstreamHandler is the handler behind newFaultyUpstream, for a test
// that runs it on a server of its own.
func newUpstreamHandler(httpBackendPath, projectRoot string) (http.Handler, *requestRecorder, *upstreamFaults) {
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
		if !ok || username != upstreamBasicAuthUsername || password != upstreamBasicAuthToken || faults.rejectCredentials.Load() {
			w.Header().Set("WWW-Authenticate", `Basic realm="e2e-upstream"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		if faults.unavailable.Load() {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		ep := rec.observe(r)
		switch {
		case ep == endpointFetch && faults.truncateFetch.Load():
			truncateResponse(w, r, backend)
		case ep == endpointFetch && faults.gzipFetch.Load():
			gzipResponse(w, r, backend)
		case ep == endpointReceivePack && faults.holdReceivePack.Load() > 0:
			delayResponse(w, r, backend, time.Duration(faults.holdReceivePack.Load()))
		default:
			if ep == endpointFetch {
				if held := faults.takeHeld(); held != nil {
					holdResponse(w, r, backend, held)
					return
				}
			}
			backend.ServeHTTP(w, r)
		}
	})
	return mux, rec, faults
}

// truncateResponse runs next into a buffer and relays its status and
// headers with only the first half of its body, declaring that length.
func truncateResponse(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := bufferResponse(w, r, next)
	body := buf.Body.Bytes()[:buf.Body.Len()/2]
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(buf.Code)
	_, _ = w.Write(body)
}

// gzipResponse runs next into a buffer and relays its status and headers
// with the body gzipped and Content-Encoding set.
func gzipResponse(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := bufferResponse(w, r, next)
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	_, _ = zw.Write(buf.Body.Bytes())
	_ = zw.Close()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.Itoa(zipped.Len()))
	w.WriteHeader(buf.Code)
	_, _ = w.Write(zipped.Bytes())
}

// holdResponse runs next into a buffer, sends the first half of its body
// with an unknown length, signals held.started, and sends the rest once
// held.release is closed.
func holdResponse(w http.ResponseWriter, r *http.Request, next http.Handler, held *heldFetch) {
	buf := bufferResponse(w, r, next)
	body := buf.Body.Bytes()
	w.WriteHeader(buf.Code)
	_, _ = w.Write(body[:len(body)/2])
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	close(held.started)
	<-held.release
	_, _ = w.Write(body[len(body)/2:])
}

// delayResponse runs next into a buffer and relays it in full after d.
func delayResponse(w http.ResponseWriter, r *http.Request, next http.Handler, d time.Duration) {
	buf := bufferResponse(w, r, next)
	time.Sleep(d)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Body.Len()))
	w.WriteHeader(buf.Code)
	_, _ = w.Write(buf.Body.Bytes())
}

// bufferResponse runs next into a recorder and copies its headers, except
// the framing ones, onto w.
func bufferResponse(w http.ResponseWriter, r *http.Request, next http.Handler) *httptest.ResponseRecorder {
	buf := httptest.NewRecorder()
	next.ServeHTTP(buf, r)
	for k, vs := range buf.Header() {
		if k != "Content-Length" && k != "Transfer-Encoding" {
			w.Header()[k] = vs
		}
	}
	return buf
}
