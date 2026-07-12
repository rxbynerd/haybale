package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
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

func TestHealthz(t *testing.T) {
	p := New(newUpstreamMap(t, nil), discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestInvalidRequestMaps404(t *testing.T) {
	p := New(newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), discardLogger())
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
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

func TestUnknownHostMaps404(t *testing.T) {
	p := New(newUpstreamMap(t, map[string]string{"github.com": "http://127.0.0.1:1"}), discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/gitlab.example/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
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

	p := New(newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), discardLogger())
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
	defer resp.Body.Close()
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

func TestForwardsQueryStringAndInfoRefs(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := New(newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), discardLogger())
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
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

	p := New(newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), discardLogger())
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
	defer resp.Body.Close()
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

	p := New(newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), discardLogger())
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
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(respBody, payload) {
		t.Errorf("streamed payload corrupted: got %d bytes, want %d bytes matching", len(respBody), len(payload))
	}
}
