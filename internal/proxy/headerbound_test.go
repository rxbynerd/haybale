package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPassthroughBoundsReadHeaders: with a read header timeout, a read
// whose upstream never sends headers is answered 502 within the bound; a
// read whose headers arrive in time streams a body that outlasts the
// bound; and a push is not bounded at all.
func TestPassthroughBoundsReadHeaders(t *testing.T) {
	const bound = 100 * time.Millisecond
	body := []byte("0008NAK\n0000")
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/info/refs"):
			<-r.Context().Done()
		case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-time.After(3 * bound)
			_, _ = w.Write(body)
		default:
			<-time.After(3 * bound)
			_, _ = w.Write(body)
		}
	}))
	defer upstreamSrv.Close()
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithReadHeaderTimeout(bound))
	srv := httptest.NewServer(p)
	defer srv.Close()

	do := func(t *testing.T, method, path, contentType string) (int, []byte, time.Duration) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+"/testhost/acme/widgets.git/"+path, bytes.NewReader(nil))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		client := &http.Client{Timeout: 10 * time.Second}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return resp.StatusCode, got, time.Since(start)
	}

	t.Run("a hung read is answered 502 at the bound", func(t *testing.T) {
		status, _, elapsed := do(t, http.MethodGet, "info/refs?service=git-upload-pack", "")
		if status != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", status)
		}
		if elapsed < bound || elapsed > 5*time.Second {
			t.Errorf("hung read took %v, want about the %v bound", elapsed, bound)
		}
	})

	t.Run("a read's body may outlast the bound", func(t *testing.T) {
		status, got, _ := do(t, http.MethodPost, "git-upload-pack", "application/x-git-upload-pack-request")
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("read = %d %q, want 200 with the whole body", status, got)
		}
	})

	t.Run("a push is not bounded", func(t *testing.T) {
		status, got, _ := do(t, http.MethodPost, "git-receive-pack", "application/x-git-receive-pack-request")
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("push = %d %q, want 200 once upstream answers", status, got)
		}
	})
}
