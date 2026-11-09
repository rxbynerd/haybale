package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
)

// TestStaleServiceThroughTheProxy runs advertisement requests through a
// stale-enabled cache while the upstream changes its answer: a stored
// advertisement answers a 503 stale, with the verified identity on the
// event and "stale" in the request log, while an upstream 401 stays the
// sanitised 502 and never reveals the status it carried.
func TestStaleServiceThroughTheProxy(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s := int(status.Load()); s != http.StatusOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
			w.WriteHeader(s)
			_, _ = io.WriteString(w, "upstream says no\n")
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000000eversion 2\n0000")
	}))
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kr, err := cache.EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(cache.Options{
		Dir: dir, Keyring: kr, MaxDiskSize: 16 << 20, MaxEntrySize: 4 << 20, MaxConcurrentFills: 2,
		MaxRequestBody: 1 << 20, Retention: time.Hour, StaleIfErrorFor: time.Hour, ResponseHeaderTimeout: 5 * time.Second,
		ExposeStatus: true, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger, WithCache(c))
	srv := httptest.NewServer(p)
	defer srv.Close()

	get := func(t *testing.T) (*http.Response, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	if resp, _ := get(t); resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Status") != "haybale; fwd=miss" {
		t.Fatalf("seeding request = %d %q, want a 200 miss", resp.StatusCode, resp.Header.Get("Cache-Status"))
	}

	status.Store(http.StatusServiceUnavailable)
	resp, body := get(t)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "version 2") {
		t.Fatalf("upstream 503: client got %d %q, want the stored advertisement", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Status"); got != "haybale; hit; fwd=stale; fwd-status=503" {
		t.Errorf("Cache-Status = %q, want the stale form", got)
	}
	lines := strings.Join(waitForLogLines(t, buf, 2), "\n")
	for _, want := range []string{`"event":"cache_stale_served"`, `"identity":"` + testIdentityID + `"`, `"cache":"stale"`} {
		if !strings.Contains(lines, want) {
			t.Errorf("logs = %q, want %q", lines, want)
		}
	}

	// A rejected credential marks the key uncacheable for the transient
	// cooldown, so only the first rejection reaches the cache's shared
	// response; the second takes the passthrough path, also a 502.
	for i, rejected := range []int32{http.StatusUnauthorized, http.StatusForbidden} {
		status.Store(rejected)
		resp, body := get(t)
		if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "upstream says no") {
			t.Errorf("upstream %d: client got %d %q, want the sanitised 502", rejected, resp.StatusCode, body)
		}
		if v := resp.Header.Get(cache.UpstreamStatusHeader); v != "" {
			t.Errorf("upstream %d: client saw %s = %q", rejected, cache.UpstreamStatusHeader, v)
		}
		if got := resp.Header.Get("Cache-Status"); i == 0 && got != "haybale; fwd=miss" {
			t.Errorf("upstream %d: Cache-Status = %q, want the shared response form", rejected, got)
		}
	}
	if n := strings.Count(buf.String(), `"event":"cache_stale_served"`); n != 1 {
		t.Errorf("cache_stale_served events = %d, want only the one for the 503", n)
	}
}

// TestUpstreamCopiesOfTheStatusHeaderAreIgnored: an upstream that sends
// cache.UpstreamStatusHeader itself can neither trigger nor suppress
// stale service, and the header never reaches the client, through the
// cache or the passthrough path.
func TestUpstreamCopiesOfTheStatusHeaderAreIgnored(t *testing.T) {
	type answer struct {
		status int
		claim  string
	}
	var current atomic.Pointer[answer]
	current.Store(&answer{status: http.StatusOK, claim: "503"})
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a := current.Load()
		w.Header().Set(cache.UpstreamStatusHeader, a.claim)
		if a.status != http.StatusOK {
			w.WriteHeader(a.status)
			_, _ = io.WriteString(w, "upstream says no\n")
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000000eversion 2\n0000")
	}))
	defer upstreamSrv.Close()

	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kr, err := cache.EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(cache.Options{
		Dir: dir, Keyring: kr, MaxDiskSize: 16 << 20, MaxEntrySize: 4 << 20, MaxConcurrentFills: 2,
		MaxRequestBody: 1 << 20, Retention: time.Hour, StaleIfErrorFor: time.Hour, ExposeStatus: true,
		ResponseHeaderTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
	logger := slog.New(slog.DiscardHandler)
	cached := httptest.NewServer(mustNew(t, upstreams, allowAllAuthenticator{}, allowAllPolicy{}, logger, WithCache(c)))
	defer cached.Close()
	passthrough := httptest.NewServer(mustNew(t, upstreams, allowAllAuthenticator{}, allowAllPolicy{}, logger))
	defer passthrough.Close()

	get := func(t *testing.T, base, repo string, a answer) *http.Response {
		t.Helper()
		current.Store(&a)
		resp, err := http.Get(base + "/testhost/acme/" + repo + ".git/info/refs?service=git-upload-pack")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if v := resp.Header.Get(cache.UpstreamStatusHeader); v != "" {
			t.Errorf("upstream %d: client saw %s = %q", a.status, cache.UpstreamStatusHeader, v)
		}
		return resp
	}

	// Each case has its own repository with a stored advertisement, since
	// a relayed 4xx marks its key uncacheable.
	seed := func(t *testing.T, repo string) {
		t.Helper()
		if resp := get(t, cached.URL, repo, answer{status: http.StatusOK, claim: "503"}); resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Status") != "haybale; fwd=miss" {
			t.Fatalf("seeding %s = %d %q, want a 200 miss", repo, resp.StatusCode, resp.Header.Get("Cache-Status"))
		}
	}
	for _, status := range []int{http.StatusNotFound, http.StatusTooManyRequests} {
		repo := "widgets-" + strconv.Itoa(status)
		seed(t, repo)
		resp := get(t, cached.URL, repo, answer{status: status, claim: "503"})
		if resp.StatusCode != status || resp.Header.Get("Cache-Status") != "haybale; fwd=miss" {
			t.Errorf("upstream %d claiming 503 = %d %q, want the upstream's answer relayed", status, resp.StatusCode, resp.Header.Get("Cache-Status"))
		}
	}
	seed(t, "widgets-503")
	resp := get(t, cached.URL, "widgets-503", answer{status: http.StatusServiceUnavailable, claim: "200"})
	if got := resp.Header.Get("Cache-Status"); resp.StatusCode != http.StatusOK || got != "haybale; hit; fwd=stale; fwd-status=503" {
		t.Errorf("upstream 503 claiming 200 = %d %q, want it served stale", resp.StatusCode, got)
	}
	for _, a := range []answer{{status: http.StatusOK, claim: "503"}, {status: http.StatusServiceUnavailable, claim: "401"}} {
		if resp := get(t, passthrough.URL, "widgets", a); resp.StatusCode != a.status {
			t.Errorf("passthrough upstream %d = %d, want it relayed", a.status, resp.StatusCode)
		}
	}
}
