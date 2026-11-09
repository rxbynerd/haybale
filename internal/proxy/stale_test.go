package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// manualClock is a clock that moves only when the test advances it.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestUpstream502ClaimingARejectedCredentialIsAnOutage: during an outage
// an upstream 502 that itself claims, in cache.UpstreamStatusHeader, to
// be a rejected 401 or 403 is an ordinary 502: the probe that receives it
// is answered stale, the client never sees the header, and the health
// gate stays open.
func TestUpstream502ClaimingARejectedCredentialIsAnOutage(t *testing.T) {
	var down atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			// The path is /acme/widgets-<claim>.git/info/refs.
			repo := strings.TrimSuffix(strings.Split(r.URL.Path, "/")[2], ".git")
			w.Header().Set(cache.UpstreamStatusHeader, repo[strings.LastIndex(repo, "-")+1:])
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "bad gateway\n")
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000000eversion 2\n0000")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	first := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = first.Serve(ln) }()
	t.Cleanup(func() { _ = first.Close() })

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
	clock := &manualClock{t: time.Now()}
	c, err := cache.New(cache.Options{
		Dir: dir, Keyring: kr, MaxDiskSize: 16 << 20, MaxEntrySize: 4 << 20, MaxConcurrentFills: 2,
		MaxRequestBody: 1 << 20, Retention: time.Hour, StaleIfErrorFor: time.Hour, ResponseHeaderTimeout: 5 * time.Second,
		ExposeStatus: true, Logger: logger, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": "http://" + addr}), allowAllAuthenticator{}, allowAllPolicy{}, logger, WithCache(c))
	srv := httptest.NewServer(p)
	defer srv.Close()
	get := func(t *testing.T, repo string) (*http.Response, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + "/testhost/acme/" + repo + ".git/info/refs?service=git-upload-pack")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	claims := []string{"401", "403"}
	for _, claim := range claims {
		if resp, _ := get(t, "widgets-"+claim); resp.StatusCode != http.StatusOK {
			t.Fatalf("seeding widgets-%s = %d, want 200", claim, resp.StatusCode)
		}
	}
	_ = first.Close()
	if resp, _ := get(t, "unseen"); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("refused upstream without an entry = %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(buf.String(), "upstream health gate opened") {
		t.Fatal("the refused connection did not open the gate")
	}

	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen again on %s: %v", addr, err)
	}
	down.Store(true)
	second := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = second.Serve(ln) }()
	t.Cleanup(func() { _ = second.Close() })

	for _, claim := range claims {
		clock.Advance(time.Minute)
		resp, body := get(t, "widgets-"+claim)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "version 2") {
			t.Errorf("502 claiming %s = %d %q, want the stored advertisement", claim, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Cache-Status"); got != "haybale; hit; fwd=stale; fwd-status=502" {
			t.Errorf("502 claiming %s: Cache-Status = %q, want the probe's stale form", claim, got)
		}
		if v := resp.Header.Get(cache.UpstreamStatusHeader); v != "" {
			t.Errorf("502 claiming %s: client saw %s = %q", claim, cache.UpstreamStatusHeader, v)
		}
	}
	if strings.Contains(buf.String(), "upstream health gate closed") {
		t.Error("a 502 claiming a rejected credential closed the gate")
	}
}
