package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// recordingCache is a ResponseCache that records every Serve and
// Invalidate call and, when handle is set, answers reads itself.
type recordingCache struct {
	mu          sync.Mutex
	serves      []gitproto.Repo
	identities  []string
	invalidates []gitproto.Repo
	handle      bool
}

func (c *recordingCache) Serve(w http.ResponseWriter, _ *http.Request, repo gitproto.Repo, _ *url.URL, _ cache.Fetcher, identity string) (cache.Outcome, bool) {
	c.mu.Lock()
	c.serves = append(c.serves, repo)
	c.identities = append(c.identities, identity)
	c.mu.Unlock()
	if !c.handle {
		return cache.Outcome{Result: observability.ResultBypass}, false
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write([]byte("cached"))
	return cache.Outcome{Result: observability.ResultHit, Status: http.StatusOK, BytesOut: int64(n)}, true
}

func (c *recordingCache) Invalidate(_ context.Context, repo gitproto.Repo, _ *url.URL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidates = append(c.invalidates, repo)
}

func (c *recordingCache) counts() (serves, invalidates int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.serves), len(c.invalidates)
}

// trackingBody counts Read calls so a test can prove a body was never
// touched.
type trackingBody struct {
	reads atomic.Int32
}

func (b *trackingBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, io.EOF
}

func (b *trackingBody) Close() error { return nil }

// TestCacheIsOfferedOnlyAfterAuthnAndPolicyAndNeverReadsDeniedBodies
// confirms the cache (the first component that may read a request body)
// is consulted only for a read that authentication and policy allowed. A
// rejected, unauthenticated or policy-denied request, and every write,
// never reach the cache, and the first three never have their body read.
// The recording cache answers an allowed read without reading its body,
// so only the passthrough write reads one here.
func TestCacheIsOfferedOnlyAfterAuthnAndPolicyAndNeverReadsDeniedBodies(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()
	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})

	const uploadPack = "/testhost/acme/widgets.git/git-upload-pack"
	tests := []struct {
		name       string
		auth       identity.Authenticator
		pol        policy.Engine
		path       string
		wantStatus int
		wantServe  bool
		wantRead   bool
	}{
		{"allowed read", allowAllAuthenticator{}, allowAllPolicy{}, uploadPack, http.StatusOK, true, false},
		{"allowed write", allowAllAuthenticator{}, allowAllPolicy{}, "/testhost/acme/widgets.git/git-receive-pack", http.StatusOK, false, true},
		{"policy denied", allowAllAuthenticator{}, denyAllPolicy{}, uploadPack, http.StatusNotFound, false, false},
		{"authn failed", denyAllAuthenticator{}, allowAllPolicy{}, uploadPack, http.StatusUnauthorized, false, false},
		{"rejected path", allowAllAuthenticator{}, allowAllPolicy{}, "/testhost/acme/widgets.git/objects/ab/cdef", http.StatusNotFound, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &recordingCache{handle: true}
			p := mustNew(t, upstreams, tt.auth, tt.pol, discardLogger(), WithCache(rc))

			body := &trackingBody{}
			req := httptest.NewRequest(http.MethodPost, tt.path, body)
			req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			serves, _ := rc.counts()
			if (serves == 1) != tt.wantServe {
				t.Errorf("cache Serve called %d times, want called = %v", serves, tt.wantServe)
			}
			if serves == 1 && rc.identities[0] != testIdentityID {
				t.Errorf("cache Serve identity = %q, want the verified identity %q", rc.identities[0], testIdentityID)
			}
			if (body.reads.Load() > 0) != tt.wantRead {
				t.Errorf("body read %d times, want read = %v", body.reads.Load(), tt.wantRead)
			}
		})
	}
}

// TestWriteInvalidatesCacheRegardlessOfStatus confirms every
// git-receive-pack POST calls Invalidate, whatever upstream answered,
// while the receive-pack handshake (a GET) and reads do not.
func TestWriteInvalidatesCacheRegardlessOfStatus(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			upstreamSrv := httptest.NewServer(respondingUpstreamHandler(status, false))
			defer upstreamSrv.Close()
			rc := &recordingCache{}
			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithCache(rc))
			srv := httptest.NewServer(p)
			defer srv.Close()

			do := func(method, path string) {
				t.Helper()
				req, err := http.NewRequest(method, srv.URL+path, strings.NewReader("0000"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			do(http.MethodGet, "/testhost/acme/widgets.git/info/refs?service=git-receive-pack")
			do(http.MethodPost, "/testhost/acme/widgets.git/git-upload-pack")
			if _, invalidates := rc.counts(); invalidates != 0 {
				t.Fatalf("Invalidate called %d times before any push", invalidates)
			}
			do(http.MethodPost, "/testhost/acme/widgets.git/git-receive-pack")
			if _, invalidates := rc.counts(); invalidates != 1 {
				t.Errorf("Invalidate called %d times after a push answered %d, want 1", invalidates, status)
			}
		})
	}
}

// advertisementUpstream is a fake git upstream that returns a valid
// protocol v2 capability advertisement for GET info/refs and records
// every request it saw.
func advertisementUpstream() (*recordingUpstream, http.Handler) {
	up := &recordingUpstream{}
	return up, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.method, up.path, up.query, up.headers, up.body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body
		up.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000000eversion 2\n0000")
	})
}

// countingCredentialSource counts mints.
type countingCredentialSource struct {
	calls atomic.Int32
}

func (c *countingCredentialSource) Credentials(context.Context, gitproto.Repo, gitproto.Verb) (upstream.BasicAuth, error) {
	c.calls.Add(1)
	return defaultTestCredential, nil
}

// TestCacheHitMintsNoCredential confirms the credential is minted lazily:
// a request served from the cache contacts neither upstream nor the
// credential source.
func TestCacheHitMintsNoCredential(t *testing.T) {
	up, handler := advertisementUpstream()
	upstreamSrv := httptest.NewServer(handler)
	defer upstreamSrv.Close()

	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
	source := &countingCredentialSource{}
	creds := map[string]upstream.CredentialSource{"testhost": source}
	p := mustNewWithCredentials(t, upstreams, creds, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithCache(newProxyCache(t, true)))
	srv := httptest.NewServer(p)
	defer srv.Close()

	var statuses []string
	for range 2 {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Git-Protocol", "version=2")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "version 2") {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		statuses = append(statuses, resp.Header.Get("Cache-Status"))
	}
	if statuses[0] != "haybale; fwd=miss" || statuses[1] != "haybale; hit" {
		t.Errorf("Cache-Status = %q, want a miss then a hit", statuses)
	}
	if source.calls.Load() != 1 {
		t.Errorf("credential minted %d times for a miss and a hit, want 1", source.calls.Load())
	}
	if method, _, _, _, _ := up.snapshot(); method == "" {
		t.Error("upstream never saw the first request")
	}
}

// TestCacheFetcherSendsOnlyAllowlistedHeaders confirms the upstream
// request the cache sends is synthesised from the canonical request: it
// carries only the allowlisted headers, asks for an identity encoding,
// identifies as git, and sends the decoded canonical body with no
// Content-Encoding even when the client gzipped its body.
func TestCacheFetcherSendsOnlyAllowlistedHeaders(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithCache(newProxyCache(t, false)))
	srv := httptest.NewServer(p)
	defer srv.Close()

	// A protocol v2 ls-refs request with the agent line git adds.
	body := pkt(t, "command=ls-refs\n", "agent=git/2.54.0\n", pktline.Delim, "peel\n", pktline.Flush)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(body))
	_ = zw.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-upload-pack", &gz)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.54.0 (client)")
	req.Header.Set("Cookie", "session=client-cookie")
	req.Header.Set("X-Custom", "must-not-be-forwarded")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	method, path, _, headers, got := up.snapshot()
	if method != http.MethodPost || path != "/acme/widgets.git/git-upload-pack" {
		t.Errorf("upstream saw %s %s", method, path)
	}
	// The canonical body has the agent line removed and is not encoded.
	want := pkt(t, "command=ls-refs\n", pktline.Delim, "peel\n", pktline.Flush)
	if string(got) != want {
		t.Errorf("upstream body = %q, want the canonical body %q", got, want)
	}
	allowed := map[string]bool{
		"Accept": true, "Accept-Encoding": true, "Authorization": true, "Content-Length": true,
		"Content-Type": true, "Git-Protocol": true, "User-Agent": true,
	}
	for name := range headers {
		if !allowed[name] {
			t.Errorf("upstream saw header %s = %q, want only the allowlisted set", name, headers.Get(name))
		}
	}
	if got := headers.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", got)
	}
	if got := headers.Get("User-Agent"); !strings.HasPrefix(got, "git/") || strings.Contains(got, "client") {
		t.Errorf("User-Agent = %q, want haybale's fixed git/ agent", got)
	}
	if got := headers.Get("Git-Protocol"); got != "version=2" {
		t.Errorf("Git-Protocol = %q", got)
	}
	if got := headers.Get("Content-Type"); got != "application/x-git-upload-pack-request" {
		t.Errorf("Content-Type = %q", got)
	}
}

// TestCacheCredentialErrorFallsBackToPassthrough502 confirms a credential
// mint failure inside the cache's fetcher releases the request to the
// passthrough path, which answers 502 and logs upstream_auth_failed as it
// does without a cache.
func TestCacheCredentialErrorFallsBackToPassthrough502(t *testing.T) {
	up := &recordingUpstream{}
	upstreamSrv := httptest.NewServer(up.handler())
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
	creds := map[string]upstream.CredentialSource{"testhost": erroringCredentialSource{err: io.ErrUnexpectedEOF}}
	p := mustNewWithCredentials(t, upstreams, creds, allowAllAuthenticator{}, allowAllPolicy{}, logger, WithCache(newProxyCache(t, false)))
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if method, _, _, _, _ := up.snapshot(); method != "" {
		t.Error("upstream saw a request without a credential")
	}
	if line := strings.Join(waitForLogLines(t, buf, 1), "\n"); !strings.Contains(line, `"event":"upstream_auth_failed"`) {
		t.Errorf("log = %q, want the upstream_auth_failed event", line)
	}
}

// TestProxiedRequestLogsCacheFields confirms the request log carries the
// documented cache fields: cache on every read when a cache is
// configured, cacheCollapsed and cacheStored on a miss, and nothing on a
// write.
func TestProxiedRequestLogsCacheFields(t *testing.T) {
	_, handler := advertisementUpstream()
	upstreamSrv := httptest.NewServer(handler)
	defer upstreamSrv.Close()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger, WithCache(newProxyCache(t, false)))
	srv := httptest.NewServer(p)
	defer srv.Close()

	do := func(method, path string, body io.Reader) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Git-Protocol", "version=2")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	do(http.MethodGet, "/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	do(http.MethodGet, "/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
	// A fetch with a have line is not cacheable and passes through.
	do(http.MethodPost, "/testhost/acme/widgets.git/git-upload-pack", strings.NewReader(pkt(t,
		"command=fetch\n", pktline.Delim,
		"want 1f1e5c8e3a0b9d2c4e6f8a0b1c2d3e4f5a6b7c8d\n", "have 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b\n", "done\n", pktline.Flush)))
	do(http.MethodPost, "/testhost/acme/widgets.git/git-receive-pack", strings.NewReader("0000"))

	lines := waitForLogLines(t, buf, 4)
	if len(lines) != 4 {
		t.Fatalf("got %d log records, want 4: %q", len(lines), lines)
	}
	checks := []struct {
		want   []string
		absent []string
	}{
		{want: []string{`"cache":"miss"`, `"cacheCollapsed":false`, `"cacheStored":true`}},
		{want: []string{`"cache":"hit"`}, absent: []string{"cacheCollapsed", "cacheStored"}},
		{want: []string{`"cache":"bypass"`, `"status":200`}, absent: []string{"cacheCollapsed"}},
		{want: []string{`"verb":"write"`}, absent: []string{`"cache"`}},
	}
	for i, c := range checks {
		for _, want := range c.want {
			if !strings.Contains(lines[i], want) {
				t.Errorf("line %d = %q, want it to contain %q", i, lines[i], want)
			}
		}
		for _, absent := range c.absent {
			if strings.Contains(lines[i], absent) {
				t.Errorf("line %d = %q, want it without %q", i, lines[i], absent)
			}
		}
	}
}
