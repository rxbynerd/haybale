package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

const refsPath = "/testhost/acme/widgets.git/info/refs?service=git-upload-pack"

// invalidationProbe is a ResponseCache that declines every read and
// records each Invalidate call along with the state of its context.
type invalidationProbe struct {
	mu      sync.Mutex
	ctxErrs []error
}

func (c *invalidationProbe) Serve(http.ResponseWriter, *http.Request, gitproto.Repo, *url.URL, cache.Fetcher) (cache.Outcome, bool) {
	return cache.Outcome{Result: observability.ResultBypass}, false
}

func (c *invalidationProbe) Invalidate(ctx context.Context, _ gitproto.Repo, _ *url.URL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctxErrs = append(c.ctxErrs, ctx.Err())
}

// disconnectingWriter is a ResponseWriter whose client has gone away: the
// first body write cancels the request context and fails.
type disconnectingWriter struct {
	header http.Header
	cancel context.CancelFunc
}

func (w *disconnectingWriter) Header() http.Header { return w.header }
func (w *disconnectingWriter) WriteHeader(int)     {}
func (w *disconnectingWriter) Write([]byte) (int, error) {
	w.cancel()
	return 0, errors.New("client disconnected")
}

// TestPushInvalidatesCacheWhenClientDisconnectsMidResponse confirms a
// push still invalidates the cache, exactly once and with a live context,
// when the client disconnects while the response is copied and
// httputil.ReverseProxy aborts the handler with a panic.
func TestPushInvalidatesCacheWhenClientDisconnectsMidResponse(t *testing.T) {
	upstreamSrv := httptest.NewServer(respondingUpstreamHandler(http.StatusOK, false))
	defer upstreamSrv.Close()
	probe := &invalidationProbe{}
	p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithCache(probe))

	// ReverseProxy panics on a failed response copy only for a request
	// served by an http.Server, which the context value signals.
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), http.ServerContextKey, &http.Server{ReadHeaderTimeout: time.Second}))
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/testhost/acme/widgets.git/git-receive-pack", strings.NewReader("0000"))
	w := &disconnectingWriter{header: http.Header{}, cancel: cancel}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		p.ServeHTTP(w, req)
	}()

	if recovered != http.ErrAbortHandler {
		t.Fatalf("ServeHTTP recovered %v, want http.ErrAbortHandler", recovered)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.ctxErrs) != 1 {
		t.Fatalf("Invalidate called %d times, want 1", len(probe.ctxErrs))
	}
	if probe.ctxErrs[0] != nil {
		t.Errorf("Invalidate context error = %v, want a context that survives request cancellation", probe.ctxErrs[0])
	}
}

// TestCredentialSourceErrorTextIsNeverLogged confirms the text of a
// credential source's error reaches no log record at any level, on the
// passthrough path and on the cache path whose fetcher wraps the error.
func TestCredentialSourceErrorTextIsNeverLogged(t *testing.T) {
	const canary = "CANARY-7f3a"
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			upstreamSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			defer upstreamSrv.Close()

			buf := &syncBuffer{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})
			creds := map[string]upstream.CredentialSource{"testhost": erroringCredentialSource{err: errors.New("mint failed: " + canary)}}
			p := mustNewWithCredentials(t, upstreams, creds, allowAllAuthenticator{}, allowAllPolicy{}, logger, path.options(t)...)
			srv := httptest.NewServer(p)

			resp, err := http.Get(srv.URL + refsPath)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			srv.Close()

			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", resp.StatusCode)
			}
			logs := buf.String()
			if !strings.Contains(logs, `"event":"upstream_auth_failed"`) {
				t.Errorf("logs = %q, want the upstream_auth_failed event", logs)
			}
			if strings.Contains(logs, canary) {
				t.Errorf("logs = %q, must never contain the credential source's error text", logs)
			}
		})
	}
}

// encodedResponse is the part of a client response that must not depend on
// which path served it.
type encodedResponse struct {
	status      int
	contentType string
	encoding    string
	body        []byte
}

// TestEncodedUpstreamResponseMatchesPassthrough confirms an upstream that
// gzips its answer whatever Accept-Encoding says reaches the client
// byte-for-byte as on the passthrough path, with every request going
// upstream because nothing about it is stored.
func TestEncodedUpstreamResponseMatchesPassthrough(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("001e# service=git-upload-pack\n0000000eversion 2\n0000"))
	_ = zw.Close()

	var hits atomic.Int32
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz.Bytes())
	}))
	defer upstreamSrv.Close()

	got := map[string]encodedResponse{}
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), path.options(t)...)
			srv := httptest.NewServer(p)
			defer srv.Close()

			seen := hits.Load()
			for i := range 2 {
				req, err := http.NewRequest(http.MethodGet, srv.URL+refsPath, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Git-Protocol", "version=2")
				req.Header.Set("Accept-Encoding", "gzip")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if now := hits.Load(); now <= seen {
					t.Errorf("request %d did not reach upstream", i)
				} else {
					seen = now
				}
				got[path.name] = encodedResponse{
					status:      resp.StatusCode,
					contentType: resp.Header.Get("Content-Type"),
					encoding:    resp.Header.Get("Content-Encoding"),
					body:        body,
				}
			}
		})
	}

	want := encodedResponse{
		status:      http.StatusOK,
		contentType: "application/x-git-upload-pack-advertisement",
		encoding:    "gzip",
		body:        gz.Bytes(),
	}
	for name, resp := range got {
		if !reflect.DeepEqual(resp, want) {
			t.Errorf("%s response = %+v, want the upstream's response %+v", name, resp, want)
		}
	}
}

// TestUpstreamBaseQueryMergesWithEndpointQuery confirms an upstream base
// URL carrying its own query string reaches upstream as the base query
// followed by the endpoint's query, on both paths.
func TestUpstreamBaseQueryMergesWithEndpointQuery(t *testing.T) {
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			up, handler := advertisementUpstream()
			upstreamSrv := httptest.NewServer(handler)
			defer upstreamSrv.Close()

			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL + "/prefix?org=acme"}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), path.options(t)...)
			srv := httptest.NewServer(p)
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL+refsPath, nil)
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

			_, gotPath, gotQuery, _, _ := up.snapshot()
			if gotPath != "/prefix/acme/widgets.git/info/refs" {
				t.Errorf("upstream path = %q, want /prefix/acme/widgets.git/info/refs", gotPath)
			}
			if gotQuery != "org=acme&service=git-upload-pack" {
				t.Errorf("upstream query = %q, want %q", gotQuery, "org=acme&service=git-upload-pack")
			}
		})
	}
}

// rejectionResponse is the full client-visible form of a rejection.
type rejectionResponse struct {
	status int
	header http.Header
	body   string
}

func fetchRejection(t *testing.T, srv *httptest.Server, path string) rejectionResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Git-Protocol", "version=2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	header := resp.Header.Clone()
	header.Del("Date")
	return rejectionResponse{status: resp.StatusCode, header: header, body: string(body)}
}

// TestRejectionResponsesAreIdenticalWithAWarmCache confirms a policy
// denial, an unknown host and a malformed path answer the same status,
// headers and body whether or not a cache holds a warm entry for the very
// URL being requested.
func TestRejectionResponsesAreIdenticalWithAWarmCache(t *testing.T) {
	_, handler := advertisementUpstream()
	upstreamSrv := httptest.NewServer(handler)
	defer upstreamSrv.Close()
	upstreams := newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL})

	warm := newProxyCache(t, true)
	warmSrv := httptest.NewServer(mustNew(t, upstreams, allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), WithCache(warm)))
	defer warmSrv.Close()
	fetchRejection(t, warmSrv, refsPath)
	if second := fetchRejection(t, warmSrv, refsPath); second.header.Get("Cache-Status") != "haybale; hit" {
		t.Fatalf("Cache-Status = %q, want the entry warm before the comparison", second.header.Get("Cache-Status"))
	}

	cases := []struct {
		name string
		pol  policy.Engine
		path string
	}{
		{"policy denied", denyAllPolicy{}, refsPath},
		{"unknown host", allowAllPolicy{}, "/other.example/acme/widgets.git/info/refs?service=git-upload-pack"},
		{"malformed path", allowAllPolicy{}, "/testhost/acme/widgets.git/objects/ab/cdef"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			withCache := httptest.NewServer(mustNew(t, upstreams, allowAllAuthenticator{}, tt.pol, discardLogger(), WithCache(warm)))
			defer withCache.Close()
			without := httptest.NewServer(mustNew(t, upstreams, allowAllAuthenticator{}, tt.pol, discardLogger()))
			defer without.Close()

			got, want := fetchRejection(t, withCache, tt.path), fetchRejection(t, without, tt.path)
			if got.status != http.StatusNotFound {
				t.Errorf("status = %d, want 404", got.status)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("with a warm cache %+v, without a cache %+v, want identical", got, want)
			}
		})
	}
}

// TestConcurrentRequestsLeaveNoGoroutines confirms that after a burst of
// concurrent reads and writes through the proxy completes and its servers
// close, the goroutine count returns to what it was before the burst.
func TestConcurrentRequestsLeaveNoGoroutines(t *testing.T) {
	fetch := pkt(t,
		"command=fetch\n", pktline.Delim,
		"want 1f1e5c8e3a0b9d2c4e6f8a0b1c2d3e4f5a6b7c8d\n", "have 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b\n", "done\n", pktline.Flush)
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			options := path.options(t)
			baseline := runtime.NumGoroutine()

			func() {
				_, handler := advertisementUpstream()
				upstreamSrv := httptest.NewServer(handler)
				defer upstreamSrv.Close()
				p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), options...)
				srv := httptest.NewServer(p)
				defer srv.Close()

				client := &http.Client{Transport: &http.Transport{}}
				defer client.CloseIdleConnections()
				var wg sync.WaitGroup
				for i := range 24 {
					wg.Go(func() {
						var req *http.Request
						var err error
						switch i % 3 {
						case 0:
							req, err = http.NewRequest(http.MethodGet, srv.URL+refsPath, nil)
						case 1:
							req, err = http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-upload-pack", strings.NewReader(fetch))
						default:
							req, err = http.NewRequest(http.MethodPost, srv.URL+"/testhost/acme/widgets.git/git-receive-pack", strings.NewReader("0000"))
						}
						if err != nil {
							t.Error(err)
							return
						}
						req.Header.Set("Git-Protocol", "version=2")
						resp, err := client.Do(req)
						if err != nil {
							t.Error(err)
							return
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					})
				}
				wg.Wait()
			}()

			deadline := time.Now().Add(5 * time.Second)
			for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if got := runtime.NumGoroutine(); got > baseline {
				var dump bytes.Buffer
				_ = pprof.Lookup("goroutine").WriteTo(&dump, 1)
				t.Errorf("%d goroutines after the burst, %d before:\n%s", got, baseline, dump.String())
			}
		})
	}
}

// fixedOutcomeCache is a ResponseCache that answers every read itself,
// writing body when set, and reports outcome whatever it wrote.
type fixedOutcomeCache struct {
	outcome cache.Outcome
	body    string
}

func (c fixedOutcomeCache) Serve(w http.ResponseWriter, _ *http.Request, _ gitproto.Repo, _ *url.URL, _ cache.Fetcher) (cache.Outcome, bool) {
	if c.body != "" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, c.body)
	}
	return c.outcome, true
}

func (fixedOutcomeCache) Invalidate(context.Context, gitproto.Repo, *url.URL) {}

// serveThroughCache runs one read through a proxy whose cache is c and
// returns the request log and the proxied-request count.
func serveThroughCache(t *testing.T, c ResponseCache) (logs string, proxied int64) {
	t.Helper()
	buf := &syncBuffer{}
	metrics, reader := observability.NewTestMetrics()
	upstreams := newUpstreamMap(t, map[string]string{"testhost": "http://127.0.0.1:1"})
	p, err := New(upstreams, credentialsForHosts(upstreams), allowAllAuthenticator{}, allowAllPolicy{}, slog.New(slog.NewJSONHandler(buf, nil)), metrics, WithCache(c))
	if err != nil {
		t.Fatal(err)
	}
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, refsPath, nil))
	return buf.String(), outcomeCounts(t, reader)["proxied"]
}

// TestCacheHandledRequestWithoutStatusRecordsNoStatus confirms a request
// the cache handled but wrote no header for, because the client left
// first, is not recorded as a proxied 200.
func TestCacheHandledRequestWithoutStatusRecordsNoStatus(t *testing.T) {
	logs, proxied := serveThroughCache(t, fixedOutcomeCache{outcome: cache.Outcome{Result: observability.ResultMiss}})

	if proxied != 0 {
		t.Errorf("proxied requests recorded = %d, want 0", proxied)
	}
	if !strings.Contains(logs, `"msg":"proxied request"`) {
		t.Fatalf("logs = %q, want the request log line", logs)
	}
	if strings.Contains(logs, `"status"`) {
		t.Errorf("logs = %q, want no status field", logs)
	}
}

// TestCacheHandledRequestLogsTheCacheOutcome confirms the request log
// carries the status and byte count the cache reports for what it wrote.
func TestCacheHandledRequestLogsTheCacheOutcome(t *testing.T) {
	logs, proxied := serveThroughCache(t, fixedOutcomeCache{
		outcome: cache.Outcome{Result: observability.ResultHit, Status: http.StatusPartialContent, BytesOut: 3},
		body:    "cached",
	})

	if proxied != 1 {
		t.Errorf("proxied requests recorded = %d, want 1", proxied)
	}
	for _, want := range []string{`"status":206`, `"bytesOut":3`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs = %q, want it to contain %q", logs, want)
		}
	}
}
