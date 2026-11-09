package cache

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// testStaleFor is the stale-if-error age the stale tests configure.
const testStaleFor = time.Hour

// handshakeTimeoutError stands in for net/http's unexported TLS handshake
// timeout error.
type handshakeTimeoutError struct{}

func (handshakeTimeoutError) Error() string { return tlsHandshakeTimeoutText }
func (handshakeTimeoutError) Timeout() bool { return true }

// plainTimeoutError is a timeout that is not a TLS handshake timeout.
type plainTimeoutError struct{}

func (plainTimeoutError) Error() string { return "something timed out" }
func (plainTimeoutError) Timeout() bool { return true }

func TestClassifyFetchError(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	cases := []struct {
		name           string
		err            error
		headerTimedOut bool
		want           upstreamResult
	}{
		{"credential API unavailable", fmt.Errorf("proxy: credential source: %w", fmt.Errorf("%w: unexpected status 503", upstream.ErrUnavailable)), false, upstreamResult{eligible: true, reason: staleReasonCredentialUnavailable}},
		{"dial refused", refused, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"dial timeout", &net.OpError{Op: "dial", Net: "tcp", Err: plainTimeoutError{}}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"name resolution in a dial", &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "upstream.test", IsNotFound: true}}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"name resolution", &net.DNSError{Err: "server misbehaving", Name: "upstream.test"}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"TLS record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"TLS certificate verification", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"x509 unknown authority", x509.UnknownAuthorityError{}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"x509 hostname", x509.HostnameError{Host: "upstream.test"}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"x509 invalid", x509.CertificateInvalidError{Reason: x509.Expired}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"TLS alert from the server", &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"TLS alert sent", &net.OpError{Op: "local error", Err: errors.New("tls: bad certificate")}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"TLS handshake timeout", handshakeTimeoutError{}, false, upstreamResult{eligible: true, reason: staleReasonConnect}},
		{"response header timeout", context.Canceled, true, upstreamResult{eligible: true, reason: staleReasonHeaderTimeout}},
		{"header timeout wins over a dial error", refused, true, upstreamResult{eligible: true, reason: staleReasonHeaderTimeout}},
		{"reset after connecting", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}, false, upstreamResult{}},
		{"write after connecting", &net.OpError{Op: "write", Net: "tcp", Err: errors.New("broken pipe")}, false, upstreamResult{}},
		{"EOF", io.EOF, false, upstreamResult{}},
		{"unexpected EOF", io.ErrUnexpectedEOF, false, upstreamResult{}},
		{"other timeout", plainTimeoutError{}, false, upstreamResult{}},
		{"cancelled", context.Canceled, false, upstreamResult{}},
		{"opaque credential error", errors.New("proxy: credential source: unexpected status 403"), false, upstreamResult{}},
		{"rate-limited mint", errors.New("proxy: credential source: unexpected status 429"), false, upstreamResult{}},
		{"no credential source", errors.New("proxy: no credential source configured for this upstream"), false, upstreamResult{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFetchError(tc.err, tc.headerTimedOut); got != tc.want {
				t.Errorf("classifyFetchError(%v, %v) = %+v, want %+v", tc.err, tc.headerTimedOut, got, tc.want)
			}
		})
	}
}

// TestClassifyFetchErrorOnRealTransportFailures checks the classification
// against the errors net/http itself returns for connection failures.
func TestClassifyFetchErrorOnRealTransportFailures(t *testing.T) {
	roundTrip := func(t *testing.T, tr *http.Transport, url string) error {
		t.Helper()
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := tr.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("round trip succeeded, want a connection failure")
		}
		return err
	}
	closedAddr := func(t *testing.T) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}
	silentAddr := func(t *testing.T) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var conns []net.Conn
		var mu sync.Mutex
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
		}()
		t.Cleanup(func() {
			_ = ln.Close()
			mu.Lock()
			defer mu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
		})
		return ln.Addr().String()
	}
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	defer untrusted.Close()

	cases := []struct {
		name string
		err  func(t *testing.T) error
	}{
		{"connection refused", func(t *testing.T) error {
			return roundTrip(t, &http.Transport{}, "http://"+closedAddr(t)+"/")
		}},
		{"TLS to a plain HTTP server", func(t *testing.T) error {
			return roundTrip(t, &http.Transport{}, strings.Replace(plain.URL, "http://", "https://", 1)+"/")
		}},
		{"untrusted certificate", func(t *testing.T) error {
			return roundTrip(t, &http.Transport{}, untrusted.URL+"/")
		}},
		{"TLS handshake timeout", func(t *testing.T) error {
			return roundTrip(t, &http.Transport{TLSHandshakeTimeout: 50 * time.Millisecond}, "https://"+silentAddr(t)+"/")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err(t)
			if got := classifyFetchError(err, false); !got.eligible || got.reason != staleReasonConnect {
				t.Errorf("classifyFetchError(%v) = %+v, want an eligible connect failure", err, got)
			}
		})
	}
}

func TestClassifyStatus(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		if got := classifyStatus(status); !got.eligible || got.reason != staleReasonUpstreamStatus || got.status != status {
			t.Errorf("classifyStatus(%d) = %+v, want eligible with the status", status, got)
		}
	}
	for _, status := range []int{200, 204, 301, 400, 401, 403, 404, 410, 422, 429, 501, 505} {
		if got := classifyStatus(status); got.eligible {
			t.Errorf("classifyStatus(%d) = %+v, want not eligible", status, got)
		}
	}
}

func TestUpstreamStatusHonoursTheSanitisedStatusAndStripsIt(t *testing.T) {
	resp := response(http.StatusBadGateway, "text/plain; charset=utf-8", []byte("Bad Gateway\n"))
	resp.Header.Set(UpstreamStatusHeader, "401")
	if got := upstreamStatus(resp); got != http.StatusUnauthorized {
		t.Errorf("upstreamStatus = %d, want the 401 upstream sent", got)
	}
	if v := resp.Header.Get(UpstreamStatusHeader); v != "" {
		t.Errorf("%s = %q after classification, want it removed", UpstreamStatusHeader, v)
	}
	plain := response(http.StatusServiceUnavailable, "text/plain", nil)
	if got := upstreamStatus(plain); got != http.StatusServiceUnavailable {
		t.Errorf("upstreamStatus without the header = %d, want the response status", got)
	}
	malformed := response(http.StatusBadGateway, "text/plain", nil)
	malformed.Header.Set(UpstreamStatusHeader, "four-oh-one")
	if got := upstreamStatus(malformed); got != http.StatusBadGateway {
		t.Errorf("upstreamStatus with a malformed header = %d, want the response status", got)
	}
}

// staleHarness is a cache with stale-if-error enabled, metrics and a log
// capture, whose clone fetch entry is already stored.
type staleHarness struct {
	c      *Cache
	clock  *fakeClock
	logs   *logCapture
	reader *sdkmetric.ManualReader
	pack   []byte
	refs   []byte
}

func newStaleHarness(t *testing.T, mutate func(*Options)) *staleHarness {
	t.Helper()
	logger, logs := newLogCapture()
	metrics, reader := observability.NewTestMetrics()
	c, clock := newTestCache(t, func(o *Options) {
		o.StaleIfErrorFor = testStaleFor
		o.ExposeStatus = true
		o.Logger = logger
		o.Metrics = metrics
		if mutate != nil {
			mutate(o)
		}
	})
	h := &staleHarness{c: c, clock: clock, logs: logs, reader: reader, pack: fetchResultBody(t, 3, 100), refs: lsRefsResultBody(t)}
	lsRefs(t, c, &fixedFetcher{status: 200, contentType: contentTypeResult, body: h.refs})
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(h.pack)); !out.Stored {
		t.Fatalf("seeding fetch = %+v, want a stored miss", out)
	}
	return h
}

// failing answers every fetch with err, or with a response of status
// when err is nil, and counts the fetches.
type failing struct {
	status int
	header http.Header
	err    error
	calls  int
	mu     sync.Mutex
}

func (f *failing) Fetch(context.Context, Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	resp := response(f.status, "text/plain", []byte(http.StatusText(f.status)+"\n"))
	for k, vs := range f.header {
		resp.Header[k] = vs
	}
	return resp, nil
}

func (f *failing) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

var errDialRefused = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}

// TestStaleServiceByFailure runs a clone fetch whose upstream request
// fails after the access-recheck window has passed, so only stale
// service can answer it from the cache.
func TestStaleServiceByFailure(t *testing.T) {
	cases := []struct {
		name        string
		fetch       *failing
		headerDelay bool
		wantStale   bool
		wantStatus  string
		wantReason  string
		wantCode    int
	}{
		{name: "503", fetch: &failing{status: 503}, wantStale: true, wantStatus: "haybale; hit; fwd=stale; fwd-status=503", wantReason: staleReasonUpstreamStatus},
		{name: "500", fetch: &failing{status: 500}, wantStale: true, wantStatus: "haybale; hit; fwd=stale; fwd-status=500", wantReason: staleReasonUpstreamStatus},
		{name: "502", fetch: &failing{status: 502}, wantStale: true, wantStatus: "haybale; hit; fwd=stale; fwd-status=502", wantReason: staleReasonUpstreamStatus},
		{name: "504", fetch: &failing{status: 504}, wantStale: true, wantStatus: "haybale; hit; fwd=stale; fwd-status=504", wantReason: staleReasonUpstreamStatus},
		{name: "connection refused", fetch: &failing{err: errDialRefused}, wantStale: true, wantStatus: "haybale; hit; fwd=stale", wantReason: staleReasonConnect},
		{name: "credential API unavailable", fetch: &failing{err: fmt.Errorf("proxy: credential source: %w", upstream.ErrUnavailable)}, wantStale: true, wantStatus: "haybale; hit; fwd=stale", wantReason: staleReasonCredentialUnavailable},
		{name: "response header timeout", headerDelay: true, wantStale: true, wantStatus: "haybale; hit; fwd=stale", wantReason: staleReasonHeaderTimeout},
		{name: "rejected credential", fetch: &failing{status: 502, header: http.Header{UpstreamStatusHeader: {"401"}}}, wantCode: 502},
		{name: "forbidden credential", fetch: &failing{status: 502, header: http.Header{UpstreamStatusHeader: {"403"}}}, wantCode: 502},
		{name: "404", fetch: &failing{status: 404}, wantCode: 404},
		{name: "429", fetch: &failing{status: 429}, wantCode: 429},
		{name: "422", fetch: &failing{status: 422}, wantCode: 422},
		{name: "opaque error", fetch: &failing{err: errors.New("proxy: credential source: unexpected status 403")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStaleHarness(t, func(o *Options) { o.ResponseHeaderTimeout = 20 * time.Millisecond })
			h.clock.Advance(10 * time.Minute) // past accessRecheck
			var fetch Fetcher = tc.fetch
			if tc.headerDelay {
				fetch = fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				})
			}
			rec := newCollectWriter()
			out, handled, aborted := serve(h.c, rec, fetchRequest(t), fetch)
			status, body, _ := rec.result()
			events := h.logs.securityEvents(t, security.EventCacheStaleServed)
			switch {
			case tc.wantStale:
				if !handled || aborted || out.Result != observability.ResultStale || status != 200 || !bytes.Equal(body, h.pack) {
					t.Fatalf("got %+v handled %v aborted %v status %d, want the stored pack served stale", out, handled, aborted, status)
				}
				if got := rec.Header().Get("Cache-Status"); got != tc.wantStatus {
					t.Errorf("Cache-Status = %q, want %q", got, tc.wantStatus)
				}
				if len(events) != 1 {
					t.Fatalf("cache_stale_served events = %d, want 1", len(events))
				}
				ev := events[0]
				want := map[string]any{
					"identity": testIdentity, "host": testRepo.Host, "owner": testRepo.Owner, "repo": testRepo.Name,
					"class": string(classFetch), "tier": observability.TierDisk, "reason": tc.wantReason, "entryAgeSeconds": float64(600),
				}
				for k, v := range want {
					if ev[k] != v {
						t.Errorf("event %s = %v, want %v", k, ev[k], v)
					}
				}
				if ev["level"] != "WARN" {
					t.Errorf("event level = %v, want WARN", ev["level"])
				}
				if got := lookups(t, h.reader, observability.ResultStale); got != 1 {
					t.Errorf("lookups{result=stale} = %d, want 1", got)
				}
				if got := tierSum(t, h.reader, "served_bytes.total", observability.TierDisk); got < int64(len(h.pack)) {
					t.Errorf("served_bytes{tier=disk} = %d, want the stale bytes counted", got)
				}
			case tc.wantCode != 0:
				if !handled || out.Result != observability.ResultMiss || status != tc.wantCode {
					t.Fatalf("got %+v handled %v status %d, want the shared %d", out, handled, status, tc.wantCode)
				}
				if v := rec.Header().Get(UpstreamStatusHeader); v != "" {
					t.Errorf("relayed %s = %q, want it stripped", UpstreamStatusHeader, v)
				}
				if len(events) != 0 {
					t.Errorf("cache_stale_served events = %d, want none", len(events))
				}
			default:
				if handled || out.Result != observability.ResultBypass {
					t.Fatalf("got %+v handled %v, want a release to passthrough", out, handled)
				}
				if len(events) != 0 {
					t.Errorf("cache_stale_served events = %d, want none", len(events))
				}
			}
			assertStoreIdle(t, h.c)
		})
	}
}

// TestStaleServiceTakesPrecedenceOverTheSharedResponse: every subscriber
// of a fill whose upstream answered 503 is served the stale entry, not
// the 503.
func TestStaleServiceTakesPrecedenceOverTheSharedResponse(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(10 * time.Minute)
	gate := make(chan struct{})
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		<-gate
		return response(503, "text/plain", []byte("unavailable\n")), nil
	})
	const subscribers = 3
	recs := make([]*collectWriter, subscribers)
	outs := make([]Outcome, subscribers)
	var wg sync.WaitGroup
	for i := range subscribers {
		recs[i] = newCollectWriter()
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], _, _ = serve(h.c, recs[i], fetchRequest(t), fetch)
		}()
		waitForSubscribers(t, h.c, i+1)
	}
	close(gate)
	wg.Wait()
	for i := range subscribers {
		status, body, _ := recs[i].result()
		if outs[i].Result != observability.ResultStale || status != 200 || !bytes.Equal(body, h.pack) {
			t.Errorf("subscriber %d: %+v status %d, want the stale pack", i, outs[i], status)
		}
		if got := recs[i].Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale; fwd-status=503" {
			t.Errorf("subscriber %d Cache-Status = %q", i, got)
		}
	}
	if got := len(h.logs.securityEvents(t, security.EventCacheStaleServed)); got != subscribers {
		t.Errorf("cache_stale_served events = %d, want one per subscriber", got)
	}
	if got := lookups(t, h.reader, observability.ResultStale); got != subscribers {
		t.Errorf("lookups{result=stale} = %d, want %d", got, subscribers)
	}
	assertStoreIdle(t, h.c)
}

func TestStaleServiceIsBoundedByStaleIfErrorFor(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(testStaleFor + time.Second)
	rec := newCollectWriter()
	out, handled, _ := serve(h.c, rec, fetchRequest(t), &failing{status: 503})
	if status, _, _ := rec.result(); !handled || out.Result != observability.ResultMiss || status != 503 {
		t.Fatalf("got %+v status %d, want the shared 503 for an entry older than staleIfErrorFor", out, status)
	}
	if got := len(h.logs.securityEvents(t, security.EventCacheStaleServed)); got != 0 {
		t.Errorf("cache_stale_served events = %d, want none", got)
	}
}

func TestStaleServiceIsOffByDefault(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.StaleIfErrorFor = 0 })
	h.clock.Advance(10 * time.Minute)
	rec := newCollectWriter()
	if out, _, _ := serve(h.c, rec, fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss {
		t.Errorf("503 with stale disabled = %+v, want the shared response", out)
	}
	if out, handled, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled || out.Result != observability.ResultBypass {
		t.Errorf("refused with stale disabled = %+v handled %v, want a release", out, handled)
	}
}

// TestStaleServiceServesRefs: refs requests always go upstream with
// refsMaxAge zero, and their stored entries answer an outage.
func TestStaleServiceServesRefs(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(time.Minute)
	rec := newCollectWriter()
	out, handled, _ := serve(h.c, rec, postV2(lsRefsBody(t)), &failing{err: errDialRefused})
	status, body, _ := rec.result()
	if !handled || out.Result != observability.ResultStale || status != 200 || !bytes.Equal(body, h.refs) {
		t.Fatalf("ls-refs = %+v status %d, want the stored refs served stale", out, status)
	}
	if ev := h.logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 1 || ev[0]["class"] != string(classLsRefs) {
		t.Errorf("events = %v, want one for class ls-refs", ev)
	}
}

// TestStaleServiceDoesNotMarkTheKey: a stale-served failure leaves the key
// cacheable, so the next request during the outage is served stale too
// rather than bypassing the cache.
func TestStaleServiceDoesNotMarkTheKey(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(10 * time.Minute)
	fetch := &failing{status: 503}
	for i := range 3 {
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), fetch); out.Result != observability.ResultStale {
			t.Fatalf("request %d = %+v, want stale", i, out)
		}
	}
	if fetch.count() != 3 {
		t.Errorf("upstream fetches = %d, want every request to try upstream", fetch.count())
	}
}

// TestStaleServiceWithoutAnEntryBehavesAsBefore: a key never stored
// fails as it would without stale-if-error.
func TestStaleServiceWithoutAnEntryBehavesAsBefore(t *testing.T) {
	h := newStaleHarness(t, nil)
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
		t.Errorf("503 for an unseen key = %+v, want the shared 503", out)
	}
	if out, handled, _ := serve(h.c, newCollectWriter(), postV2(fetchBody(t, "want "+oidA+"\n", "done\n")), &failing{err: errDialRefused}); handled || out.Result != observability.ResultBypass {
		t.Errorf("refused for an unseen key = %+v handled %v, want a release", out, handled)
	}
}

// TestStaleServiceNeverServesWrites: a write offered to the cache is
// declined before any upstream request, so it can never be answered
// stale.
func TestStaleServiceNeverServesWrites(t *testing.T) {
	h := newStaleHarness(t, nil)
	fetch := &failing{err: errDialRefused}
	r := httptest.NewRequest(http.MethodPost, "/github.com/acme/widgets.git/git-receive-pack", bytes.NewReader([]byte("0000")))
	r.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	out, handled, _ := serve(h.c, newCollectWriter(), r, fetch)
	if handled || out.Result != observability.ResultBypass || fetch.count() != 0 {
		t.Errorf("receive-pack = %+v handled %v fetches %d, want a bypass that never fetches", out, handled, fetch.count())
	}
}

// TestStaleServiceFromTheRemoteTier: with no tier-1 entry, the remote
// tier's copy is spooled and served stale, and stored locally.
func TestStaleServiceFromTheRemoteTier(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	logger, logs := newLogCapture()
	c, clock, reader := newRemoteTestCache(t, store, func(o *Options) {
		o.StaleIfErrorFor = testStaleFor
		o.ExposeStatus = true
		o.Logger = logger
	})
	clock.Advance(2 * time.Minute)
	rec := newCollectWriter()
	out, handled, aborted := serve(c, rec, fetchRequest(t), &failing{status: 502})
	status, body, _ := rec.result()
	if !handled || aborted || out.Result != observability.ResultStale || status != 200 || !bytes.Equal(body, pack) {
		t.Fatalf("got %+v handled %v aborted %v status %d, want the remote copy served stale", out, handled, aborted, status)
	}
	if got := rec.Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale; fwd-status=502" {
		t.Errorf("Cache-Status = %q", got)
	}
	if got := tierSum(t, reader, "served_bytes.total", observability.TierRemote); got != int64(len(pack)) {
		t.Errorf("served_bytes{tier=remote} = %d, want %d", got, len(pack))
	}
	if got := lookups(t, reader, observability.ResultStale); got != 1 {
		t.Errorf("lookups{result=stale} = %d, want 1", got)
	}
	ev := logs.securityEvents(t, security.EventCacheStaleServed)
	if len(ev) != 1 || ev[0]["tier"] != observability.TierRemote || ev[0]["identity"] != testIdentity || ev[0]["entryAgeSeconds"] != float64(120) {
		t.Errorf("events = %v, want one remote-tier event for the identity", ev)
	}
	if got := len(entryFiles(t, c.opts.Dir)); got != 1 {
		t.Errorf("tier-1 entries = %d, want the remote copy stored locally", got)
	}
	assertStoreIdle(t, c)
}

// TestStaleServiceSkipsRemoteEntriesPastTheBound: a remote copy older
// than staleIfErrorFor is not served.
func TestStaleServiceSkipsRemoteEntriesPastTheBound(t *testing.T) {
	store := newMemBlobStore()
	seedPeer(t, store, remotePack(t))
	c, clock, _ := newRemoteTestCache(t, store, func(o *Options) { o.StaleIfErrorFor = testStaleFor })
	clock.Advance(testStaleFor + time.Minute)
	if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 502}); out.Result != observability.ResultMiss || out.Status != 502 {
		t.Errorf("got %+v, want the shared 502", out)
	}
}

func TestNewRejectsStaleIfErrorForBeyondRetention(t *testing.T) {
	opts := Options{
		Dir: cacheDir(t), Keyring: testKeyring(t), MaxDiskSize: 64 << 20, MaxEntrySize: 8 << 20,
		MaxConcurrentFills: 1, MaxRequestBody: 1 << 20, Retention: time.Hour,
	}
	opts.StaleIfErrorFor = 2 * time.Hour
	if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "must not exceed retention") {
		t.Errorf("New with staleIfErrorFor above retention = %v, want an error", err)
	}
	opts.StaleIfErrorFor = -time.Second
	if _, err := New(opts); err == nil {
		t.Error("New with a negative staleIfErrorFor succeeded")
	}
}
