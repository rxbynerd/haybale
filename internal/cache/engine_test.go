package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
)

var testBaseURL = &url.URL{Scheme: "https", Host: "upstream.test"}

// fetchFunc adapts a function to the Fetcher interface.
type fetchFunc func(ctx context.Context, req Request) (*http.Response, error)

func (f fetchFunc) Fetch(ctx context.Context, req Request) (*http.Response, error) {
	return f(ctx, req)
}

// newTestCache opens a Cache on a fresh directory with small limits and
// a fake clock, closing it when the test ends.
func newTestCache(t *testing.T, mutate func(*Options)) (*Cache, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	opts := Options{
		Dir:                cacheDir(t),
		Keyring:            testKeyring(t),
		MaxDiskSize:        64 << 20,
		MaxEntrySize:       8 << 20,
		MaxConcurrentFills: 4,
		MaxRequestBody:     1 << 20,
		Retention:          24 * time.Hour,
		AccessRecheck:      5 * time.Minute,
		Now:                clock.Now,
	}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c, clock
}

// response builds an upstream response with a known Content-Length.
func response(status int, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// streamingResponse builds a 200 response of unknown length read from r.
func streamingResponse(contentType string, r io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          r,
		ContentLength: -1,
	}
}

// fixedFetcher answers every fetch with a copy of resp's body and counts
// the fetches.
type fixedFetcher struct {
	status      int
	contentType string
	body        []byte
	calls       atomic.Int32
}

func (f *fixedFetcher) Fetch(context.Context, Request) (*http.Response, error) {
	f.calls.Add(1)
	return response(f.status, f.contentType, f.body), nil
}

func fetchResultBody(t testing.TB, frames, frameSize int) []byte {
	t.Helper()
	parts := []any{"packfile\n"}
	for i := range frames {
		parts = append(parts, "\x01"+strings.Repeat(string(rune('a'+i%26)), frameSize))
	}
	return pkts(t, append(parts, pktline.Flush)...)
}

func advertisementBody(t testing.TB) []byte {
	t.Helper()
	return pkts(t, "version 2\n", "agent=git/2.54.0\n", "ls-refs=unborn\n", "fetch=shallow\n", pktline.Flush)
}

func lsRefsResultBody(t testing.TB) []byte {
	t.Helper()
	return pkts(t, oidA+" HEAD symref-target:refs/heads/main\n", oidA+" refs/heads/main\n", pktline.Flush)
}

// fetchRequest is a cacheable v2 fetch (a clone) for testRepo.
func fetchRequest(t testing.TB) *http.Request {
	t.Helper()
	return postV2(cloneFetchBody(t))
}

// collectWriter is a concurrency-safe ResponseWriter that signals its
// first body write, so a test can attach a follower mid-fill.
type collectWriter struct {
	mu        sync.Mutex
	header    http.Header
	status    int
	body      bytes.Buffer
	flushes   int
	firstOnce sync.Once
	first     chan struct{}
}

func newCollectWriter() *collectWriter {
	return &collectWriter{header: make(http.Header), first: make(chan struct{})}
}

func (w *collectWriter) Header() http.Header { return w.header }

func (w *collectWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
}

func (w *collectWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.firstOnce.Do(func() { close(w.first) })
	return w.body.Write(p)
}

func (w *collectWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushes++
}

func (w *collectWriter) result() (status int, body []byte, flushes int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status, bytes.Clone(w.body.Bytes()), w.flushes
}

// serve runs Serve against w and returns its results, recovering a
// panic(http.ErrAbortHandler) as aborted.
func serve(c *Cache, w http.ResponseWriter, r *http.Request, fetch Fetcher) (out Outcome, handled, aborted bool) {
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				panic(v)
			}
			aborted = true
		}
	}()
	out, handled = c.Serve(w, r, testRepo, testBaseURL, fetch)
	return out, handled, false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func entryFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestNewRejectsBadOptions(t *testing.T) {
	kr := testKeyring(t)
	valid := Options{Dir: cacheDir(t), Keyring: kr, MaxDiskSize: 1 << 20, MaxEntrySize: 1 << 10, MaxConcurrentFills: 1, MaxRequestBody: 1 << 10, Retention: time.Hour}
	cases := map[string]func(*Options){
		"no dir":          func(o *Options) { o.Dir = "" },
		"no key":          func(o *Options) { o.Keyring = Keyring{} },
		"entry over disk": func(o *Options) { o.MaxEntrySize = o.MaxDiskSize + 1 },
		"zero fills":      func(o *Options) { o.MaxConcurrentFills = 0 },
		"zero retention":  func(o *Options) { o.Retention = 0 },
		"negative age":    func(o *Options) { o.RefsMaxAge = -1 },
		"remote tier":     func(o *Options) { o.Remote = fakeBlobStore{} },
	}
	for name, mutate := range cases {
		opts := valid
		mutate(&opts)
		if c, err := New(opts); err == nil {
			_ = c.Close(context.Background())
			t.Errorf("%s: New accepted the options", name)
		}
	}
}

// fakeBlobStore is a non-nil BlobStore for the rejection test only.
type fakeBlobStore struct{ BlobStore }

func TestServeBypassesUncacheableRequests(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.ExposeStatus = true })
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}

	body := fetchBody(t, "want "+oidA+"\n", "have "+oidB+"\n", "done\n")
	r := postV2(body)
	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, r, fetch)
	if handled || out.Result != observability.ResultBypass {
		t.Fatalf("Serve = %+v, handled %v; want a bypass", out, handled)
	}
	if fetch.calls.Load() != 0 {
		t.Error("a bypassed request reached the fetcher")
	}
	if got := rec.Header().Get("Cache-Status"); got != "haybale; fwd=bypass" {
		t.Errorf("Cache-Status = %q, want the bypass form set for the passthrough path", got)
	}
	replayed, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(replayed, body) {
		t.Errorf("body after bypass = %q (err %v), want the original body restored", replayed, err)
	}
}

func TestLeaderAndFollowerStreamTheSameBytesAndLaterRequestsHit(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.ExposeStatus = true; o.AccessRecheck = 0 })
	want := fetchResultBody(t, 40, 5000)
	pr, pw := io.Pipe()
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		return streamingResponse(contentTypeResult, pr), nil
	})

	leader := newCollectWriter()
	var leaderOut Outcome
	var leaderHandled bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		leaderOut, leaderHandled, _ = serve(c, leader, fetchRequest(t), fetch)
	}()

	// First part of the body, then wait until the leader has received it
	// so the follower attaches to a fill that is in flight.
	if _, err := pw.Write(want[:70000]); err != nil {
		t.Fatal(err)
	}
	<-leader.first

	follower := newCollectWriter()
	var followerOut Outcome
	wg.Add(1)
	go func() {
		defer wg.Done()
		followerOut, _, _ = serve(c, follower, fetchRequest(t), fetch)
	}()
	waitFor(t, "the follower to attach", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, f := range c.fills {
			if f.subscribers == 2 {
				return true
			}
		}
		return false
	})
	if _, err := pw.Write(want[70000:]); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if !leaderHandled || leaderOut.Result != observability.ResultMiss || leaderOut.Collapsed || !leaderOut.Stored {
		t.Errorf("leader outcome = %+v, want a stored, uncollapsed miss", leaderOut)
	}
	if followerOut.Result != observability.ResultMiss || !followerOut.Collapsed || !followerOut.Stored {
		t.Errorf("follower outcome = %+v, want a stored, collapsed miss", followerOut)
	}
	for name, w := range map[string]*collectWriter{"leader": leader, "follower": follower} {
		status, body, flushes := w.result()
		if status != http.StatusOK || !bytes.Equal(body, want) {
			t.Errorf("%s: status %d, %d bytes; want 200 and %d identical bytes", name, status, len(body), len(want))
		}
		if flushes == 0 {
			t.Errorf("%s: response was never flushed", name)
		}
		if got := w.Header().Get("Content-Type"); got != contentTypeResult {
			t.Errorf("%s: Content-Type = %q", name, got)
		}
		if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-cache") {
			t.Errorf("%s: Cache-Control = %q", name, got)
		}
	}
	if got := leader.Header().Get("Cache-Status"); got != "haybale; fwd=miss" {
		t.Errorf("leader Cache-Status = %q", got)
	}
	if got := follower.Header().Get("Cache-Status"); got != "haybale; fwd=miss; collapsed" {
		t.Errorf("follower Cache-Status = %q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream fetched %d times, want 1", calls.Load())
	}

	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, fetchRequest(t), fetch)
	if !handled || out.Result != observability.ResultHit || out.BytesOut != int64(len(want)) {
		t.Fatalf("third request outcome = %+v handled %v, want a hit of %d bytes", out, handled, len(want))
	}
	if !bytes.Equal(rec.Body.Bytes(), want) || rec.Header().Get("Cache-Status") != "haybale; hit" {
		t.Errorf("hit body matches = %v, Cache-Status = %q", bytes.Equal(rec.Body.Bytes(), want), rec.Header().Get("Cache-Status"))
	}
	if calls.Load() != 1 {
		t.Errorf("a hit fetched upstream (calls = %d)", calls.Load())
	}
}

func TestPackHitRequiresRecentRefsSuccess(t *testing.T) {
	c, clock := newTestCache(t, nil)
	packs := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 2, 100)}
	refs := &fixedFetcher{status: 200, contentType: contentTypeResult, body: lsRefsResultBody(t)}

	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packs); out.Result != observability.ResultMiss {
		t.Fatalf("first fetch = %+v, want a miss", out)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packs); out.Result != observability.ResultMiss {
		t.Fatalf("fetch without a refs success = %+v, want a miss", out)
	}
	if out, handled, _ := serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), refs); !handled || out.Result != observability.ResultMiss {
		t.Fatalf("ls-refs = %+v handled %v, want a handled miss", out, handled)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packs); out.Result != observability.ResultHit {
		t.Fatalf("fetch after a refs success = %+v, want a hit", out)
	}
	clock.Advance(6 * time.Minute)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packs); out.Result != observability.ResultMiss {
		t.Fatalf("fetch after the recheck window = %+v, want a miss", out)
	}
	if packs.calls.Load() != 3 {
		t.Errorf("pack fetched %d times, want 3", packs.calls.Load())
	}
}

func TestRefsAreNotCoalescedWhenRefsMaxAgeIsZero(t *testing.T) {
	c, _ := newTestCache(t, nil)
	gate := make(chan struct{})
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		<-gate
		return response(http.StatusOK, contentTypeAdvertisement, advertisementBody(t)), nil
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, handled, _ := serve(c, httptest.NewRecorder(), get("Git-Protocol", "version=2"), fetch)
			if !handled || out.Result != observability.ResultMiss || out.Collapsed {
				t.Errorf("advertisement = %+v handled %v, want an uncollapsed miss", out, handled)
			}
		}()
	}
	waitFor(t, "both fetches to start", func() bool { return calls.Load() == 2 })
	close(gate)
	wg.Wait()
	if out, _, _ := serve(c, httptest.NewRecorder(), get("Git-Protocol", "version=2"), fetch); out.Result != observability.ResultMiss {
		t.Errorf("advertisement with refsMaxAge 0 = %+v, want a miss", out)
	}
}

func TestRefsHitWithinRefsMaxAge(t *testing.T) {
	c, clock := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
	fetch := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)}
	if out, _, _ := serve(c, httptest.NewRecorder(), get(), fetch); out.Result != observability.ResultMiss || !out.Stored {
		t.Fatalf("first = %+v, want a stored miss", out)
	}
	rec := httptest.NewRecorder()
	if out, _, _ := serve(c, rec, get(), fetch); out.Result != observability.ResultHit {
		t.Fatalf("second = %+v, want a hit", out)
	}
	if !bytes.Equal(rec.Body.Bytes(), advertisementBody(t)) || rec.Header().Get("Content-Type") != contentTypeAdvertisement {
		t.Errorf("hit body/type = %q/%q", rec.Body.Bytes(), rec.Header().Get("Content-Type"))
	}
	clock.Advance(2 * time.Minute)
	if out, _, _ := serve(c, httptest.NewRecorder(), get(), fetch); out.Result != observability.ResultMiss {
		t.Fatalf("after refsMaxAge = %+v, want a miss", out)
	}
	if fetch.calls.Load() != 2 {
		t.Errorf("fetched %d times, want 2", fetch.calls.Load())
	}
}

func TestExpiredEntryIsDeletedAndMissed(t *testing.T) {
	c, clock := newTestCache(t, func(o *Options) { o.AccessRecheck = 0; o.Retention = time.Hour })
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
	clock.Advance(2 * time.Hour)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultMiss {
		t.Fatalf("after retention = %+v, want a miss", out)
	}
	if fetch.calls.Load() != 2 {
		t.Errorf("fetched %d times, want 2", fetch.calls.Load())
	}
}

func TestNon200ResponseIsSharedByEverySubscriber(t *testing.T) {
	c, _ := newTestCache(t, nil)
	gate := make(chan struct{})
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		<-gate
		resp := response(http.StatusNotFound, "text/plain", []byte("no such repository\n"))
		resp.Header.Set("X-Upstream", "kept")
		resp.Header.Set("Connection", "close")
		return resp, nil
	})
	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, 3)
	outs := make([]Outcome, 3)
	for i := range recs {
		recs[i] = httptest.NewRecorder()
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], _, _ = serve(c, recs[i], fetchRequest(t), fetch)
		}()
	}
	waitFor(t, "three subscribers", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, f := range c.fills {
			return f.subscribers == 3
		}
		return false
	})
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream called %d times, want 1", calls.Load())
	}
	for i, rec := range recs {
		if rec.Code != http.StatusNotFound || rec.Body.String() != "no such repository\n" {
			t.Errorf("subscriber %d: %d %q", i, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Upstream") != "kept" || rec.Header().Get("Connection") != "" {
			t.Errorf("subscriber %d: headers = %v, want upstream headers without hop-by-hop ones", i, rec.Header())
		}
		if outs[i].Result != observability.ResultMiss || outs[i].Status != http.StatusNotFound || outs[i].Stored {
			t.Errorf("subscriber %d outcome = %+v", i, outs[i])
		}
	}
	if len(entryFiles(t, c.opts.Dir)) != 0 {
		t.Error("a non-200 response left files in the cache directory")
	}
	// The key is marked uncacheable for a cooldown, so the next request
	// passes through.
	if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); handled {
		t.Error("request after a shared non-200 was handled by the cache, want a bypass")
	}
}

func TestFetchErrorReleasesSubscribersToPassthrough(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.ExposeStatus = true })
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	})
	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, fetchRequest(t), fetch)
	if handled || out.Result != observability.ResultBypass {
		t.Fatalf("Serve = %+v handled %v, want a release to passthrough", out, handled)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Cache-Status") != "haybale; fwd=bypass" {
		t.Errorf("response was touched: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestOversizeResponseIsServedNotStoredAndMarksTheKey(t *testing.T) {
	c, clock := newTestCache(t, func(o *Options) { o.MaxEntrySize = 1 << 16; o.AccessRecheck = 0 })
	want := fetchResultBody(t, 30, 5000)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: want}
	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, fetchRequest(t), fetch)
	// A known Content-Length over the limit releases before spooling.
	if handled || out.Result != observability.ResultBypass {
		t.Fatalf("known oversize = %+v handled %v, want a bypass", out, handled)
	}

	// Unknown length: the response is spooled, served and discarded.
	c.marks = uncacheableMarks{}
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(want)
		_ = pw.Close()
	}()
	streaming := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return streamingResponse(contentTypeResult, pr), nil
	})
	rec = httptest.NewRecorder()
	out, handled, _ = serve(c, rec, fetchRequest(t), streaming)
	if !handled || out.Result != observability.ResultMiss || out.Stored || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("oversize stream = %+v handled %v, %d bytes; want a served, unstored miss", out, handled, rec.Body.Len())
	}
	if len(entryFiles(t, c.opts.Dir)) != 0 {
		t.Error("oversize response left files behind")
	}
	if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); handled {
		t.Error("key was not marked uncacheable after an oversize response")
	}
	clock.Advance(25 * time.Hour)
	if _, handled, _ := serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), &fixedFetcher{status: 200, contentType: contentTypeResult, body: lsRefsResultBody(t)}); !handled {
		t.Fatal("ls-refs was not handled")
	}
	fetch = &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !handled || out.Result != observability.ResultMiss {
		t.Errorf("after retention the mark should have expired: %+v handled %v", out, handled)
	}
}

func TestUpstreamErrorMidStreamAbortsSubscribers(t *testing.T) {
	c, _ := newTestCache(t, nil)
	pr, pw := io.Pipe()
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return streamingResponse(contentTypeResult, pr), nil
	})
	w := newCollectWriter()
	done := make(chan bool)
	go func() {
		_, _, aborted := serve(c, w, fetchRequest(t), fetch)
		done <- aborted
	}()
	body := fetchResultBody(t, 20, 5000)
	if _, err := pw.Write(body[:70000]); err != nil {
		t.Fatal(err)
	}
	<-w.first
	if err := pw.CloseWithError(errors.New("upstream reset")); err != nil {
		t.Fatal(err)
	}
	if aborted := <-done; !aborted {
		t.Fatal("subscriber did not abort with http.ErrAbortHandler after an upstream error")
	}
	waitFor(t, "the fill to end", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.fills) == 0
	})
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("aborted fill left files: %v", files)
	}
	if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); handled {
		t.Error("key was not marked uncacheable after a transport failure")
	}
}

func TestIdleTimeoutAbortsStalledFill(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.IdleTimeout = 100 * time.Millisecond })
	pr, pw := io.Pipe()
	var fetchCtx context.Context
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		fetchCtx = ctx
		return streamingResponse(contentTypeResult, pr), nil
	})
	w := newCollectWriter()
	done := make(chan bool)
	go func() {
		_, _, aborted := serve(c, w, fetchRequest(t), fetch)
		done <- aborted
	}()
	if _, err := pw.Write(fetchResultBody(t, 20, 5000)[:70000]); err != nil {
		t.Fatal(err)
	}
	<-w.first
	// Behave like a transport whose body read is cancelled with the
	// context: stall until the fill's context ends, then fail the read.
	go func() {
		<-fetchCtx.Done()
		_ = pw.CloseWithError(fetchCtx.Err())
	}()
	if aborted := <-done; !aborted {
		t.Fatal("subscriber was not aborted after the idle timeout")
	}
}

func TestResponseHeaderTimeoutReleasesSubscribers(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.ResponseHeaderTimeout = 50 * time.Millisecond })
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	start := time.Now()
	_, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
	if handled {
		t.Fatal("request was handled although upstream never answered")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("header timeout did not cancel the fetch promptly")
	}
}

func TestFillWithNoSubscribersIsCancelled(t *testing.T) {
	c, _ := newTestCache(t, nil)
	c.idleGrace = 50 * time.Millisecond
	fetchStarted := make(chan context.Context, 1)
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		fetchStarted <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	r := fetchRequest(t).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(c, httptest.NewRecorder(), r, fetch)
	}()
	fetchCtx := <-fetchStarted
	cancel()
	<-done
	select {
	case <-fetchCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("fill kept running after its only subscriber left")
	}
	waitFor(t, "the fill to end", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.fills) == 0
	})
	// Abandonment marks nothing: the next request starts a new fill.
	fetch2 := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch2); !handled {
		t.Error("request after an abandoned fill was not handled")
	}
}

func TestErrPacketAndTruncationAreServedButNotStored(t *testing.T) {
	cases := map[string]struct {
		body   []byte
		length int64
	}{
		"ERR packet":            {pkts(t, "ERR upload-pack: not our ref "+oidA+"\n"), -1},
		"sideband error":        {pkts(t, "packfile\n", "\x01PACK", "\x03fatal: oops\n", pktline.Flush), -1},
		"missing flush":         {pkts(t, "packfile\n", "\x01PACK"), -1},
		"content-length larger": {pkts(t, "packfile\n", "\x01PACK", pktline.Flush), 500},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
			var calls atomic.Int32
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
				calls.Add(1)
				resp := streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(tc.body)))
				resp.ContentLength = tc.length
				return resp, nil
			})
			rec := httptest.NewRecorder()
			out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
			if aborted || !handled || out.Result != observability.ResultMiss || out.Stored {
				t.Fatalf("Serve = %+v handled %v aborted %v, want a served, unstored miss", out, handled, aborted)
			}
			if !bytes.Equal(rec.Body.Bytes(), tc.body) {
				t.Errorf("client received %q, want upstream's own bytes %q", rec.Body.Bytes(), tc.body)
			}
			if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
				t.Errorf("unstorable response left files: %v", files)
			}
			if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); handled {
				t.Error("next request did not pass through during the cooldown")
			}
		})
	}
}

func TestPushDuringRefsFillDiscardsIt(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
	pr, pw := io.Pipe()
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return streamingResponse(contentTypeAdvertisement, pr), nil
	})
	w := newCollectWriter()
	outCh := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(c, w, get(), fetch)
		outCh <- out
	}()
	body := advertisementBody(t)
	if _, err := pw.Write(body[:10]); err != nil {
		t.Fatal(err)
	}
	<-w.first
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	if _, err := pw.Write(body[10:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	out := <-outCh
	if out.Result != observability.ResultMiss || out.Stored {
		t.Fatalf("outcome = %+v, want an unstored miss", out)
	}
	if _, body, _ := w.result(); !bytes.Equal(body, advertisementBody(t)) {
		t.Error("subscriber did not receive the full advertisement")
	}
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("discarded refs fill left files: %v", files)
	}
	// A generation mismatch marks nothing.
	fixed := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)}
	if out, handled, _ := serve(c, httptest.NewRecorder(), get(), fixed); !handled || !out.Stored {
		t.Errorf("next advertisement = %+v handled %v, want a stored miss", out, handled)
	}
}

func TestInvalidateDeletesRefsEntriesOnly(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
	refs := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)}
	packs := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	serve(c, httptest.NewRecorder(), get(), refs)
	serve(c, httptest.NewRecorder(), fetchRequest(t), packs)
	if files := entryFiles(t, c.opts.Dir); len(files) != 2 {
		t.Fatalf("entries = %v, want one refs and one pack entry", files)
	}
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	files := entryFiles(t, c.opts.Dir)
	if len(files) != 1 || !strings.HasPrefix(files[0], "v1/pack/") {
		t.Fatalf("entries after Invalidate = %v, want only the pack entry", files)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), get(), refs); out.Result != observability.ResultMiss {
		t.Errorf("advertisement after Invalidate = %+v, want a miss", out)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packs); out.Result != observability.ResultHit {
		t.Errorf("pack after Invalidate = %+v, want a hit", out)
	}
}

func TestPurgeCountsAndSelectsGroups(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
	serve(c, httptest.NewRecorder(), get(), &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)})
	serve(c, httptest.NewRecorder(), fetchRequest(t), &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)})
	ctx := context.Background()
	if _, err := c.Purge(ctx, testRepo, testBaseURL, Group("blobs")); err == nil {
		t.Error("Purge accepted an unknown group")
	}
	if n, err := c.Purge(ctx, testRepo, testBaseURL, GroupPack); err != nil || n != 1 {
		t.Errorf("Purge(pack) = %d, %v; want 1", n, err)
	}
	if n, err := c.Purge(ctx, testRepo, testBaseURL, ""); err != nil || n != 1 {
		t.Errorf("Purge(both) = %d, %v; want the remaining refs entry", n, err)
	}
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("entries after purge = %v", files)
	}
}

func TestCorruptEntryIsDeletedAndRefetched(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 30, 5000)}
	serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
	files := entryFiles(t, c.opts.Dir)
	if len(files) != 1 {
		t.Fatalf("entries = %v, want one", files)
	}
	path := filepath.Join(c.opts.Dir, filepath.FromSlash(files[0]))
	data, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-30] ^= 0xff
	writeEntry(t, path, data)

	// The corruption is in the trailer, so earlier segments are served
	// before verification fails: the response is aborted.
	rec := httptest.NewRecorder()
	if _, _, aborted := serve(c, rec, fetchRequest(t), fetch); !aborted {
		t.Fatal("corrupt final segment did not abort the response")
	}

	// Corrupt the header: verification fails before any byte, so the
	// entry is deleted and the request is refetched.
	data, err = os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	data[preambleLen+10] ^= 0xff
	writeEntry(t, path, data)
	rec = httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
	if aborted || !handled || out.Result != observability.ResultMiss || !out.Stored {
		t.Fatalf("after header corruption: %+v handled %v aborted %v, want a stored miss", out, handled, aborted)
	}
	if fetch.calls.Load() != 2 {
		t.Errorf("fetched %d times, want 2", fetch.calls.Load())
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
		t.Errorf("after refetch = %+v, want a hit", out)
	}
}

// writeEntry overwrites an entry file under the test's cache directory.
func writeEntry(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // path is within the test's own cache directory
		t.Fatal(err)
	}
}

func TestNoFillSlotBypasses(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.MaxConcurrentFills = 1 })
	gate := make(chan struct{})
	blocked := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		<-gate
		return response(http.StatusOK, contentTypeResult, fetchResultBody(t, 1, 10)), nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(c, httptest.NewRecorder(), fetchRequest(t), blocked)
	}()
	waitFor(t, "the first fill", func() bool { return len(c.slots) == 1 })
	other := postV2(fetchBody(t, "want "+oidB+"\n", "done\n"))
	fixed := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	if out, handled, _ := serve(c, httptest.NewRecorder(), other, fixed); handled || out.Result != observability.ResultBypass {
		t.Errorf("second key with no free slot = %+v handled %v, want a bypass", out, handled)
	}
	if fixed.calls.Load() != 0 {
		t.Error("bypassed request reached the fetcher")
	}
	close(gate)
	<-done
}

func TestCloseWaitsForFillsAndRejectsLaterRequests(t *testing.T) {
	c, _ := newTestCache(t, nil)
	fetchStarted := make(chan struct{})
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		close(fetchStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(c, httptest.NewRecorder(), fetchRequest(t).WithContext(ctx), fetch)
	}()
	<-fetchStarted
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := c.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancel()
	<-done
	if _, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); handled {
		t.Error("Serve after Close handled a request")
	}
}

func TestCloseReportsADeadline(t *testing.T) {
	c, _ := newTestCache(t, nil)
	c.wg.Add(1) // a goroutine that never finishes
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want a deadline error", err)
	}
}

func TestCacheStatusValue(t *testing.T) {
	cases := []struct {
		result    string
		collapsed bool
		want      string
	}{
		{observability.ResultHit, false, "haybale; hit"},
		{observability.ResultMiss, false, "haybale; fwd=miss"},
		{observability.ResultMiss, true, "haybale; fwd=miss; collapsed"},
		{observability.ResultBypass, false, "haybale; fwd=bypass"},
	}
	for _, tc := range cases {
		if got := cacheStatusValue(tc.result, tc.collapsed); got != tc.want {
			t.Errorf("cacheStatusValue(%q, %v) = %q, want %q", tc.result, tc.collapsed, got, tc.want)
		}
	}
}

func TestCacheStatusIsAbsentByDefault(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	for range 2 {
		rec := httptest.NewRecorder()
		serve(c, rec, fetchRequest(t), fetch)
		if _, ok := rec.Header()["Cache-Status"]; ok {
			t.Error("Cache-Status emitted without exposeStatus")
		}
	}
}

func TestV0FetchUsesTheV0Grammar(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
	body := pkts(t, "NAK\n", "\x01PACK", "\x02progress\n", pktline.Flush)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: body}
	r := post(v0Body(t, v0Caps))
	if out, handled, _ := serve(c, httptest.NewRecorder(), r, fetch); !handled || !out.Stored {
		t.Fatalf("v0 fetch = %+v handled %v, want a stored miss", out, handled)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), post(v0Body(t, v0Caps)), fetch); out.Result != observability.ResultHit {
		t.Errorf("second v0 fetch = %+v, want a hit", out)
	}
}

func TestRecordsPruneExpiredEntries(t *testing.T) {
	now := time.Now()
	a := accessRecords{window: time.Minute}
	for i := range pruneThreshold {
		var h [32]byte
		h[0], h[1] = byte(i), byte(i>>8)
		a.record(h, now.Add(-2*time.Minute))
	}
	a.record([32]byte{0xff, 0xff, 0xff}, now)
	if len(a.last) != 1 {
		t.Errorf("access records after prune = %d, want 1", len(a.last))
	}
	var m uncacheableMarks
	for i := range pruneThreshold {
		m.mark(Key{KeyHash: [32]byte{byte(i), byte(i >> 8)}}, now.Add(-time.Minute))
	}
	m.mark(Key{KeyHash: [32]byte{0xff, 0xff, 0xff}}, now.Add(time.Minute))
	if len(m.until) != 1 {
		t.Errorf("marks after prune = %d, want 1", len(m.until))
	}
	if m.marked(Key{KeyHash: [32]byte{0xff, 0xff, 0xff}}, now.Add(2*time.Minute)) {
		t.Error("expired mark reported as marked")
	}
}
