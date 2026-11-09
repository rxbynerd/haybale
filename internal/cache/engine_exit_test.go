package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
)

// exitCache is a cache with captured logs and metrics for the exit-path
// tests.
func exitCache(t *testing.T, mutate func(*Options)) (*Cache, *logCapture, *sdkmetric.ManualReader) {
	t.Helper()
	logger, logs := newLogCapture()
	m, reader := observability.NewTestMetrics()
	c, _ := newTestCache(t, func(o *Options) {
		o.AccessRecheck = 0
		o.Logger = logger
		o.Metrics = m
		if mutate != nil {
			mutate(o)
		}
	})
	return c, logs, reader
}

func TestEncodedUpstreamResponseIsReleasedToPassthrough(t *testing.T) {
	c, _, reader := exitCache(t, nil)
	body := fetchResultBody(t, 2, 100)
	for i, tc := range []struct {
		encoding    string
		wantHandled bool
	}{
		{"gzip", false},
		{"br, gzip", false},
		{"identity", true},
		{"Identity", true},
		{"", true},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			r := fetchRequestFor(t, i)
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
				resp := response(http.StatusOK, contentTypeResult, body)
				if tc.encoding != "" {
					resp.Header.Set("Content-Encoding", tc.encoding)
				}
				return resp, nil
			})
			rec := httptest.NewRecorder()
			out, handled, aborted := serve(c, rec, r, fetch)
			if aborted || handled != tc.wantHandled {
				t.Fatalf("Serve = %+v handled %v aborted %v, want handled %v", out, handled, aborted, tc.wantHandled)
			}
			if tc.wantHandled && (!out.Stored || !bytes.Equal(rec.Body.Bytes(), body)) {
				t.Errorf("identity response = %+v with %d bytes, want stored and complete", out, rec.Body.Len())
			}
			if !tc.wantHandled {
				if _, ok, _ := serve(c, httptest.NewRecorder(), r, fetch); ok {
					t.Error("key was not marked after an encoded response")
				}
			}
			assertStoreIdle(t, c)
		})
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonEncoding); got != 2 {
		t.Errorf("fills discarded encoding = %d, want 2", got)
	}
	if got := fillsWithReason(t, reader, observability.FillResultStored, ""); got != 3 {
		t.Errorf("fills stored = %d, want 3", got)
	}
}

func TestFillPanicBeforeHeadersReleasesSubscribers(t *testing.T) {
	c, logs, reader := exitCache(t, nil)
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		panic("fetcher exploded")
	})
	out, handled, aborted := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
	if aborted || handled || out.Result != observability.ResultBypass {
		t.Fatalf("Serve = %+v handled %v aborted %v, want a bypass", out, handled, aborted)
	}
	assertStoreIdle(t, c)
	if recs := logs.records(t, "fill panicked"); len(recs) != 1 || recs[0]["level"] != "ERROR" {
		t.Errorf("fill panicked log = %v, want one Error record", recs)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
		t.Errorf("fills discarded store_error = %d, want 1", got)
	}
}

// panicAfterReader serves n bytes and then panics on the next Read.
type panicAfterReader struct {
	data []byte
	n    int
	gate chan struct{}
}

func (r *panicAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		<-r.gate
		panic("body exploded")
	}
	k := copy(p, r.data[:min(r.n, len(r.data))])
	r.data = r.data[k:]
	return k, nil
}

func (r *panicAfterReader) Close() error { return nil }

func TestFillPanicMidBodyAbortsSubscribers(t *testing.T) {
	c, logs, reader := exitCache(t, nil)
	body := fetchResultBody(t, 20, 5000)
	gate := make(chan struct{})
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return streamingResponse(contentTypeResult, &panicAfterReader{data: body[:70000], n: 70000, gate: gate}), nil
	})
	leader := newCollectWriter()
	results := make(chan bool, 2)
	go func() {
		_, _, aborted := serve(c, leader, fetchRequest(t), fetch)
		results <- aborted
	}()
	<-leader.first
	go func() {
		_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), fetch)
		results <- aborted
	}()
	waitForSubscribers(t, c, 2)
	close(gate)
	for range 2 {
		if aborted := <-results; !aborted {
			t.Error("a subscriber was not aborted after the body panicked")
		}
	}
	assertStoreIdle(t, c)
	if recs := logs.records(t, "fill panicked"); len(recs) != 1 {
		t.Errorf("fill panicked records = %d, want 1", len(recs))
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
		t.Errorf("fills discarded store_error = %d, want 1", got)
	}
}

// panicWriter accepts the sealed header and panics on every later Write.
type panicWriter struct{ writes int }

func (w *panicWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > 1 {
		panic("sealing exploded")
	}
	return len(p), nil
}

func TestFlushPanicAbortsTheFillNotTheProcess(t *testing.T) {
	c, logs, _ := exitCache(t, nil)
	c.flushInterval = 10 * time.Millisecond
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

	// Point the seal at a writer that panics, so the next timed flush
	// panics inside the timer goroutine.
	c.mu.Lock()
	var f *fill
	for _, f = range c.fills {
	}
	c.mu.Unlock()
	f.seal.mu.Lock()
	sw, err := newSealedWriter(&panicWriter{}, c.keyring, testHeader())
	f.seal.w = sw
	f.seal.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write(body[70000:70100]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the flush panic to be recorded", func() bool {
		f.seal.mu.Lock()
		defer f.seal.mu.Unlock()
		return f.seal.err != nil
	})
	if _, err := pw.Write(body[70100:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	if aborted := <-done; !aborted {
		t.Fatal("subscriber was not aborted after the flush panicked")
	}
	if recs := logs.records(t, "flush panicked"); len(recs) != 1 || recs[0]["level"] != "ERROR" {
		t.Errorf("flush panicked log = %v, want one Error record", recs)
	}
	f.seal.mu.Lock()
	closed := f.seal.closed
	f.seal.mu.Unlock()
	if !closed {
		t.Error("abort did not close the seal, so a later flush could still run")
	}
	assertStoreIdle(t, c)
}

func TestAbortStopsTheFlushTimer(t *testing.T) {
	c, _, _ := exitCache(t, nil)
	c.flushInterval = time.Hour
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
	if _, err := pw.Write(fetchResultBody(t, 20, 5000)[:70000]); err != nil {
		t.Fatal(err)
	}
	<-w.first
	c.mu.Lock()
	var f *fill
	for _, f = range c.fills {
	}
	c.mu.Unlock()
	_ = pw.CloseWithError(errors.New("upstream reset"))
	if aborted := <-done; !aborted {
		t.Fatal("subscriber was not aborted")
	}
	f.seal.mu.Lock()
	closed, armed := f.seal.closed, f.seal.timer != nil && f.seal.timer.Stop()
	f.seal.mu.Unlock()
	if !closed || armed {
		t.Errorf("after abort: seal closed %v, timer still armed %v", closed, armed)
	}
	assertStoreIdle(t, c)
}

func TestClassificationBodyBudget(t *testing.T) {
	c, _, reader := exitCache(t, nil)
	type stalled struct {
		pw *io.PipeWriter
		r  *http.Request
	}
	var wg sync.WaitGroup
	stalls := make([]stalled, maxClassifications)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	for i := range stalls {
		pr, pw := io.Pipe()
		r := postV2(nil)
		r.Body = pr
		r.ContentLength = -1
		stalls[i] = stalled{pw: pw, r: r}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Most of these find no free fill slot and pass through; the
			// passthrough path closes the replayed body.
			if _, handled, _ := serve(c, httptest.NewRecorder(), r, fetch); !handled {
				_ = r.Body.Close()
			}
		}()
	}
	waitFor(t, "every classification slot to be taken", func() bool { return len(c.classifySlots) == maxClassifications })

	body := cloneFetchBody(t)
	r := postV2(body)
	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, r, fetch)
	if handled || out.Result != observability.ResultBypass {
		t.Fatalf("request beyond the body budget = %+v handled %v, want a bypass", out, handled)
	}
	if rec.Header().Get("Cache-Status") != "" {
		t.Error("Cache-Status set although the cache does not expose it")
	}
	replayed, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(replayed, body) {
		t.Fatalf("replayed body = %d bytes, %v; want the %d original bytes", len(replayed), err, len(body))
	}
	if got := sumWhere(t, reader, "haybale.response_cache.lookups.total", map[string]string{"haybale.result": observability.ResultBypass, "haybale.class": observability.ClassBypass}); got != 1 {
		t.Errorf("bypass lookups with class bypass = %d, want 1", got)
	}

	for i, s := range stalls {
		_, _ = s.pw.Write(fetchBody(t, "want "+wantOID(i)+"\n", "done\n"))
		_ = s.pw.Close()
	}
	wg.Wait()
	if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !ok || out.Result != observability.ResultMiss {
		t.Errorf("request after the stalled ones finished = %+v handled %v, want a handled miss", out, ok)
	}
	if n := len(c.classifySlots); n != 0 {
		t.Errorf("classification slots still held = %d, want 0", n)
	}
	assertStoreIdle(t, c)
}

func TestClassificationSlotIsReleasedOnEveryExit(t *testing.T) {
	c, _, _ := exitCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	cases := map[string]func(t *testing.T){
		"handled": func(t *testing.T) {
			t.Helper()
			if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !ok {
				t.Fatal("not handled")
			}
		},
		"bypassed and replayed": func(t *testing.T) {
			t.Helper()
			r := post(fetchBody(t, "want "+oidA+"\n", "have "+oidB+"\n", "done\n"))
			if _, ok, _ := serve(c, httptest.NewRecorder(), r, fetch); ok {
				t.Fatal("handled a request with haves")
			}
			if _, err := io.ReadAll(r.Body); err != nil {
				t.Fatal(err)
			}
		},
		"bypassed and closed": func(t *testing.T) {
			t.Helper()
			r := post(fetchBody(t, "want "+oidA+"\n", "have "+oidB+"\n", "done\n"))
			if _, ok, _ := serve(c, httptest.NewRecorder(), r, fetch); ok {
				t.Fatal("handled a request with haves")
			}
			_ = r.Body.Close()
		},
		"client read error": func(t *testing.T) {
			t.Helper()
			r := postV2(nil)
			r.Body = io.NopCloser(&errReader{err: errors.New("connection reset")})
			r.ContentLength = -1
			if _, ok, _ := serve(c, httptest.NewRecorder(), r, fetch); ok {
				t.Fatal("handled a request whose body failed")
			}
			_ = r.Body.Close()
		},
		"panic": func(t *testing.T) {
			t.Helper()
			c.hooks.beforeOpenReader = func(entryKey) { panic("subscriber exploded") }
			defer func() { c.hooks.beforeOpenReader = nil }()
			defer func() {
				if recover() == nil {
					t.Fatal("panic did not propagate")
				}
			}()
			_, _ = c.Serve(httptest.NewRecorder(), otherFetchRequest(t), testRepo, testBaseURL, fetch)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			run(t)
			if n := len(c.classifySlots); n != 0 {
				t.Errorf("classification slots held after %s = %d", name, n)
			}
		})
	}
	assertStoreIdle(t, c)
}

// TestEarlyBypassesDoNotLeakClassificationSlots drives each bypass that
// returns before the body is read, plus the classification errors, more
// often than there are slots. The bodies are never read or closed, as
// when a passthrough path gives up early. A request after them must
// still classify.
func TestEarlyBypassesDoNotLeakClassificationSlots(t *testing.T) {
	c, _, reader := exitCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	body := cloneFetchBody(t)
	paths := map[string]func() *http.Request{
		"bad Git-Protocol": func() *http.Request { return post(body, "Git-Protocol", "version=3") },
		"query string": func() *http.Request {
			r := postV2(body)
			r.URL.RawQuery = "x=1"
			return r
		},
		"wrong Content-Type": func() *http.Request {
			r := postV2(body)
			r.Header.Set("Content-Type", "text/plain")
			return r
		},
		"Content-Encoding": func() *http.Request { return postV2(body, "Content-Encoding", "br") },
		"GET with a body": func() *http.Request {
			r := get()
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			return r
		},
		"unparseable path": func() *http.Request {
			r := postV2(body)
			r.URL.Path = "/nowhere"
			return r
		},
		"write request": func() *http.Request {
			r := postV2(body)
			r.URL.Path = "/github.com/acme/widgets.git/git-receive-pack"
			return r
		},
	}
	const attempts = 200
	for name, build := range paths {
		for range attempts {
			if out, handled, _ := serve(c, httptest.NewRecorder(), build(), fetch); handled || out.Result != observability.ResultBypass {
				t.Fatalf("%s = %+v handled %v, want a bypass", name, out, handled)
			}
		}
		if n := len(c.classifySlots); n != 0 {
			t.Fatalf("%s left %d classification slots held", name, n)
		}
	}
	if got := sumWhere(t, reader, "haybale.response_cache.lookups.total", map[string]string{"haybale.result": observability.ResultBypass}); got != int64(len(paths)*attempts) {
		t.Errorf("bypass lookups = %d, want %d", got, len(paths)*attempts)
	}
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !handled || out.Result != observability.ResultMiss {
		t.Errorf("request after %d early bypasses = %+v handled %v, want a handled miss", len(paths)*attempts, out, handled)
	}
	assertStoreIdle(t, c)
}

// TestClassificationSlotIsNotHeldWhileStreaming starts more concurrent
// clones than there are slots; every one is served from the one fill, so
// none passes through for want of a slot.
func TestClassificationSlotIsNotHeldWhileStreaming(t *testing.T) {
	c, _, _ := exitCache(t, nil)
	pr, pw := io.Pipe()
	var fetches atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		fetches.Add(1)
		return streamingResponse(contentTypeResult, pr), nil
	})
	const clients = maxClassifications + 8
	type result struct {
		out     Outcome
		handled bool
	}
	results := make(chan result, clients)
	requests := make([]*http.Request, clients)
	for i := range requests {
		requests[i] = fetchRequest(t)
	}
	// Each client is started once the previous one has joined, so fewer
	// than maxClassifications are ever in the pre-stream phase together.
	for i, r := range requests {
		go func() {
			out, handled, _ := serve(c, httptest.NewRecorder(), r, fetch)
			results <- result{out, handled}
		}()
		waitFor(t, "the client to join the one fill", func() bool { return subscribersAre(c, i+1) })
	}
	waitFor(t, "the classification slots to be released", func() bool { return len(c.classifySlots) == 0 })
	_, _ = pw.Write(fetchResultBody(t, 1, 10))
	_ = pw.Close()
	for range clients {
		if res := <-results; !res.handled || res.out.Result != observability.ResultMiss {
			t.Errorf("client = %+v handled %v, want a miss served from the shared fill", res.out, res.handled)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("upstream fetches = %d, want 1", got)
	}
	assertStoreIdle(t, c)
}

func TestReplayBodyDropsItsBufferOnceReplayed(t *testing.T) {
	r := postV2(cloneFetchBody(t))
	if _, reason, err := readBody(r, false, 1<<20); err != nil || reason != "" {
		t.Fatalf("readBody: %q, %v", reason, err)
	}
	rb, ok := r.Body.(*replayBody)
	if !ok {
		t.Fatalf("body is %T", r.Body)
	}
	if len(rb.captured) == 0 {
		t.Fatal("captured bytes were dropped before the replay")
	}
	data, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(data, cloneFetchBody(t)) {
		t.Fatalf("replay = %d bytes, %v", len(data), err)
	}
	if rb.captured != nil {
		t.Errorf("after replay: %d captured bytes remain", len(rb.captured))
	}
}

func TestClientDisconnectMidStream(t *testing.T) {
	t.Run("leader", func(t *testing.T) {
		c, _, _ := exitCache(t, nil)
		body := fetchResultBody(t, 20, 5000)
		fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: body}
		w := newFailAfterWriter(70000)
		out, handled, aborted := serve(c, w, fetchRequest(t), fetch)
		if aborted || !handled || out.Result != observability.ResultMiss || out.BytesOut == 0 || out.BytesOut >= int64(len(body)) {
			t.Fatalf("leader whose client left = %+v handled %v aborted %v", out, handled, aborted)
		}
		assertStoreIdle(t, c)
		if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
			t.Errorf("fill did not commit after the client left: %+v", out)
		}
	})
	t.Run("follower while the leader continues", func(t *testing.T) {
		c, _, _ := exitCache(t, nil)
		body := fetchResultBody(t, 20, 5000)
		pr, pw := io.Pipe()
		fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
			return streamingResponse(contentTypeResult, pr), nil
		})
		leader := newCollectWriter()
		var leaderOut Outcome
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaderOut, _, _ = serve(c, leader, fetchRequest(t), fetch)
		}()
		if _, err := pw.Write(body[:70000]); err != nil {
			t.Fatal(err)
		}
		<-leader.first
		follower := newFailAfterWriter(0)
		var followerOut Outcome
		var followerAborted bool
		wg.Add(1)
		go func() {
			defer wg.Done()
			followerOut, _, followerAborted = serve(c, follower, fetchRequest(t), fetch)
		}()
		<-follower.failed
		if _, err := pw.Write(body[70000:]); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		wg.Wait()
		if followerAborted || followerOut.Result != observability.ResultMiss {
			t.Errorf("follower whose client left = %+v aborted %v", followerOut, followerAborted)
		}
		if !leaderOut.Stored {
			t.Errorf("leader = %+v, want stored", leaderOut)
		}
		if _, got, _ := leader.result(); !bytes.Equal(got, body) {
			t.Error("leader did not receive the complete body")
		}
		assertStoreIdle(t, c)
	})
	t.Run("hit", func(t *testing.T) {
		c, _, _ := exitCache(t, nil)
		fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 20, 5000)}
		serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
		out, handled, aborted := serve(c, newFailAfterWriter(70000), fetchRequest(t), fetch)
		if aborted || !handled || out.Result != observability.ResultHit {
			t.Fatalf("hit whose client left = %+v handled %v aborted %v", out, handled, aborted)
		}
		assertStoreIdle(t, c)
		if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
			t.Errorf("entry after a disconnected hit = %+v, want a hit", out)
		}
	})
}

// cancelledLeader starts a request whose context is cancelled once the
// first body bytes have reached it, and returns the fill's context and
// the request's results.
func cancelledLeader(t *testing.T, c *Cache, pr io.ReadCloser) (fillCtx context.Context, done <-chan Outcome) {
	t.Helper()
	started := make(chan context.Context, 1)
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		started <- ctx
		return streamingResponse(contentTypeResult, pr), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	w := newCollectWriter()
	outCh := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(c, w, fetchRequest(t).WithContext(ctx), fetch)
		outCh <- out
	}()
	fillCtx = <-started
	<-w.first
	cancel()
	return fillCtx, outCh
}

func TestAbandonedFillAfterSpoolingLeavesNothingBehind(t *testing.T) {
	c, _, _ := exitCache(t, func(o *Options) { o.IdleTimeout = time.Hour })
	c.idleGrace = 50 * time.Millisecond
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write(fetchResultBody(t, 20, 5000)[:70000]) }()
	fillCtx, outCh := cancelledLeader(t, c, pr)
	// A blocked subscriber notices its client leaving without waiting for
	// the idle timeout.
	select {
	case out := <-outCh:
		if out.Result != observability.ResultMiss {
			t.Errorf("cancelled subscriber = %+v", out)
		}
	case <-time.After(shortly):
		t.Fatal("subscriber did not return after its context was cancelled")
	}
	select {
	case <-fillCtx.Done():
	case <-time.After(shortly):
		t.Fatal("fill was not abandoned after its only subscriber left")
	}
	_ = pw.CloseWithError(fillCtx.Err())
	assertStoreIdle(t, c)
	if c.marks.marked(entryKeyFor(t, c, fetchRequest(t)), c.now()) {
		t.Error("an abandoned fill marked its key")
	}
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !ok || !out.Stored {
		t.Errorf("request after an abandoned fill = %+v handled %v, want a fresh stored fill", out, ok)
	}
}

func TestSubscriberReattachingWithinTheGraceKeepsTheFillAlive(t *testing.T) {
	c, _, _ := exitCache(t, nil)
	c.idleGrace = 2 * time.Second
	body := fetchResultBody(t, 20, 5000)
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write(body[:70000]) }()
	fillCtx, outCh := cancelledLeader(t, c, pr)
	<-outCh
	second := newCollectWriter()
	var out Outcome
	done := make(chan struct{})
	go func() {
		defer close(done)
		out, _, _ = serve(c, second, fetchRequest(t), fetchFunc(func(context.Context, Request) (*http.Response, error) {
			t.Error("a second fetch was started")
			return nil, errors.New("unexpected")
		}))
	}()
	waitForSubscribers(t, c, 1)
	if _, err := pw.Write(body[70000:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	<-done
	if fillCtx.Err() != nil && !out.Stored {
		t.Fatalf("fill was cancelled although a subscriber re-attached: %+v", out)
	}
	if !out.Stored || !out.Collapsed {
		t.Errorf("second subscriber = %+v, want a stored, collapsed miss", out)
	}
	if _, got, _ := second.result(); !bytes.Equal(got, body) {
		t.Error("second subscriber did not receive the complete body")
	}
	assertStoreIdle(t, c)
}

func TestNon200ResponseEdges(t *testing.T) {
	t.Run("body over the shared limit releases", func(t *testing.T) {
		c, _, reader := exitCache(t, nil)
		fetch := &fixedFetcher{status: http.StatusServiceUnavailable, contentType: "text/plain", body: bytes.Repeat([]byte("x"), sharedBodyLimit+1)}
		if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok || out.Result != observability.ResultBypass {
			t.Fatalf("Serve = %+v handled %v, want a bypass", out, ok)
		}
		if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonUpstreamStatus); got != 1 {
			t.Errorf("fills discarded upstream_status = %d, want 1", got)
		}
		assertStoreIdle(t, c)
	})
	t.Run("read error while buffering releases", func(t *testing.T) {
		c, _, reader := exitCache(t, nil)
		fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
			resp := response(http.StatusNotFound, "text/plain", nil)
			resp.Body = io.NopCloser(&errReader{err: errors.New("reset")})
			return resp, nil
		})
		if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok || out.Result != observability.ResultBypass {
			t.Fatalf("Serve = %+v handled %v, want a bypass", out, ok)
		}
		if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonFetchError); got != 1 {
			t.Errorf("fills discarded fetch_error = %d, want 1", got)
		}
		assertStoreIdle(t, c)
	})
	t.Run("nil body is a fetch error", func(t *testing.T) {
		c, _, reader := exitCache(t, nil)
		fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentTypeResult}}}, nil
		})
		if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok || out.Result != observability.ResultBypass {
			t.Fatalf("Serve = %+v handled %v, want a bypass", out, ok)
		}
		if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonFetchError); got != 1 {
			t.Errorf("fills discarded fetch_error = %d, want 1", got)
		}
		assertStoreIdle(t, c)
	})
	t.Run("headers are relayed and Content-Length recomputed", func(t *testing.T) {
		c, _, _ := exitCache(t, nil)
		fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
			resp := response(http.StatusForbidden, "text/plain", []byte("denied"))
			resp.Header.Set("Content-Length", "9999")
			resp.Header.Set("X-Upstream", "kept")
			resp.Header.Set("Transfer-Encoding", "chunked")
			return resp, nil
		})
		rec := httptest.NewRecorder()
		out, ok, _ := serve(c, rec, fetchRequest(t), fetch)
		if !ok || out.Status != http.StatusForbidden || rec.Body.String() != "denied" {
			t.Fatalf("Serve = %+v handled %v body %q", out, ok, rec.Body.String())
		}
		if rec.Header().Get("Content-Length") != "6" || rec.Header().Get("X-Upstream") != "kept" || rec.Header().Get("Transfer-Encoding") != "" {
			t.Errorf("relayed headers = %v", rec.Header())
		}
		assertStoreIdle(t, c)
	})
}

func TestStoreFailuresEndTheFill(t *testing.T) {
	t.Run("spool cannot be created", func(t *testing.T) {
		c, _, reader := exitCache(t, nil)
		if err := os.RemoveAll(c.opts.Dir); err != nil {
			t.Fatal(err)
		}
		fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
		out, ok, aborted := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
		if aborted || ok || out.Result != observability.ResultBypass {
			t.Fatalf("Serve = %+v handled %v aborted %v, want a bypass", out, ok, aborted)
		}
		if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
			t.Errorf("fills discarded store_error = %d, want 1", got)
		}
		if got := storeErrors(t, reader, observability.OperationCreate); got != 1 {
			t.Errorf("store_errors(create) = %d, want 1", got)
		}
		if err := os.MkdirAll(c.opts.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("spool write fails mid-fill", func(t *testing.T) {
		c, _, reader := exitCache(t, nil)
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
		body := fetchResultBody(t, 40, 5000)
		if _, err := pw.Write(body[:70000]); err != nil {
			t.Fatal(err)
		}
		<-w.first
		c.mu.Lock()
		var f *fill
		for _, f = range c.fills {
		}
		c.mu.Unlock()
		// Close the spool's descriptor under it so the next write fails.
		// The fill aborts and closes the upstream body as soon as that
		// write fails, so later pipe writes may be refused.
		if err := f.spool.f.Close(); err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write(body[70000:])
		_ = pw.Close()
		if aborted := <-done; !aborted {
			t.Fatal("subscriber was not aborted after the spool write failed")
		}
		if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
			t.Errorf("fills discarded store_error = %d, want 1", got)
		}
		if got := storeErrors(t, reader, observability.OperationWrite); got != 1 {
			t.Errorf("store_errors(write) = %d, want 1", got)
		}
		assertStoreIdle(t, c)
	})
}

func TestFillMetricsPerExit(t *testing.T) {
	c, _, reader := exitCache(t, func(o *Options) { o.RefsMaxAge = time.Minute })
	exits := []struct {
		name   string
		req    func() *http.Request
		resp   func() (*http.Response, error)
		result string
		reason string
	}{
		{"stored", func() *http.Request { return fetchRequestFor(t, 1) }, func() (*http.Response, error) {
			return response(200, contentTypeResult, fetchResultBody(t, 1, 10)), nil
		}, observability.FillResultStored, ""},
		{"error packet", func() *http.Request { return fetchRequestFor(t, 2) }, func() (*http.Response, error) {
			return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(pkts(t, "ERR nope\n")))), nil
		}, observability.FillResultDiscarded, observability.FillReasonErrorPacket},
		{"sideband error", func() *http.Request { return fetchRequestFor(t, 3) }, func() (*http.Response, error) {
			return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(pkts(t, "packfile\n", "\x01PACK", "\x03fatal\n", pktline.Flush)))), nil
		}, observability.FillResultDiscarded, observability.FillReasonSidebandError},
		{"framing", func() *http.Request { return fetchRequestFor(t, 4) }, func() (*http.Response, error) {
			return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader([]byte("00zz")))), nil
		}, observability.FillResultDiscarded, observability.FillReasonFraming},
		{"truncated", func() *http.Request { return fetchRequestFor(t, 5) }, func() (*http.Response, error) {
			return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(pkts(t, "packfile\n", "\x01PACK")))), nil
		}, observability.FillResultDiscarded, observability.FillReasonTruncated},
		{"upstream status", func() *http.Request { return fetchRequestFor(t, 6) }, func() (*http.Response, error) {
			return response(http.StatusNotFound, "text/plain", []byte("gone")), nil
		}, observability.FillResultDiscarded, observability.FillReasonUpstreamStatus},
		{"fetch error", func() *http.Request { return fetchRequestFor(t, 7) }, func() (*http.Response, error) {
			return nil, errors.New("dial failed")
		}, observability.FillResultDiscarded, observability.FillReasonFetchError},
		{"encoding", func() *http.Request { return fetchRequestFor(t, 8) }, func() (*http.Response, error) {
			resp := response(200, contentTypeResult, fetchResultBody(t, 1, 10))
			resp.Header.Set("Content-Encoding", "gzip")
			return resp, nil
		}, observability.FillResultDiscarded, observability.FillReasonEncoding},
	}
	for _, e := range exits {
		t.Run(e.name, func(t *testing.T) {
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) { return e.resp() })
			serve(c, httptest.NewRecorder(), e.req(), fetch)
			if got := fillsWithReason(t, reader, e.result, e.reason); got != 1 {
				t.Errorf("fills %s/%s = %d, want 1", e.result, e.reason, got)
			}
			assertStoreIdle(t, c)
		})
	}
	// Generation: a push during a refs fill.
	c.hooks.beforeCommit = func(key entryKey) {
		if key.Group == GroupRefs {
			c.Invalidate(context.Background(), testRepo, testBaseURL)
		}
	}
	serve(c, httptest.NewRecorder(), get(), &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)})
	c.hooks.beforeCommit = nil
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonGeneration); got != 1 {
		t.Errorf("fills discarded generation = %d, want 1", got)
	}

	// Lookups, collapsing and byte tiers across a miss, a follower and a hit.
	stored := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 1, 10)}
	before := lookups(t, reader, observability.ResultMiss)
	lf := newLateFollower(t, c, fetchRequestFor(t, 20), func() *http.Response {
		return response(200, contentTypeResult, fetchResultBody(t, 1, 10))
	})
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequestFor(t, 20), lf.fetch); !handled || out.Collapsed {
		t.Fatalf("leader = %+v handled %v, want a handled, uncollapsed miss", out, handled)
	}
	if out, handled := lf.wait(); !handled || !out.Collapsed {
		t.Fatalf("follower = %+v handled %v, want a handled, collapsed miss", out, handled)
	}
	c.hooks.afterDecision, c.hooks.beforeOpenReader = nil, nil
	serve(c, httptest.NewRecorder(), fetchRequestFor(t, 1), stored) // hit
	if got := lookups(t, reader, observability.ResultHit); got != 1 {
		t.Errorf("hit lookups = %d, want 1", got)
	}
	if got := lookups(t, reader, observability.ResultMiss); got != before+2 {
		t.Errorf("miss lookups = %d, want %d (the leader and the follower)", got, before+2)
	}
	if got := lookups(t, reader, observability.ResultBypass); got != 2 {
		t.Errorf("bypass lookups = %d, want 2 (the fetch error and the encoded response)", got)
	}
	if got := sumWhere(t, reader, "haybale.response_cache.collapsed.total", nil); got != 1 {
		t.Errorf("collapsed.total = %d, want 1", got)
	}
	if got := sumWhere(t, reader, "haybale.response_cache.served_bytes.total", map[string]string{"haybale.tier": observability.TierDisk}); got == 0 {
		t.Error("no bytes served from the disk tier after a hit")
	}
	if got := sumWhere(t, reader, "haybale.response_cache.served_bytes.total", map[string]string{"haybale.tier": observability.TierUpstream}); got == 0 {
		t.Error("no bytes served from the upstream tier after misses")
	}
	if got := sumWhere(t, reader, "haybale.response_cache.fill_bytes.total", map[string]string{"haybale.tier": observability.TierUpstream}); got == 0 {
		t.Error("no fill bytes recorded for the upstream tier")
	}
	if got := sumWhere(t, reader, "haybale.response_cache.fill_bytes.total", map[string]string{"haybale.tier": observability.TierDisk}); got != 0 {
		t.Errorf("fill bytes recorded for the disk tier = %d, want 0", got)
	}
}

func TestRefsFillCapBypassesTheNextRequest(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) {
		o.MaxDiskSize = 256 << 20
		o.MaxEntrySize = 8 << 20
		o.RefsMaxAge = time.Minute
		o.AccessRecheck = 0
	})
	var mu sync.Mutex
	var bodies []*io.PipeWriter
	refs := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		mu.Lock()
		bodies = append(bodies, pw)
		mu.Unlock()
		return streamingResponse(contentTypeResult, pr), nil
	})
	var wg sync.WaitGroup
	for i := range maxRefsFills {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := pkts(t, "command=ls-refs\n", pktline.Delim, "ref-prefix refs/heads/b"+strconv.Itoa(i)+"\n", pktline.Flush)
			serve(c, httptest.NewRecorder(), postV2(body), refs)
		}()
	}
	waitFor(t, "every refs slot to be taken", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.refsFills == maxRefsFills
	})
	extra := &fixedFetcher{status: 200, contentType: contentTypeResult, body: lsRefsResultBody(t)}
	if out, ok, _ := serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), extra); ok || out.Result != observability.ResultBypass || extra.calls.Load() != 0 {
		t.Errorf("refs request beyond the cap = %+v handled %v fetches %d, want an unfetched bypass", out, ok, extra.calls.Load())
	}
	mu.Lock()
	for _, pw := range bodies {
		_, _ = pw.Write(lsRefsResultBody(t))
		_ = pw.Close()
	}
	mu.Unlock()
	wg.Wait()
	assertStoreIdle(t, c)
}

func TestCloseMidStreamLeavesNoTempFilesAndIsIdempotent(t *testing.T) {
	c, _ := newTestCache(t, nil)
	pr, pw := io.Pipe()
	started := make(chan context.Context, 1)
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		started <- ctx
		return streamingResponse(contentTypeResult, pr), nil
	})
	w := newCollectWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(c, w, fetchRequest(t), fetch)
	}()
	fillCtx := <-started
	if _, err := pw.Write(fetchResultBody(t, 20, 5000)[:70000]); err != nil {
		t.Fatal(err)
	}
	<-w.first
	go func() {
		<-fillCtx.Done()
		_ = pw.CloseWithError(fillCtx.Err())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), shortly)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done
	for _, f := range entryFiles(t, c.opts.Dir) {
		if strings.HasPrefix(f, tempNamePrefix) {
			t.Errorf("temporary file left behind: %s", f)
		}
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
