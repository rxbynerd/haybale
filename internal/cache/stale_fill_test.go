package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// closeTracker is an upstream body that records whether it was closed.
type closeTracker struct {
	io.Reader
	closed atomic.Bool
}

func (c *closeTracker) Close() error {
	c.closed.Store(true)
	return nil
}

// ctxBody fails every read once ctx has ended, as a transport's body does
// when its request is cancelled.
type ctxBody struct {
	ctx context.Context
	r   io.ReadCloser
}

func (b ctxBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	return b.r.Read(p)
}

func (b ctxBody) Close() error { return b.r.Close() }

// slowReader delays every read by delay and calls first before the first.
type slowReader struct {
	r     io.Reader
	delay time.Duration
	first func()
	once  atomic.Bool
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.once.CompareAndSwap(false, true) {
		s.first()
	}
	<-time.After(s.delay)
	return s.r.Read(p)
}

// TestRemoteStaleStreamOutlivesTheUpstreamIdleTimeout: once a 5xx body
// has been buffered, the upstream request is closed and released before a
// remote stale copy streams, so a stream longer than idleTimeout completes
// for every subscriber. A 5xx body over the shared limit is the same.
func TestRemoteStaleStreamOutlivesTheUpstreamIdleTimeout(t *testing.T) {
	for name, size := range map[string]int{"shared 503": 64, "503 over the shared limit": sharedBodyLimit + 1} {
		t.Run(name, func(t *testing.T) {
			const idle = 60 * time.Millisecond
			store := newMemBlobStore()
			pack := fetchResultBody(t, 200, 5000)
			seedPeer(t, store, pack)
			c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
				enableStale(o)
				o.IdleTimeout = idle
			})
			clock.Advance(2 * time.Minute)

			upstreamBody := &closeTracker{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), size))}
			var fetchCtx atomic.Pointer[context.Context]
			release := make(chan struct{})
			fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
				fetchCtx.Store(&ctx)
				<-release
				resp := response(http.StatusServiceUnavailable, "text/plain", nil)
				resp.Body, resp.ContentLength = upstreamBody, int64(size)
				return resp, nil
			})
			var closedFirst, releasedFirst atomic.Bool
			store.set(func(m *memBlobStore) {
				m.wrapBody = func(_ context.Context, key string, _ int64, body io.Reader) io.Reader {
					if !strings.HasPrefix(key, packPrefix) {
						return body
					}
					return &slowReader{r: body, delay: idle / 3, first: func() {
						closedFirst.Store(upstreamBody.closed.Load())
						if ctx := fetchCtx.Load(); ctx != nil {
							releasedFirst.Store((*ctx).Err() != nil)
						}
					}}
				}
			})

			reqs := []*http.Request{fetchRequest(t), fetchRequest(t)}
			results := make(chan served, len(reqs))
			for i, r := range reqs {
				go func() {
					rec := newCollectWriter()
					out, handled, aborted := serve(c, rec, r, fetch)
					_, body, _ := rec.result()
					if aborted {
						handled = false
					}
					results <- served{out: out, handled: handled, body: body}
				}()
				waitForSubscribers(t, c, i+1)
			}
			close(release)
			for range reqs {
				res := <-results
				if !res.handled || res.out.Result != observability.ResultStale || !bytes.Equal(res.body, pack) {
					t.Errorf("subscriber = %+v handled %v with %d bytes, want the remote copy served stale", res.out, res.handled, len(res.body))
				}
			}
			if !closedFirst.Load() || !releasedFirst.Load() {
				t.Errorf("before the remote stream: upstream body closed %v, request released %v; want both", closedFirst.Load(), releasedFirst.Load())
			}
			assertStoreIdle(t, c)
		})
	}
}

// TestHeaderTimerFiringAfterFetchReturnsIsAHeaderTimeout: a header timer
// that fires between the Fetcher returning and the fill claiming the
// response makes it a header timeout, eligible for stale service, rather
// than a body cut off mid-read.
func TestHeaderTimerFiringAfterFetchReturnsIsAHeaderTimeout(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.ResponseHeaderTimeout = 20 * time.Millisecond })
	h.clock.Advance(10 * time.Minute)
	h.c.hooks.afterFetch = func(key entryKey) {
		pollFor(func() bool {
			h.c.mu.Lock()
			f := h.c.fills[key]
			h.c.mu.Unlock()
			return f != nil && f.headerCut.Load() == headerCutTimeout
		})
	}
	fetch := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		resp := response(http.StatusOK, contentTypeResult, h.pack)
		resp.Body = ctxBody{ctx: ctx, r: resp.Body}
		return resp, nil
	})
	rec := newCollectWriter()
	out, handled, aborted := serve(h.c, rec, fetchRequest(t), fetch)
	if _, body, _ := rec.result(); !handled || aborted || out.Result != observability.ResultStale || !bytes.Equal(body, h.pack) {
		t.Fatalf("got %+v handled %v aborted %v, want the stored pack served stale", out, handled, aborted)
	}
	events := h.logs.securityEvents(t, security.EventCacheStaleServed)
	if len(events) != 1 || events[0]["reason"] != staleReasonHeaderTimeout {
		t.Errorf("events = %v, want one with reason %s", events, staleReasonHeaderTimeout)
	}
	if got := len(h.logs.records(t, "fill aborted")); got != 0 {
		t.Errorf("fill aborted logs = %d, want none", got)
	}
}

// TestHeaderTimerFiringAfterAFetchErrorKeepsItsClass: a header timer that
// fires after the fill has claimed a connect failure leaves it a connect
// failure, which opens the gate, rather than a neutral header timeout.
func TestHeaderTimerFiringAfterAFetchErrorKeepsItsClass(t *testing.T) {
	const timeout = 20 * time.Millisecond
	h := newStaleHarness(t, func(o *Options) { o.ResponseHeaderTimeout = timeout })
	h.clock.Advance(10 * time.Minute)
	h.c.hooks.afterFetchFailed = func(entryKey) { <-time.After(5 * timeout) }
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: errDialRefused}); out.Result != observability.ResultStale {
		t.Fatalf("refused fetch = %+v, want stale", out)
	}
	events := h.logs.securityEvents(t, security.EventCacheStaleServed)
	if len(events) != 1 || events[0]["reason"] != staleReasonConnect {
		t.Errorf("events = %v, want one with reason %s", events, staleReasonConnect)
	}
	if !h.c.gates.isOpen(testRepo.Host) {
		t.Error("the refused connection did not open the gate")
	}
}

// TestFetchErrorsLeaveTheKeyUnmarkedWithStaleService: with stale service
// enabled a fetch error, before the body or during it, leaves the key
// cacheable; without it the key is marked as before.
func TestFetchErrorsLeaveTheKeyUnmarkedWithStaleService(t *testing.T) {
	reset := errors.New("read tcp: connection reset by peer")
	for _, stale := range []bool{true, false} {
		h := newStaleHarness(t, func(o *Options) {
			if !stale {
				o.StaleIfErrorFor = 0
			}
		})
		h.clock.Advance(10 * time.Minute)
		if out, handled, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: reset}); handled {
			t.Fatalf("stale %v: reset before headers = %+v, want a release", stale, out)
		}
		midBody := fetchFunc(func(context.Context, Request) (*http.Response, error) {
			resp := response(http.StatusOK, contentTypeResult, nil)
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(h.pack[:40]), iotest.ErrReader(reset)))
			resp.ContentLength = -1
			return resp, nil
		})
		serve(h.c, newCollectWriter(), otherFetchRequest(t), midBody)
		now := h.c.now()
		for name, r := range map[string]*http.Request{"release": fetchRequest(t), "abort": otherFetchRequest(t)} {
			if got := h.c.marks.marked(entryKeyFor(t, h.c, r), now); got == stale {
				t.Errorf("stale %v: key after a fetch error %s marked %v, want %v", stale, name, got, !stale)
			}
		}
		if stale {
			openGate(t, h)
			if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: reset}); out.Result != observability.ResultStale {
				t.Errorf("next request with the gate open = %+v, want stale", out)
			}
		}
	}
}

// TestStaleServiceKeepsOtherMarks: with stale service enabled, truncated
// and oversize responses still mark their keys, and a key marked by a
// rejected credential is relayed to passthrough while the gate is closed.
func TestStaleServiceKeepsOtherMarks(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.MaxEntrySize = 64 << 10 })
	h.clock.Advance(10 * time.Minute)
	truncated := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		resp := response(http.StatusOK, contentTypeResult, h.pack)
		resp.ContentLength = int64(len(h.pack)) + 10
		return resp, nil
	})
	serve(h.c, newCollectWriter(), fetchRequestFor(t, 1), truncated)
	serve(h.c, newCollectWriter(), fetchRequestFor(t, 2), packFetcher(fetchResultBody(t, 20, 5000)))
	now := h.c.now()
	for name, r := range map[string]*http.Request{"truncated": fetchRequestFor(t, 1), "too_large": fetchRequestFor(t, 2)} {
		if !h.c.marks.marked(entryKeyFor(t, h.c, r), now) {
			t.Errorf("%s response left its key unmarked", name)
		}
	}

	rejected := &failing{status: http.StatusBadGateway, header: http.Header{UpstreamStatusHeader: {"401"}}}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), rejected); out.Result != observability.ResultMiss || out.Status != http.StatusBadGateway {
		t.Fatalf("rejected credential = %+v, want the shared 502", out)
	}
	if out, handled, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); handled || out.Result != observability.ResultBypass {
		t.Errorf("503 for a key a 401 marked = %+v handled %v, want passthrough", out, handled)
	}
}

// TestStaleServiceReadsAnUnreachableRemoteTierOnce: when the fill's
// remote read has already failed, stale service does not read the remote
// tier again.
func TestStaleServiceReadsAnUnreachableRemoteTierOnce(t *testing.T) {
	store := newMemBlobStore()
	seedPeer(t, store, remotePack(t))
	c, _, _ := newRemoteTestCache(t, store, enableStale)
	lsRefs(t, c, refsFetcher(t))
	store.set(func(m *memBlobStore) {
		m.getHook = func(key string, _ int64) error {
			if strings.HasPrefix(key, packPrefix) {
				return errors.New("memblob: 503 SlowDown")
			}
			return nil
		}
	})
	before := store.count("get", packPrefix)
	if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
		t.Errorf("fetch with the bucket and upstream failing = %+v, want the shared 503", out)
	}
	if got := store.count("get", packPrefix) - before; got != 1 {
		t.Errorf("remote pack reads = %d, want one", got)
	}
}

// advancingWriter advances clock by step on its first body write.
type advancingWriter struct {
	*collectWriter
	clock *fakeClock
	step  time.Duration
	once  atomic.Bool
}

func (w *advancingWriter) Write(p []byte) (int, error) {
	if w.once.CompareAndSwap(false, true) {
		w.clock.Advance(w.step)
	}
	return w.collectWriter.Write(p)
}

// TestStaleEventAgeIsTakenWhenServingStarts: the event's entryAgeSeconds
// is the entry's age when its response began, not when it finished.
func TestStaleEventAgeIsTakenWhenServingStarts(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(10 * time.Minute)
	w := &advancingWriter{collectWriter: newCollectWriter(), clock: h.clock, step: 5 * time.Minute}
	if out, _, _ := serve(h.c, w, fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
		t.Fatalf("got %+v, want stale", out)
	}
	events := h.logs.securityEvents(t, security.EventCacheStaleServed)
	if len(events) != 1 || events[0]["entryAgeSeconds"] != float64(600) {
		t.Errorf("events = %v, want one with entryAgeSeconds 600", events)
	}
}
