package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// TestCancelledFillsDoNotOpenTheGate: a dial cut short because every
// subscriber left, or because the cache closed, says nothing about
// upstream, so it opens no gate and serves nothing stale.
func TestCancelledFillsDoNotOpenTheGate(t *testing.T) {
	for _, viaClose := range []bool{false, true} {
		h := newStaleHarness(t, nil)
		h.c.idleGrace = time.Millisecond
		h.clock.Advance(10 * time.Minute)
		called := make(chan struct{}, 1)
		dial := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
			called <- struct{}{}
			<-ctx.Done()
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
		})
		ctx, cancel := context.WithCancel(context.Background())
		r := fetchRequest(t).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			serve(h.c, newCollectWriter(), r, dial)
		}()
		select {
		case <-called:
		case <-time.After(shortly):
			t.Fatal("the fill never reached upstream")
		}
		if viaClose {
			closeCtx, stop := context.WithTimeout(context.Background(), shortly)
			if err := h.c.Close(closeCtx); err != nil {
				t.Errorf("Close: %v", err)
			}
			stop()
		} else {
			cancel()
		}
		select {
		case <-done:
		case <-time.After(shortly):
			t.Fatal("the request never returned")
		}
		cancel()
		waitFor(t, "the fill to end", func() bool {
			h.c.mu.Lock()
			defer h.c.mu.Unlock()
			return len(h.c.fills) == 0
		})
		if got := len(h.logs.records(t, gateOpenedMsg)); got != 0 {
			t.Errorf("close %v: gate opened logs = %d, want none", viaClose, got)
		}
		if ev := h.logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
			t.Errorf("close %v: stale events = %d, want none", viaClose, len(ev))
		}
		if h.c.gates.held(testRepo.Host, h.c.now()) {
			t.Errorf("close %v: the next request would be held", viaClose)
		}
	}
}

// TestStaleServiceAgeBoundaries: on either tier, an entry exactly
// staleIfErrorFor old is served and one a tick older is not; with
// staleIfErrorFor equal to retention, an entry past it is deleted.
func TestStaleServiceAgeBoundaries(t *testing.T) {
	t.Run("exactly staleIfErrorFor", func(t *testing.T) {
		h := newStaleHarness(t, nil)
		h.clock.Advance(testStaleFor)
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
			t.Errorf("entry at the bound = %+v, want stale", out)
		}
	})
	t.Run("a tick over staleIfErrorFor", func(t *testing.T) {
		h := newStaleHarness(t, nil)
		h.clock.Advance(testStaleFor + time.Nanosecond)
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
			t.Errorf("entry past the bound = %+v, want the shared 503", out)
		}
	})
	for _, tc := range []struct {
		name   string
		age    time.Duration
		served bool
	}{
		{"tier 2 exactly staleIfErrorFor", testStaleFor, true},
		{"tier 2 a tick over staleIfErrorFor", testStaleFor + time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemBlobStore()
			seedPeer(t, store, remotePack(t))
			c, clock, _ := newRemoteTestCache(t, store, enableStale)
			clock.Advance(tc.age)
			out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 502})
			switch {
			case tc.served && out.Result != observability.ResultStale:
				t.Errorf("remote entry at the bound = %+v, want stale", out)
			case !tc.served && (out.Result != observability.ResultMiss || out.Status != 502):
				t.Errorf("remote entry past the bound = %+v, want the shared 502", out)
			}
		})
	}
	t.Run("tier 1 past retention", func(t *testing.T) {
		h := newStaleHarness(t, func(o *Options) { o.Retention = testStaleFor })
		h.clock.Advance(testStaleFor)
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
			t.Fatalf("entry at retention = %+v, want stale", out)
		}
		h.clock.Advance(time.Nanosecond)
		before := len(entryFiles(t, h.c.opts.Dir))
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss {
			t.Errorf("entry past retention = %+v, want the shared 503", out)
		}
		if after := len(entryFiles(t, h.c.opts.Dir)); after != before-1 {
			t.Errorf("entry files = %d after, %d before; want the expired pack deleted", after, before)
		}
	})
	t.Run("tier 2 past retention", func(t *testing.T) {
		store := newMemBlobStore()
		seedPeer(t, store, remotePack(t))
		c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
			enableStale(o)
			o.Retention = testStaleFor
		})
		clock.Advance(testStaleFor + time.Nanosecond)
		if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 502}); out.Result != observability.ResultMiss || out.Status != 502 {
			t.Errorf("remote entry past retention = %+v, want the shared 502", out)
		}
		waitFor(t, "the expired remote entry to be deleted", func() bool { return len(store.keys(packPrefix)) == 0 })
	})
}

// TestStaleFallbackWhenTheEntryGoesAfterTheDecision: when the entry a fill
// chose to serve stale is gone by the time its subscribers open it, a 5xx
// is relayed as the shared response and a refused connection is released
// to passthrough.
func TestStaleFallbackWhenTheEntryGoesAfterTheDecision(t *testing.T) {
	cases := map[string]struct {
		fetch   *failing
		handled bool
		status  int
	}{
		"503":     {fetch: &failing{status: 503}, handled: true, status: 503},
		"refused": {fetch: &failing{err: errDialRefused}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newStaleHarness(t, nil)
			h.clock.Advance(10 * time.Minute)
			h.c.hooks.beforeStaleOutcome = func(entryKey) {
				if _, err := h.c.Purge(context.Background(), testRepo, testBaseURL, ""); err != nil {
					t.Error(err)
				}
			}
			out, handled, _ := serve(h.c, newCollectWriter(), fetchRequest(t), tc.fetch)
			if handled != tc.handled || out.Status != tc.status || out.Result == observability.ResultStale {
				t.Errorf("got %+v handled %v, want handled %v status %d", out, handled, tc.handled, tc.status)
			}
			if ev := h.logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
				t.Errorf("stale events = %d, want none", len(ev))
			}
		})
	}
}

// TestRemoteStaleReadFailures: a remote read that fails leaves the shared
// 5xx, and a remote entry that fails verification after its first segment
// aborts the response, raises the integrity event and is deleted.
func TestRemoteStaleReadFailures(t *testing.T) {
	t.Run("get fails", func(t *testing.T) {
		store := newMemBlobStore()
		seedPeer(t, store, remotePack(t))
		logger, logs := newLogCapture()
		c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
			enableStale(o)
			o.Logger = logger
		})
		clock.Advance(time.Minute)
		store.set(func(m *memBlobStore) {
			m.getHook = func(key string, _ int64) error {
				if strings.HasPrefix(key, packPrefix) {
					return errors.New("memblob: 500 InternalError")
				}
				return nil
			}
		})
		if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
			t.Errorf("got %+v, want the shared 503", out)
		}
		if ev := logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
			t.Errorf("stale events = %d, want none", len(ev))
		}
	})
	t.Run("verification fails mid-spool", func(t *testing.T) {
		store := newMemBlobStore()
		seedPeer(t, store, remotePack(t))
		logger, logs := newLogCapture()
		c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
			enableStale(o)
			o.Logger = logger
		})
		clock.Advance(time.Minute)
		store.set(func(m *memBlobStore) {
			m.wrapBody = func(_ context.Context, key string, _ int64, body io.Reader) io.Reader {
				if !strings.HasPrefix(key, packPrefix) {
					return body
				}
				data, _ := io.ReadAll(body)
				data[3*segmentSize/2] ^= 0xff
				return bytes.NewReader(data)
			}
		})
		out, handled, aborted := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 503})
		if !aborted && handled {
			t.Errorf("got %+v handled %v, want the response aborted", out, handled)
		}
		// The subscriber can meet the corrupt segment in the spool before
		// the fill does, so the fill's verdict is awaited.
		waitFor(t, "the corrupt remote entry to be deleted", func() bool { return len(store.keys(packPrefix)) == 0 })
		assertStoreIdle(t, c)
		if ev := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(ev) != 1 {
			t.Errorf("integrity events = %d, want 1", len(ev))
		}
		if ev := logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
			t.Errorf("stale events = %d, want none", len(ev))
		}
	})
}

// TestRemoteStaleSpoolFailurePublishesTheFallback: when a qualifying
// remote copy cannot be spooled, subscribers receive the answer stale
// service would have replaced: the shared 5xx, or a release to
// passthrough after a refused connection.
func TestRemoteStaleSpoolFailurePublishesTheFallback(t *testing.T) {
	cases := map[string]struct {
		fetch   *failing
		handled bool
		status  int
	}{
		"503":     {fetch: &failing{status: 503}, handled: true, status: 503},
		"refused": {fetch: &failing{err: errDialRefused}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			seedPeer(t, store, remotePack(t))
			logger, logs := newLogCapture()
			c, clock, reader := newRemoteTestCache(t, store, func(o *Options) {
				enableStale(o)
				o.Logger = logger
				// The remote copy is larger than the whole disk budget, so
				// its spool cannot be created.
				o.MaxDiskSize, o.MaxEntrySize = 64<<10, 32<<10
			})
			clock.Advance(time.Minute)
			out, handled, _ := serve(c, newCollectWriter(), fetchRequest(t), tc.fetch)
			if handled != tc.handled || out.Status != tc.status || out.Result == observability.ResultStale {
				t.Errorf("got %+v handled %v, want handled %v status %d", out, handled, tc.handled, tc.status)
			}
			if n := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonDiskBudget); n != 1 {
				t.Errorf("disk_budget fills = %d, want 1", n)
			}
			if ev := logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
				t.Errorf("stale events = %d, want none", len(ev))
			}
			assertStoreIdle(t, c)
		})
	}
}

// TestStaleServiceRecordsTheFillAndLeavesTheKeyCacheable: a 5xx answered
// stale records a discarded fill with reason upstream_status and marks
// nothing.
func TestStaleServiceRecordsTheFillAndLeavesTheKeyCacheable(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(10 * time.Minute)
	before := fillsWithReason(t, h.reader, observability.FillResultDiscarded, observability.FillReasonUpstreamStatus)
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
		t.Fatalf("got %+v, want stale", out)
	}
	if got := fillsWithReason(t, h.reader, observability.FillResultDiscarded, observability.FillReasonUpstreamStatus) - before; got != 1 {
		t.Errorf("discarded upstream_status fills = %d, want 1", got)
	}
	if h.c.marks.marked(entryKeyFor(t, h.c, fetchRequest(t)), h.c.now()) {
		t.Error("the key is marked uncacheable after a stale answer")
	}
}

// TestStaleServiceWithoutExposeStatus: a stale response carries no
// Cache-Status when the cache does not expose it.
func TestStaleServiceWithoutExposeStatus(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.ExposeStatus = false })
	h.clock.Advance(10 * time.Minute)
	rec := newCollectWriter()
	if out, _, _ := serve(h.c, rec, fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
		t.Fatalf("got %+v, want stale", out)
	}
	if got := rec.Header().Get("Cache-Status"); got != "" {
		t.Errorf("Cache-Status = %q, want none", got)
	}
}

// TestStaleServiceAfterAPush: a push deletes the refs entries, so ls-refs
// is not answered stale in a later outage, while the stored pack still
// is.
func TestStaleServiceAfterAPush(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.c.Invalidate(context.Background(), testRepo, testBaseURL)
	h.clock.Advance(10 * time.Minute)
	if out, handled, _ := serve(h.c, newCollectWriter(), postV2(lsRefsBody(t)), &failing{err: errDialRefused}); handled || out.Result == observability.ResultStale {
		t.Errorf("ls-refs after a push = %+v handled %v, want a release", out, handled)
	}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: errDialRefused}); out.Result != observability.ResultStale {
		t.Errorf("fetch after a push = %+v, want stale", out)
	}
}

// TestStaleServiceAnswersUnreadable5xxBodies: a 5xx whose body cannot be
// read, or is larger than the shared limit, is still answered stale.
func TestStaleServiceAnswersUnreadable5xxBodies(t *testing.T) {
	bodies := map[string]func() io.ReadCloser{
		"read fails":            func() io.ReadCloser { return io.NopCloser(iotest.ErrReader(errors.New("connection reset"))) },
		"over the shared limit": func() io.ReadCloser { return io.NopCloser(bytes.NewReader(make([]byte, sharedBodyLimit+1))) },
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			h := newStaleHarness(t, nil)
			h.clock.Advance(10 * time.Minute)
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
				resp := response(503, "text/plain", nil)
				resp.Body, resp.ContentLength = body(), -1
				return resp, nil
			})
			rec := newCollectWriter()
			out, _, _ := serve(h.c, rec, fetchRequest(t), fetch)
			if _, got, _ := rec.result(); out.Result != observability.ResultStale || !bytes.Equal(got, h.pack) {
				t.Errorf("got %+v, want the stored pack served stale", out)
			}
		})
	}
}

// TestRemoteStaleStreamLogsTheEventWhenTheClientLeaves: a client that
// disconnects partway through a remote stale stream is still recorded as
// served stale.
func TestRemoteStaleStreamLogsTheEventWhenTheClientLeaves(t *testing.T) {
	store := newMemBlobStore()
	seedPeer(t, store, remotePack(t))
	logger, logs := newLogCapture()
	metrics, reader := observability.NewTestMetrics()
	c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
		enableStale(o)
		o.Logger = logger
		o.Metrics = metrics
	})
	clock.Advance(time.Minute)
	w := newFailAfterWriter(1000)
	out, handled, _ := serve(c, w, fetchRequest(t), &failing{status: 503})
	if !handled || out.Result != observability.ResultStale {
		t.Fatalf("got %+v handled %v, want a stale answer the client left", out, handled)
	}
	ev := logs.securityEvents(t, security.EventCacheStaleServed)
	if len(ev) != 1 || ev[0]["tier"] != observability.TierRemote {
		t.Errorf("events = %v, want one for the remote tier", ev)
	}
	if got := lookups(t, reader, observability.ResultStale); got != 1 {
		t.Errorf("stale lookups = %d, want 1", got)
	}
}
