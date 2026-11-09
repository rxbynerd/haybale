package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// newRemoteStaleReplica is a stale-enabled cache on store holding
// testRepo's ls-refs and clone fetch entries on disk, with its clock past
// accessRecheck and the purge marker check interval. Its gate admits no
// probe within the test, so an open gate holds every request.
func newRemoteStaleReplica(t *testing.T, store *memBlobStore) (*Cache, *fakeClock, *logCapture) {
	t.Helper()
	logger, logs := newLogCapture()
	c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
		enableStale(o)
		o.Logger = logger
	})
	c.gates.interval = 24 * time.Hour
	lsRefs(t, c, refsFetcher(t))
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(remotePack(t))); !out.Stored {
		t.Fatalf("seeding fetch = %+v, want a stored miss", out)
	}
	clock.Advance(10 * time.Minute)
	return c, clock, logs
}

// staleReads are the two reads of testRepo whose entries the replica
// holds.
func staleReads(t *testing.T) map[string]func() *http.Request {
	return map[string]func() *http.Request{
		"ls-refs": func() *http.Request { return postV2(lsRefsBody(t)) },
		"fetch":   func() *http.Request { return fetchRequest(t) },
	}
}

// bothGroups purges both groups of a repository.
var bothGroups = []Group{GroupRefs, GroupPack}

// clearMarks forgets every uncacheable mark, so a key whose failed fill
// marked it is offered to the cache again.
func clearMarks(c *Cache) {
	c.marks.mu.Lock()
	defer c.marks.mu.Unlock()
	c.marks.until = nil
}

// markerKey is the remote key of testRepo's purge marker.
func markerKey(c *Cache) string {
	return purgeMarkerPath(c.keyring.RepoHash(testBaseURL, testRepo))
}

// TestStaleServiceRefusesALocallyPurgedEntry: without a remote tier, a
// purge on this replica leaves nothing to serve stale, on the fetch-error
// path and while the gate is open.
func TestStaleServiceRefusesALocallyPurgedEntry(t *testing.T) {
	for _, held := range []bool{false, true} {
		h := newStaleHarness(t, nil)
		if _, err := h.c.Purge(context.Background(), testRepo, testBaseURL, ""); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(10 * time.Minute)
		if held {
			if out, handled, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
				t.Fatalf("refused fetch without an entry = %+v, want a release", out)
			}
		}
		out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{status: 503})
		if out.Result != observability.ResultMiss || out.Status != 503 {
			t.Errorf("held %v: purged key = %+v, want the shared 503", held, out)
		}
		if ev := h.logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
			t.Errorf("held %v: stale events = %d, want none", held, len(ev))
		}
	}
}

// TestStaleServiceRefusesARemoteEntryAMarkerCovers: a remote entry older
// than the repository's purge marker is not served stale and is deleted.
func TestStaleServiceRefusesARemoteEntryAMarkerCovers(t *testing.T) {
	store := newMemBlobStore()
	seedPeer(t, store, remotePack(t))
	packKeys := store.keys(packPrefix)
	if len(packKeys) != 1 {
		t.Fatalf("remote packs = %v, want one", packKeys)
	}
	data, _ := store.object(packKeys[0])
	c, clock, _ := newRemoteTestCache(t, store, enableStale)
	clock.Advance(time.Minute)
	if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now()); err != nil {
		t.Fatal(err)
	}
	store.set(func(m *memBlobStore) { m.objects[packKeys[0]] = memObject{data: data, modTime: clock.Now()} })
	clock.Advance(time.Minute)

	if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 502}); out.Result != observability.ResultMiss || out.Status != 502 {
		t.Errorf("covered remote entry = %+v, want the shared 502", out)
	}
	waitFor(t, "the covered remote entry to be deleted", func() bool { return len(store.keys(packPrefix)) == 0 })
}

// TestHeldStaleServiceReadsTheMarkerFirst: while the gate is open, a
// held request reads the purge marker a peer wrote before answering, so
// entries the marker covers are never served.
func TestHeldStaleServiceReadsTheMarkerFirst(t *testing.T) {
	store := newMemBlobStore()
	c, clock, logs := newRemoteStaleReplica(t, store)
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	if !c.gates.held(testRepo.Host, c.now()) {
		t.Fatal("the refused connection did not open the gate")
	}
	if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(markerCheckInterval(c.opts.AccessRecheck))
	before := store.count("get", purgePrefix)
	for name, req := range staleReads(t) {
		if out, handled, _ := serve(c, newCollectWriter(), req(), &failing{err: errDialRefused}); handled || out.Result == observability.ResultStale {
			t.Errorf("held %s after a peer's purge = %+v handled %v, want a release", name, out, handled)
		}
	}
	if got := store.count("get", purgePrefix) - before; got != 1 {
		t.Errorf("marker reads = %d, want one shared by both requests", got)
	}
	if ev := logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
		t.Errorf("stale events = %d, want none", len(ev))
	}
}

// TestStaleDecisionWaitsForTheMarkerRead: an upstream failure that
// arrives before the purge marker read finishes is decided only once the
// read has, so the first request after a peer's purge is already refused.
func TestStaleDecisionWaitsForTheMarkerRead(t *testing.T) {
	for name, req := range staleReads(t) {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			c, clock, _ := newRemoteStaleReplica(t, store)
			if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now()); err != nil {
				t.Fatal(err)
			}
			failed := make(chan struct{})
			var once sync.Once
			store.set(func(m *memBlobStore) {
				m.getHook = func(key string, _ int64) error {
					if strings.HasPrefix(key, purgePrefix) {
						select {
						case <-failed:
						case <-time.After(shortly):
						}
					}
					return nil
				}
			})
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
				defer once.Do(func() { close(failed) })
				return response(503, "text/plain", []byte("down\n")), nil
			})
			if out, _, _ := serve(c, newCollectWriter(), req(), fetch); out.Result != observability.ResultMiss || out.Status != 503 {
				t.Errorf("first request after the purge = %+v, want the shared 503", out)
			}
		})
	}
}

// TestStaleServiceFailsClosedWithoutACurrentMarkerCheck: a marker read
// that fails, a marker that fails verification, and a check skipped under
// the backoff all leave the request to fail as it would without stale
// service.
func TestStaleServiceFailsClosedWithoutACurrentMarkerCheck(t *testing.T) {
	cases := map[string]func(c *Cache, store *memBlobStore){
		"marker read fails": func(_ *Cache, store *memBlobStore) {
			store.set(func(m *memBlobStore) {
				m.getHook = func(key string, _ int64) error {
					if strings.HasPrefix(key, purgePrefix) {
						return errors.New("memblob: 503 SlowDown")
					}
					return nil
				}
			})
		},
		"marker fails verification": func(c *Cache, store *memBlobStore) {
			store.set(func(m *memBlobStore) { m.objects[markerKey(c)] = memObject{data: []byte("not a sealed marker")} })
		},
	}
	for name, fault := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			c, clock, logs := newRemoteStaleReplica(t, store)
			fault(c, store)
			for read, req := range staleReads(t) {
				if out, _, _ := serve(c, newCollectWriter(), req(), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
					t.Errorf("%s = %+v, want the shared 503", read, out)
				}
			}
			// Within the backoff no marker is read and nothing is served
			// stale, even once the fault has cleared.
			store.set(func(m *memBlobStore) {
				m.getHook = nil
				delete(m.objects, markerKey(c))
			})
			clearMarks(c)
			clock.Advance(time.Second)
			before := store.count("get", purgePrefix)
			for read, req := range staleReads(t) {
				if out, _, _ := serve(c, newCollectWriter(), req(), &failing{status: 503}); out.Result != observability.ResultMiss || out.Status != 503 {
					t.Errorf("%s under the backoff = %+v, want the shared 503", read, out)
				}
			}
			if got := store.count("get", purgePrefix) - before; got != 0 {
				t.Errorf("marker reads under the backoff = %d, want none", got)
			}
			if ev := logs.securityEvents(t, security.EventCacheStaleServed); len(ev) != 0 {
				t.Errorf("stale events = %d, want none", len(ev))
			}
			clearMarks(c)
			clock.Advance(purgeCheckBackoff)
			if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{status: 503}); out.Result != observability.ResultStale {
				t.Errorf("fetch after the backoff = %+v, want stale", out)
			}
		})
	}
}

// TestStaleServiceWithACurrentMarkerCheck: with no marker, or one older
// than the entries, stale service answers; a check that succeeded within
// the interval is reused, and concurrent checks share one read.
func TestStaleServiceWithACurrentMarkerCheck(t *testing.T) {
	t.Run("no marker", func(t *testing.T) {
		store := newMemBlobStore()
		c, _, _ := newRemoteStaleReplica(t, store)
		before := store.count("get", purgePrefix)
		for read, req := range staleReads(t) {
			if out, _, _ := serve(c, newCollectWriter(), req(), &failing{status: 503}); out.Result != observability.ResultStale {
				t.Errorf("%s = %+v, want stale", read, out)
			}
		}
		if got := store.count("get", purgePrefix) - before; got != 1 {
			t.Errorf("marker reads = %d, want one reused by the second request", got)
		}
	})

	t.Run("marker older than the entries", func(t *testing.T) {
		store := newMemBlobStore()
		c, clock, _ := newRemoteStaleReplica(t, store)
		if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		for read, req := range staleReads(t) {
			if out, _, _ := serve(c, newCollectWriter(), req(), &failing{status: 503}); out.Result != observability.ResultStale {
				t.Errorf("%s = %+v, want stale", read, out)
			}
		}
	})

	t.Run("concurrent checks share one read", func(t *testing.T) {
		store := newMemBlobStore()
		c, _, _ := newRemoteStaleReplica(t, store)
		release := make(chan struct{})
		store.set(func(m *memBlobStore) {
			m.getHook = func(key string, _ int64) error {
				if strings.HasPrefix(key, purgePrefix) {
					select {
					case <-release:
					case <-time.After(shortly):
					}
				}
				return nil
			}
		})
		before := store.count("get", purgePrefix)
		const clients = 10
		fetch := &failing{status: 503}
		reqs := make([]*http.Request, clients)
		for i := range reqs {
			reqs[i] = postV2(lsRefsBody(t))
		}
		results := make(chan Outcome, clients)
		for _, r := range reqs {
			go func() {
				out, _, _ := serve(c, newCollectWriter(), r, fetch)
				results <- out
			}()
		}
		waitFor(t, "every refs fill to reach upstream", func() bool { return fetch.count() == clients })
		waitFor(t, "the marker read to start", func() bool { return store.count("get", purgePrefix)-before == 1 })
		close(release)
		for range clients {
			if out := receive(t, results, "an ls-refs request"); out.Result != observability.ResultStale {
				t.Errorf("ls-refs = %+v, want stale", out)
			}
		}
		if got := store.count("get", purgePrefix) - before; got != 1 {
			t.Errorf("marker reads = %d, want one shared read", got)
		}
	})
}

// TestHeldStaleServiceWaitsAtMostTheMarkerTimeout: a held request whose
// marker read hangs gives up at the marker timeout and is not answered
// stale.
func TestHeldStaleServiceWaitsAtMostTheMarkerTimeout(t *testing.T) {
	store := newMemBlobStore()
	c, clock, _ := newRemoteStaleReplica(t, store)
	c.markerTimeout = 50 * time.Millisecond
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, _ int64, body io.Reader) io.Reader {
			if !strings.HasPrefix(key, purgePrefix) {
				return body
			}
			<-ctx.Done()
			return iotest.ErrReader(ctx.Err())
		}
	})
	clock.Advance(markerCheckInterval(c.opts.AccessRecheck))
	start := time.Now()
	out, handled, _ := serve(c, newCollectWriter(), fetchRequest(t), &failing{err: errDialRefused})
	if elapsed := time.Since(start); elapsed > shortly {
		t.Errorf("held request took %v, want it bounded by the marker timeout", elapsed)
	}
	if handled || out.Result == observability.ResultStale {
		t.Errorf("held request with a hung marker read = %+v handled %v, want a release", out, handled)
	}
}

// TestProbeWithoutACurrentMarkerCheckWaitsForUpstream: a probe whose
// purge marker cannot be read is not answered stale at its deadline; it
// waits for upstream and, once the header timeout cuts that, is released.
func TestProbeWithoutACurrentMarkerCheckWaitsForUpstream(t *testing.T) {
	const interval = 50 * time.Millisecond
	store := newMemBlobStore()
	c, clock, _ := newRemoteStaleReplica(t, store)
	c.gates.interval = interval
	c.opts.ResponseHeaderTimeout = 4 * interval
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	store.set(func(m *memBlobStore) {
		m.getHook = func(key string, _ int64) error {
			if strings.HasPrefix(key, purgePrefix) {
				return errors.New("memblob: 503 SlowDown")
			}
			return nil
		}
	})
	clock.Advance(markerCheckInterval(c.opts.AccessRecheck))
	deadlines := probeDeadlines(c)
	hang := newHangingFetch()
	done := make(chan served, 1)
	r := fetchRequest(t)
	start := time.Now()
	go func() {
		out, handled, _ := serve(c, newCollectWriter(), r, hang)
		done <- served{out: out, handled: handled}
	}()
	if awaitDeadline(t, deadlines) {
		t.Fatal("a probe without a current marker check was answered stale")
	}
	select {
	case res := <-done:
		t.Fatalf("probe finished at the deadline: %+v", res.out)
	default:
	}
	res := receive(t, done, "the probe")
	if res.handled || res.out.Result == observability.ResultStale {
		t.Errorf("probe = %+v handled %v, want a release", res.out, res.handled)
	}
	if elapsed := time.Since(start); elapsed < c.opts.ResponseHeaderTimeout {
		t.Errorf("probe finished after %v, want it to wait the %v header timeout", elapsed, c.opts.ResponseHeaderTimeout)
	}
}

// TestSharedMarkerReadOutlivesALeaderThatLeaves: a held request that
// leads the purge marker read and then disconnects neither cuts the read
// short nor fails it for a refs fill waiting on the same read, which still
// learns the purge state is current and renews the access record.
func TestSharedMarkerReadOutlivesALeaderThatLeaves(t *testing.T) {
	store := newMemBlobStore()
	c, clock, _ := newRemoteStaleReplica(t, store)
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	markerRead := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, _ int64, body io.Reader) io.Reader {
			if strings.HasPrefix(key, purgePrefix) {
				select {
				case <-markerRead:
				case <-ctx.Done():
				}
			}
			return body
		}
	})
	joined := make(chan struct{}, 1)
	c.hooks.markerCheckJoined = func() { joined <- struct{}{} }
	clock.Advance(markerCheckInterval(c.opts.AccessRecheck))
	repoHash := c.keyring.RepoHash(testBaseURL, testRepo)
	if c.access.recent(repoHash, c.now()) {
		t.Fatal("the access record is still recent before the refs fill")
	}

	before := store.count("get", purgePrefix)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leader := fetchRequest(t).WithContext(ctx)
	left := make(chan struct{})
	go func() {
		defer close(left)
		serve(c, newCollectWriter(), leader, &failing{status: 503})
	}()
	waitFor(t, "the held request's marker read to start", func() bool { return store.count("get", purgePrefix)-before == 1 })

	c.gates.report(testRepo.Host, classifyStatus(http.StatusOK), c.now(), c.now())
	refsDone := make(chan Outcome, 1)
	refsReq := postV2(lsRefsBody(t))
	go func() {
		out, _, _ := serve(c, newCollectWriter(), refsReq, refsFetcher(t))
		refsDone <- out
	}()
	select {
	case <-joined:
	case <-time.After(shortly):
		t.Fatal("the refs fill never joined the marker read")
	}
	cancel()
	select {
	case <-left:
	case <-time.After(shortly):
		t.Fatal("the leaving request was never answered")
	}
	close(markerRead)
	select {
	case out := <-refsDone:
		if out.Result != observability.ResultMiss || out.Status != http.StatusOK {
			t.Errorf("refs fill = %+v, want an upstream miss", out)
		}
	case <-time.After(shortly):
		t.Fatal("the refs fill never finished")
	}
	if !c.access.recent(repoHash, c.now()) {
		t.Error("the refs fill did not renew the access record")
	}
	if got := store.count("get", purgePrefix) - before; got != 1 {
		t.Errorf("marker reads = %d, want the one shared read", got)
	}
	c.purges.mu.Lock()
	_, backoff := c.purges.failed[repoHash]
	c.purges.mu.Unlock()
	if backoff {
		t.Error("the leaving request started the marker backoff")
	}
}

// gatedWriter blocks its first Write until open is closed, and closes
// writing once that Write has begun.
type gatedWriter struct {
	*collectWriter
	writing chan struct{}
	open    chan struct{}
	once    sync.Once
}

func newGatedWriter() *gatedWriter {
	return &gatedWriter{collectWriter: newCollectWriter(), writing: make(chan struct{}), open: make(chan struct{})}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.writing) })
	<-w.open
	return w.collectWriter.Write(p)
}

// TestHeldRequestsFreeTheirClassificationSlot: a held request gives up
// its classification slot before it waits on the purge marker read, and
// holds none while its stale answer streams.
func TestHeldRequestsFreeTheirClassificationSlot(t *testing.T) {
	store := newMemBlobStore()
	c, clock, _ := newRemoteStaleReplica(t, store)
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	if _, err := purgeRemote(store, c.keyring, bothGroups, clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	markerRead := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, _ int64, body io.Reader) io.Reader {
			if strings.HasPrefix(key, purgePrefix) {
				select {
				case <-markerRead:
				case <-ctx.Done():
				}
			}
			return body
		}
	})
	clock.Advance(markerCheckInterval(c.opts.AccessRecheck))
	before := store.count("get", purgePrefix)
	w := newGatedWriter()
	r := fetchRequest(t)
	done := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(c, w, r, &failing{err: errDialRefused})
		done <- out
	}()
	waitFor(t, "the marker read to start", func() bool { return store.count("get", purgePrefix)-before == 1 })
	if n := len(c.classifySlots); n != 0 {
		t.Errorf("classification slots held during the marker read = %d, want 0", n)
	}
	close(markerRead)
	select {
	case <-w.writing:
	case <-time.After(shortly):
		t.Fatal("the held answer never started streaming")
	}
	if n := len(c.classifySlots); n != 0 {
		t.Errorf("classification slots held while streaming = %d, want 0", n)
	}
	close(w.open)
	select {
	case out := <-done:
		if out.Result != observability.ResultStale {
			t.Errorf("held request = %+v, want stale", out)
		}
	case <-time.After(shortly):
		t.Fatal("the held request never finished")
	}
}
