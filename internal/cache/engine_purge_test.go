package cache

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
)

func TestPackHitsLapseWhileTheMarkerCannotBeChecked(t *testing.T) {
	cases := map[string]struct {
		fault   func(store *memBlobStore, markerPath string)
		wantHit bool
	}{
		"the marker is absent": {wantHit: true},
		"the marker read fails": {fault: func(store *memBlobStore, _ string) {
			store.set(func(m *memBlobStore) {
				m.getHook = func(key string, _ int64) error {
					if strings.HasPrefix(key, purgePrefix) {
						return errors.New("memblob: 503 SlowDown")
					}
					return nil
				}
			})
		}},
		"the marker is corrupt": {fault: func(store *memBlobStore, markerPath string) {
			store.store(markerPath, []byte("not a sealed marker"))
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			c, clock, _ := newRemoteTestCache(t, store, nil)
			refs := refsFetcher(t)
			lsRefs(t, c, refs)
			upstream := packFetcher(remotePack(t))
			if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); !out.Stored {
				t.Fatalf("fetch = %+v, want a stored miss", out)
			}
			if tc.fault != nil {
				tc.fault(store, purgeMarkerPath(c.keyring.RepoHash(testBaseURL, testRepo)))
			}

			clock.Advance(4 * time.Minute)
			lsRefs(t, c, refs)
			if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultHit {
				t.Fatalf("fetch within accessRecheck of the last renewal = %+v, want a hit", out)
			}
			clock.Advance(2 * time.Minute)
			lsRefs(t, c, refs)
			out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream)
			if got := out.Result == observability.ResultHit; got != tc.wantHit {
				t.Errorf("fetch past accessRecheck of the first renewal = %+v, want hit %v", out, tc.wantHit)
			}
		})
	}
}

func TestWithoutARemoteTierRefsFillsAlwaysRenewTheAccessRecord(t *testing.T) {
	c, clock := newTestCache(t, nil)
	refs := refsFetcher(t)
	lsRefs(t, c, refs)
	upstream := packFetcher(remotePack(t))
	serve(c, httptest.NewRecorder(), fetchRequest(t), upstream)
	clock.Advance(4 * time.Minute)
	lsRefs(t, c, refs)
	clock.Advance(2 * time.Minute)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultHit {
		t.Errorf("fetch = %+v, want a hit renewed by the second ls-refs", out)
	}
}

func TestMarkerChecksAreCachedForTheInterval(t *testing.T) {
	cases := map[string]struct {
		accessRecheck time.Duration
		interval      time.Duration
	}{
		"default accessRecheck":    {5 * time.Minute, janitorInterval},
		"accessRecheck below that": {30 * time.Second, 30 * time.Second},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			c, clock, _ := newRemoteTestCache(t, store, func(o *Options) { o.AccessRecheck = tc.accessRecheck })
			refs := refsFetcher(t)
			lsRefs(t, c, refs)
			clock.Advance(tc.interval - time.Second)
			lsRefs(t, c, refs)
			if got := store.count("get", purgePrefix); got != 1 {
				t.Errorf("marker reads within the interval = %d, want 1", got)
			}
			clock.Advance(time.Second)
			lsRefs(t, c, refs)
			if got := store.count("get", purgePrefix); got != 2 {
				t.Errorf("marker reads after the interval = %d, want 2", got)
			}
		})
	}
}

func TestConcurrentRefsFillsShareOneMarkerRead(t *testing.T) {
	store := newMemBlobStore()
	release := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.getHook = func(key string, _ int64) error {
			if strings.HasPrefix(key, purgePrefix) {
				<-release
			}
			return nil
		}
	})
	c, _, _ := newRemoteTestCache(t, store, nil)
	refs := refsFetcher(t)
	const fills = 10
	var wg sync.WaitGroup
	errs := make(chan string, fills)
	for range fills {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, handled, aborted := serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), refs)
			if !handled || aborted || out.Result != observability.ResultMiss {
				errs <- "ls-refs was not served"
			}
		}()
	}
	waitFor(t, "every refs fill to start", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.refsFills == fills
	})
	close(release)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if got := store.count("get", purgePrefix); got != 1 {
		t.Errorf("marker reads = %d, want one shared by %d fills", got, fills)
	}
}
