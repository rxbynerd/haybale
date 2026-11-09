package cache

import (
	"context"
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

// seedRepoEntries stores one remote refs and two remote pack entry
// objects for testRepo and returns their keys.
func seedRepoEntries(store *memBlobStore, kr Keyring) []string {
	repoHash := kr.RepoHash(testBaseURL, testRepo)
	var keys []string
	for i, g := range []Group{GroupRefs, GroupPack, GroupPack} {
		k := entryKey{Group: g, RepoHash: repoHash}
		k.KeyHash[0] = byte(i + 1)
		store.store(k.Path(), []byte("sealed"))
		keys = append(keys, k.Path())
	}
	return keys
}

func TestPurgeRepositoryStepFailures(t *testing.T) {
	kr := testKeyring(t)
	markerPath := purgeMarkerPath(kr.RepoHash(testBaseURL, testRepo))
	failing := errors.New("memblob: 503 SlowDown")
	cases := map[string]struct {
		fault       func(m *memBlobStore)
		wantStep    PurgeStep
		wantMarker  bool
		wantRemote  int
		wantDeleted int
	}{
		"the marker read fails": {
			fault: func(m *memBlobStore) {
				m.getHook = func(string, int64) error { return failing }
			},
			wantStep: PurgeStepMarker,
		},
		"the marker write fails": {
			fault: func(m *memBlobStore) {
				m.putHook = func(context.Context, string) error { return failing }
			},
			wantStep: PurgeStepMarker,
		},
		"the listing fails": {
			fault:      func(m *memBlobStore) { m.listErr = failing },
			wantStep:   PurgeStepRemote,
			wantMarker: true,
		},
		"a delete fails part way": {
			fault: func(m *memBlobStore) {
				n := 0
				m.deleteHook = func(context.Context, string) error {
					if n++; n > 1 {
						return failing
					}
					return nil
				}
			},
			wantStep:    PurgeStepRemote,
			wantMarker:  true,
			wantRemote:  1,
			wantDeleted: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			seedRepoEntries(store, kr)
			store.set(tc.fault)
			local := 0
			res, err := PurgeRepository(context.Background(), kr, PurgeRequest{
				Repo: testRepo, BaseURL: testBaseURL, Groups: []Group{GroupRefs, GroupPack}, Now: newFakeClock().Now(),
				Remote:      store,
				DeleteLocal: func(string) (int, error) { local++; return 1, nil },
			})
			var pe *PurgeError
			if !errors.As(err, &pe) || pe.Step != tc.wantStep || !errors.Is(err, failing) {
				t.Fatalf("PurgeRepository = %+v, %v; want a %d step failure", res, err, tc.wantStep)
			}
			if _, ok := store.object(markerPath); ok != tc.wantMarker {
				t.Errorf("marker present = %v, want %v", ok, tc.wantMarker)
			}
			if res.Remote != tc.wantRemote {
				t.Errorf("remote deleted = %d, want %d", res.Remote, tc.wantRemote)
			}
			if got := 3 - len(store.keys("v1/refs/")) - len(store.keys("v1/pack/")); got != tc.wantDeleted {
				t.Errorf("remote objects gone = %d, want %d", got, tc.wantDeleted)
			}
			wantLocal := 2
			if tc.wantStep == PurgeStepMarker {
				wantLocal = 0
			}
			if local != wantLocal {
				t.Errorf("local group deletions = %d, want %d", local, wantLocal)
			}
		})
	}
}

func TestPurgeRepositoryReplacesACorruptMarker(t *testing.T) {
	kr := testKeyring(t)
	store := newMemBlobStore()
	markerPath := purgeMarkerPath(kr.RepoHash(testBaseURL, testRepo))
	store.store(markerPath, []byte("not a sealed marker"))
	now := newFakeClock().Now()
	res, err := PurgeRepository(context.Background(), kr, PurgeRequest{Repo: testRepo, BaseURL: testBaseURL, Groups: []Group{GroupPack}, Now: now, Remote: store})
	if err != nil || !res.MarkerReplaced {
		t.Fatalf("PurgeRepository = %+v, %v; want the marker replaced", res, err)
	}
	times, found, err := readPurgeMarker(context.Background(), store, kr, kr.RepoHash(testBaseURL, testRepo), now)
	if err != nil || !found || !times.pack.Equal(now) || !times.refs.IsZero() {
		t.Errorf("marker = %+v found %v, %v; want pack purged at %v only", times, found, err, now)
	}
}

func TestPurgeMarkerToleratesAKeptTimeFromAFastClock(t *testing.T) {
	kr := testKeyring(t)
	store := newMemBlobStore()
	repoHash := kr.RepoHash(testBaseURL, testRepo)
	now := newFakeClock().Now()
	ahead := now.Add(3 * time.Minute)
	if _, err := purgeRemote(store, kr, []Group{GroupPack}, ahead); err != nil {
		t.Fatal(err)
	}
	if _, err := purgeRemote(store, kr, []Group{GroupRefs}, now); err != nil {
		t.Fatal(err)
	}
	times, found, err := readPurgeMarker(context.Background(), store, kr, repoHash, now)
	if err != nil || !found {
		t.Fatalf("readPurgeMarker: found %v, %v; want the marker to verify", found, err)
	}
	if !times.pack.Equal(ahead) || !times.refs.Equal(now) {
		t.Errorf("marker times = %+v, want pack %v and refs %v", times, ahead, now)
	}
}
