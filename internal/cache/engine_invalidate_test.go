package cache

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
)

func TestInvalidateDeletesTheRemoteRefsBeforeReturning(t *testing.T) {
	store := newMemBlobStore()
	peer := seedPeerWith(t, store, remotePack(t), withRefsMaxAge)
	peer.Invalidate(context.Background(), testRepo, testBaseURL)
	if got := store.keys(refsPrefix); len(got) != 0 {
		t.Errorf("remote refs objects when Invalidate returned = %v, want none", got)
	}
}

func TestAPushingReplicaDoesNotServePrePushRefsLeftInTheBucket(t *testing.T) {
	store := newMemBlobStore()
	seedPeerWith(t, store, remotePack(t), withRefsMaxAge)
	store.set(func(m *memBlobStore) {
		m.deleteHook = func(context.Context, string) error { return errors.New("memblob: 503 SlowDown") }
	})
	c, _, reader := newRemoteTestCache(t, store, withRefsMaxAge)
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	if got := store.keys(refsPrefix); len(got) != 1 {
		t.Fatalf("remote refs objects = %v, want the one whose deletion failed", got)
	}
	if got := remoteStoreErrors(t, reader, observability.OperationDelete); got != 1 {
		t.Errorf("store_errors{operation=delete} = %d, want 1", got)
	}
	refs := refsFetcher(t)
	if out := lsRefs(t, c, refs); refs.calls.Load() != 1 || out.Result != observability.ResultMiss {
		t.Errorf("ls-refs after the push = %+v upstream %d, want an upstream miss", out, refs.calls.Load())
	}
	if n := store.count("delete", refsPrefix); n != 1 {
		t.Errorf("remote refs deletes = %d, want only the push's", n)
	}
}

func TestRemoteRefsEntriesAreJudgedAgainstThePushTime(t *testing.T) {
	c, clock, _ := newRemoteTestCache(t, newMemBlobStore(), withRefsMaxAge)
	repoHash := c.keyring.RepoHash(testBaseURL, testRepo)
	pushAt := clock.Now()
	c.gens.bump(repoHash, pushAt)
	clock.Advance(10 * time.Second)
	f := &fill{c: c, key: entryKey{Group: GroupRefs, RepoHash: repoHash}}
	for _, tc := range []struct {
		createdAt time.Time
		want      bool
	}{
		{pushAt.Add(-time.Second), false},
		{pushAt, false},
		{pushAt.Add(time.Second), true},
	} {
		if got := f.remoteFresh(entryHeader{CreatedAt: tc.createdAt}); got != tc.want {
			t.Errorf("remoteFresh(created %s relative to the push) = %v, want %v", tc.createdAt.Sub(pushAt), got, tc.want)
		}
	}
}

func TestInvalidateIsBoundedByTheHeaderTimeout(t *testing.T) {
	store := newMemBlobStore()
	const headerTimeout = 100 * time.Millisecond
	c, _, _ := newRemoteTestCache(t, store, func(o *Options) { o.RemoteHeaderTimeout = headerTimeout })
	repoHash := c.keyring.RepoHash(testBaseURL, testRepo)
	store.store(entryKey{Group: GroupRefs, RepoHash: repoHash}.Path(), []byte("x"))
	store.set(func(m *memBlobStore) {
		m.deleteHook = func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		}
	})
	start := time.Now()
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	if elapsed := time.Since(start); elapsed > 20*headerTimeout {
		t.Errorf("Invalidate against a stalled store took %s, want about the header timeout %s", elapsed, headerTimeout)
	}
}

func TestARefsUploadInFlightAcrossAPushLeavesNoObject(t *testing.T) {
	store := newMemBlobStore()
	release := make(chan struct{})
	var putting atomic.Bool
	store.set(func(m *memBlobStore) {
		m.putHook = func(_ context.Context, key string) error {
			if strings.HasPrefix(key, refsPrefix) {
				putting.Store(true)
				<-release
			}
			return nil
		}
	})
	c, _, reader := newRemoteTestCache(t, store, withRefsMaxAge)
	lsRefs(t, c, refsFetcher(t))
	waitFor(t, "the refs upload to start", putting.Load)
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	close(release)
	waitFor(t, "the upload to finish", func() bool {
		return uploadsWith(t, reader, observability.UploadResultSkipped) == 1
	})
	if got := store.keys(refsPrefix); len(got) != 0 {
		t.Errorf("remote refs objects = %v, want the superseded upload deleted", got)
	}
}

func TestAFailedInvalidationIsNotLoggedAsDone(t *testing.T) {
	store := newMemBlobStore()
	logger, logs := newLogCapture()
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	store.set(func(m *memBlobStore) { m.listErr = errors.New("memblob: 503 SlowDown") })
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	if got := remoteStoreErrors(t, reader, observability.OperationList); got != 1 {
		t.Errorf("store_errors{operation=list} = %d, want 1", got)
	}
	if got := logs.records(t, "cache: invalidated remote refs entries after a push"); len(got) != 0 {
		t.Errorf("success records = %v, want none after a failed listing", got)
	}
}

func TestBackgroundDeletesCutShortByCloseRecordNothing(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	var deleting atomic.Bool
	store.set(func(m *memBlobStore) {
		m.deleteHook = func(ctx context.Context, _ string) error {
			deleting.Store(true)
			<-ctx.Done()
			return ctx.Err()
		}
	})
	logger, logs := newLogCapture()
	c, clock, reader := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	clock.Advance(25 * time.Hour)
	lsRefs(t, c, refsFetcher(t))
	serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack))
	waitFor(t, "the expiry delete to start", deleting.Load)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); err == nil {
		t.Fatal("Close returned nil with a delete blocked")
	}
	waitFor(t, "the delete to end", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.remoteTasks) == 0
	})
	if got := remoteStoreErrors(t, reader, observability.OperationDelete); got != 0 {
		t.Errorf("store_errors{operation=delete} = %d, want none for a delete Close cancelled", got)
	}
	if got := logs.records(t, "remote cache tier operation failed"); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}
