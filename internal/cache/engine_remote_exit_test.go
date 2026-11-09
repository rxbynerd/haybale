package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// readerFunc adapts a function to io.Reader.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// newRemoteFillCase seeds store through a peer and returns a second
// cache, with its logs captured, whose ls-refs has made the peer's pack
// eligible, together with the pack, its remote key and a counter of
// discarded fills by reason. prepare runs after seeding and before the
// second cache's first request.
func newRemoteFillCase(t *testing.T, store *memBlobStore, prepare func(key string, data []byte)) (*Cache, *logCapture, []byte, string, func(reason string) int64) {
	t.Helper()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	if prepare != nil {
		data, _ := store.object(key)
		prepare(key, bytes.Clone(data))
	}
	logger, logs := newLogCapture()
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	lsRefs(t, c, refsFetcher(t))
	discarded := func(reason string) int64 {
		return fillsWithReason(t, reader, observability.FillResultDiscarded, reason)
	}
	return c, logs, pack, key, discarded
}

// assertNoPackStored fails the test when c holds a pack entry.
func assertNoPackStored(t *testing.T, c *Cache) {
	t.Helper()
	for _, f := range entryFiles(t, c.opts.Dir) {
		if strings.HasPrefix(f, packPrefix) {
			t.Errorf("pack entry %s was stored", f)
		}
	}
}

func TestRemoteShortReadsPastTheResumesAreAFetchError(t *testing.T) {
	store := newMemBlobStore()
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, func(key string, _ []byte) {
		store.set(func(m *memBlobStore) {
			m.wrapBody = func(_ context.Context, k string, offset int64, body io.Reader) io.Reader {
				switch {
				case k != key:
					return body
				case offset == 0:
					return io.LimitReader(body, 80000)
				default:
					return io.LimitReader(body, 0)
				}
			}
		})
	})
	_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if !aborted {
		t.Fatal("the response was not aborted after the remote read could not continue")
	}
	assertStoreIdle(t, c)
	if got := discarded(observability.FillReasonFetchError); got != 1 {
		t.Errorf("fills discarded with fetch_error = %d, want 1", got)
	}
	if got := discarded(observability.FillReasonStoreError); got != 0 {
		t.Errorf("fills discarded with store_error = %d, want 0", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 0 {
		t.Errorf("integrity events = %v, want none for a short read", got)
	}
	if n := store.count("delete", key); n != 0 {
		t.Errorf("remote deletes of the object = %d, want none", n)
	}
	if _, ok := store.object(key); !ok {
		t.Error("the remote object was removed")
	}
	assertNoPackStored(t, c)
}

func TestRemoteObjectTruncatedAtRestIsAnIntegrityFailure(t *testing.T) {
	store := newMemBlobStore()
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, func(key string, data []byte) {
		store.store(key, data[:len(data)-frameLen-trailerCTLen])
	})
	_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if !aborted {
		t.Fatal("a remote entry missing its trailer did not abort the response")
	}
	assertStoreIdle(t, c)
	if got := discarded(observability.FillReasonStoreError); got != 1 {
		t.Errorf("fills discarded with store_error = %d, want 1", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 1 || got[0]["tier"] != observability.TierRemote {
		t.Errorf("integrity events = %v, want one for the remote tier", got)
	}
	if _, ok := store.object(key); ok {
		t.Error("the truncated remote object was not deleted")
	}
	assertNoPackStored(t, c)
}

func TestRemoteResumeGetFailuresUseTheResumes(t *testing.T) {
	store := newMemBlobStore()
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, func(key string, _ []byte) {
		store.set(func(m *memBlobStore) {
			m.wrapBody = func(_ context.Context, k string, offset int64, body io.Reader) io.Reader {
				if k == key && offset == 0 {
					return cutReader(body, 80000)
				}
				return body
			}
			m.getHook = func(k string, offset int64) error {
				if k == key && offset > 0 {
					return fmt.Errorf("memblob: 503 SlowDown")
				}
				return nil
			}
		})
	})
	_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if !aborted {
		t.Fatal("the response was not aborted after every resume Get failed")
	}
	assertStoreIdle(t, c)
	if got := store.getOffsets(key); fmt.Sprint(got) != "[0 80000 80000 80000]" {
		t.Errorf("remote Get offsets = %v, want the first Get and three resumes", got)
	}
	if got := discarded(observability.FillReasonFetchError); got != 1 {
		t.Errorf("fills discarded with fetch_error = %d, want 1", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 0 {
		t.Errorf("integrity events = %v, want none", got)
	}
}

// replaceDuringRead cuts the first read of key at 80000 bytes after
// replacing the object in place with alt, as a peer's upload within the
// same second would.
func replaceDuringRead(store *memBlobStore, key string, alt []byte) {
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(_ context.Context, k string, offset int64, body io.Reader) io.Reader {
			if k != key || offset != 0 {
				return body
			}
			return io.MultiReader(io.LimitReader(body, 80000), readerFunc(func([]byte) (int, error) {
				store.replaceInPlace(key, alt)
				return 0, errCut
			}))
		}
	})
}

func TestRemoteResumeOfAReplacedObjectIsAFetchError(t *testing.T) {
	store := newMemBlobStore()
	store.set(func(m *memBlobStore) { m.etags = true })
	var alt []byte
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, func(key string, data []byte) {
		alt = bytes.Clone(data)
		alt[100000] ^= 0xff
		replaceDuringRead(store, key, alt)
	})
	_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if !aborted {
		t.Fatal("the response was not aborted after the object changed")
	}
	assertStoreIdle(t, c)
	if got := discarded(observability.FillReasonFetchError); got != 1 {
		t.Errorf("fills discarded with fetch_error = %d, want 1", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 0 {
		t.Errorf("integrity events = %v, want none for a replaced object", got)
	}
	if data, ok := store.object(key); !ok || !bytes.Equal(data, alt) {
		t.Error("the replacement object was deleted or changed")
	}
}

func TestRemoteResumeWithoutAnETagSplicesASameSecondReplacement(t *testing.T) {
	store := newMemBlobStore()
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, func(key string, data []byte) {
		alt := bytes.Clone(data)
		alt[100000] ^= 0xff
		replaceDuringRead(store, key, alt)
	})
	_, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if !aborted {
		t.Fatal("the response was not aborted after the spliced bytes failed verification")
	}
	assertStoreIdle(t, c)
	if got := discarded(observability.FillReasonStoreError); got != 1 {
		t.Errorf("fills discarded with store_error = %d, want 1", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 1 {
		t.Errorf("integrity events = %v, want one: without an ETag the splice is caught only by the AEAD", got)
	}
	if _, ok := store.object(key); ok {
		t.Error("the object that failed verification was not deleted")
	}
}
