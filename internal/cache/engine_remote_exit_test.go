package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

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
// second cache's first request; mutate adjusts the second cache's options.
func newRemoteFillCase(t *testing.T, store *memBlobStore, mutate func(*Options), prepare func(key string, data []byte)) (*Cache, *logCapture, []byte, string, func(reason string) int64) {
	t.Helper()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	if prepare != nil {
		data, _ := store.object(key)
		prepare(key, bytes.Clone(data))
	}
	logger, logs := newLogCapture()
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) {
		o.Logger = logger
		if mutate != nil {
			mutate(o)
		}
	})
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
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, nil, func(key string, _ []byte) {
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
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, nil, func(key string, data []byte) {
		store.store(key, data[:len(data)-frameLen-trailerCTLen])
	})
	// The trailer is checked last, so whether the subscriber had already
	// written bytes, and is aborted, or had not, and is released to the
	// passthrough path, depends on scheduling.
	_, handled, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack))
	if handled && !aborted {
		t.Fatal("a remote entry missing its trailer was served as complete")
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
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, nil, func(key string, _ []byte) {
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
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, nil, func(key string, data []byte) {
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
	c, logs, pack, key, discarded := newRemoteFillCase(t, store, nil, func(key string, data []byte) {
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

func TestRemoteHeaderFailureFallsThroughWithoutResuming(t *testing.T) {
	never := make(chan struct{})
	cases := map[string]func(ctx context.Context, body io.Reader) io.Reader{
		"stalls": func(ctx context.Context, body io.Reader) io.Reader {
			return &gateReader{ctx: ctx, r: body, n: 100, release: never}
		},
		"fails": func(_ context.Context, body io.Reader) io.Reader { return cutReader(body, 100) },
	}
	for name, wrap := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			const headerTimeout = 100 * time.Millisecond
			c, logs, pack, key, _ := newRemoteFillCase(t, store, func(o *Options) {
				o.RemoteHeaderTimeout = headerTimeout
				o.IdleTimeout = time.Minute
			}, func(key string, _ []byte) {
				store.set(func(m *memBlobStore) {
					m.wrapBody = func(ctx context.Context, k string, offset int64, body io.Reader) io.Reader {
						if k != key {
							return body
						}
						return wrap(ctx, body)
					}
				})
			})
			upstream := packFetcher(pack)
			rec := newCollectWriter()
			start := time.Now()
			out, _, aborted := serve(c, rec, fetchRequest(t), upstream)
			elapsed := time.Since(start)
			if aborted || !out.Stored || upstream.calls.Load() != 1 {
				t.Fatalf("fetch = %+v aborted %v upstream %d, want a stored miss from upstream", out, aborted, upstream.calls.Load())
			}
			if _, body, _ := rec.result(); !bytes.Equal(body, pack) {
				t.Errorf("received %d bytes, want the %d pack bytes", len(body), len(pack))
			}
			if elapsed > 10*headerTimeout {
				t.Errorf("fall-through took %s, want about the header timeout %s", elapsed, headerTimeout)
			}
			if got := store.getOffsets(key); fmt.Sprint(got) != "[0]" {
				t.Errorf("remote Get offsets = %v, want the one Get and no resume", got)
			}
			if n := store.count("delete", key); n != 0 {
				t.Errorf("remote deletes = %d, want none", n)
			}
			if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 0 {
				t.Errorf("integrity events = %v, want none", got)
			}
			assertStoreIdle(t, c)
		})
	}
}

// fillsFrom counts fills.total for tier, result and, when not empty, reason.
func fillsFrom(t *testing.T, reader *sdkmetric.ManualReader, tier, result, reason string) int64 {
	t.Helper()
	want := map[string]string{"haybale.tier": tier, "haybale.result": result}
	if reason != "" {
		want["haybale.reason"] = reason
	}
	return sumWhere(t, reader, "haybale.response_cache.fills.total", want)
}

func TestFillsAreCountedByTheTierTheyReadFrom(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	c, _, reader := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))
	if out, _, _ := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack)); !out.Stored {
		t.Fatalf("fetch = %+v, want a stored remote fill", out)
	}
	store.set(func(m *memBlobStore) {
		m.getHook = func(string, int64) error { return errors.New("memblob: 503 SlowDown") }
	})
	other := packFetcher(fetchResultBody(t, 3, 100))
	if out, _, _ := serve(c, newCollectWriter(), otherFetchRequest(t), other); !out.Stored || other.calls.Load() != 1 {
		t.Fatalf("fetch with a failing remote = %+v upstream %d, want a stored upstream fill", out, other.calls.Load())
	}
	assertStoreIdle(t, c)

	if got := fillsFrom(t, reader, observability.TierRemote, observability.FillResultStored, ""); got != 1 {
		t.Errorf("fills{tier=remote,result=stored} = %d, want 1", got)
	}
	if got := fillsFrom(t, reader, observability.TierUpstream, observability.FillResultStored, ""); got != 2 {
		t.Errorf("fills{tier=upstream,result=stored} = %d, want the ls-refs and the fall-through", got)
	}
	if got := sumWhere(t, reader, "haybale.response_cache.fills.total", nil); got != 3 {
		t.Errorf("fills = %d, want 3: a remote attempt that falls through is one upstream fill", got)
	}
}

func TestAnAbortedRemoteFillCountsItsBytes(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(_ context.Context, k string, offset int64, body io.Reader) io.Reader {
			switch {
			case k != key:
				return body
			case offset == 0:
				return cutReader(body, 80000)
			default:
				return cutReader(body, 0)
			}
		}
	})
	c, _, reader := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))
	if _, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), packFetcher(pack)); !aborted {
		t.Fatal("the response was not aborted")
	}
	assertStoreIdle(t, c)
	if got := fillsFrom(t, reader, observability.TierRemote, observability.FillResultDiscarded, observability.FillReasonFetchError); got != 1 {
		t.Errorf("fills{tier=remote,reason=fetch_error} = %d, want 1", got)
	}
	if got := tierSum(t, reader, "fill_bytes.total", observability.TierRemote); got <= 0 || got >= int64(len(pack)) {
		t.Errorf("fill_bytes{tier=remote} = %d, want the verified bytes read before the abort", got)
	}
}
