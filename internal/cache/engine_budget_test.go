package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/rxbynerd/haybale/internal/observability"
)

// budgetCache is a cache with captured metrics and small limits for the
// budget tests.
func budgetCache(t *testing.T, mutate func(*Options)) (*Cache, *fakeClock, *sdkmetric.ManualReader) {
	t.Helper()
	m, reader := observability.NewTestMetrics()
	c, clock := newTestCache(t, func(o *Options) {
		o.AccessRecheck = 0
		o.Metrics = m
		if mutate != nil {
			mutate(o)
		}
	})
	return c, clock, reader
}

// wantOID returns a distinct, well-formed object id for i.
func wantOID(i int) string {
	return fmt.Sprintf("%040x", 0xabc000+i)
}

// fetchRequestFor is a cacheable clone of a distinct want, so that
// requests for different i have different keys.
func fetchRequestFor(t testing.TB, i int) *http.Request {
	t.Helper()
	return postV2(fetchBody(t, "want "+wantOID(i)+"\n", "done\n"))
}

// storeEntries stores n distinct pack entries of the given body size and
// returns a fetcher for them.
func storeEntries(t *testing.T, c *Cache, n, frames int) *fixedFetcher {
	t.Helper()
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, frames, 5000)}
	for i := range n {
		if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequestFor(t, 100+i), fetch); !handled || !out.Stored {
			t.Fatalf("entry %d = %+v handled %v, want a stored miss", i, out, handled)
		}
	}
	return fetch
}

// hitsFor counts how many of the n stored entries are still hits.
func hitsFor(t *testing.T, c *Cache, n int, fetch Fetcher) int {
	t.Helper()
	hits := 0
	for i := range n {
		if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequestFor(t, 100+i), fetch); out.Result == observability.ResultHit {
			hits++
		}
	}
	return hits
}

func TestKnownOversizeResponseIsServedToEverySubscriberAndNotStored(t *testing.T) {
	c, clock, reader := budgetCache(t, func(o *Options) { o.MaxEntrySize = 1 << 16 })
	kept := storeEntries(t, c, 2, 3)
	want := fetchResultBody(t, 30, 5000) // about 150 KB, over twice the limit
	gate := make(chan struct{})
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		<-gate
		return response(http.StatusOK, contentTypeResult, want), nil
	})
	const n = 3
	recs := make([]*httptest.ResponseRecorder, n)
	outs := make([]Outcome, n)
	handled := make([]bool, n)
	var wg sync.WaitGroup
	for i := range n {
		recs[i] = httptest.NewRecorder()
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], handled[i], _ = serve(c, recs[i], fetchRequest(t), fetch)
		}()
	}
	waitForSubscribers(t, c, n)
	close(gate)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("upstream fetched %d times, want 1", calls.Load())
	}
	for i := range n {
		if !handled[i] || outs[i].Result != observability.ResultMiss || outs[i].Stored || !bytes.Equal(recs[i].Body.Bytes(), want) {
			t.Errorf("subscriber %d: %+v handled %v, %d bytes; want a served, unstored miss of %d bytes", i, outs[i], handled[i], recs[i].Body.Len(), len(want))
		}
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonTooLarge); got != 1 {
		t.Errorf("fills discarded too_large = %d, want 1", got)
	}
	if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok {
		t.Error("next request was handled; want a bypass while the key is marked")
	}
	if calls.Load() != 1 {
		t.Errorf("a marked key reached upstream (calls = %d)", calls.Load())
	}
	if hits := hitsFor(t, c, 2, kept); hits != 2 {
		t.Errorf("committed entries still hits = %d, want 2", hits)
	}
	assertStoreIdle(t, c)

	// The mark lasts for the retention period.
	clock.Advance(c.opts.Retention + time.Minute)
	if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !ok {
		t.Error("request after retention was not handled; the mark should have expired")
	}
}

func TestKnownOversizeResponseBeyondFreeBudgetReleasesSubscribers(t *testing.T) {
	c, clock, reader := budgetCache(t, func(o *Options) {
		o.MaxDiskSize = 1 << 20
		o.MaxEntrySize = 256 << 10
	})
	kept := storeEntries(t, c, 3, 40) // three entries of about 200 KB
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		return response(http.StatusOK, contentTypeResult, fetchResultBody(t, 100, 5000)), nil
	})
	rec := httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
	if aborted || handled || out.Result != observability.ResultBypass {
		t.Fatalf("oversize beyond the free budget: %+v handled %v aborted %v, want a bypass", out, handled, aborted)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonTooLarge); got != 1 {
		t.Errorf("fills discarded too_large = %d, want 1", got)
	}
	if hits := hitsFor(t, c, 3, kept); hits != 3 {
		t.Errorf("committed entries still hits = %d, want 3; none may be evicted for a response that will not be stored", hits)
	}
	if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok {
		t.Error("next request was handled; want a bypass while the key is marked")
	}
	clock.Advance(c.opts.Retention + time.Minute)
	if calls.Load() != 1 {
		t.Errorf("upstream fetched %d times through the cache, want 1", calls.Load())
	}
	assertStoreIdle(t, c)
}

// chunkedBody streams body in chunks of unknown total length.
func chunkedBody(body []byte) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		for off := 0; off < len(body); off += 32 << 10 {
			end := min(off+32<<10, len(body))
			if _, err := pw.Write(body[off:end]); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	return pr
}

func TestUnknownLengthResponseThatOutgrowsTheBudgetAbortsOnceAndIsMarkedForRetention(t *testing.T) {
	c, clock, reader := budgetCache(t, func(o *Options) {
		o.MaxDiskSize = 2 << 20
		o.MaxEntrySize = 256 << 10
	})
	kept := storeEntries(t, c, 5, 20)     // five entries of about 100 KB
	huge := fetchResultBody(t, 720, 5000) // about 3.6 MB
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		return streamingResponse(contentTypeResult, chunkedBody(huge)), nil
	})
	w := newCollectWriter()
	out, handled, aborted := serve(c, w, fetchRequest(t), fetch)
	if !aborted {
		t.Fatalf("first attempt = %+v handled %v, want an abort once the free budget is exhausted", out, handled)
	}
	if _, body, _ := w.result(); len(body) == 0 || len(body) >= len(huge) {
		t.Errorf("client received %d bytes, want a partial response", len(body))
	}
	if hits := hitsFor(t, c, 5, kept); hits != 5 {
		t.Errorf("committed entries still hits = %d, want all 5", hits)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonTooLarge); got != 1 {
		t.Errorf("fills discarded too_large = %d, want 1", got)
	}
	assertStoreIdle(t, c)

	clock.Advance(2 * time.Minute)
	if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok || calls.Load() != 1 {
		t.Errorf("second attempt handled=%v calls=%d, want a bypass with no new fetch", ok, calls.Load())
	}
	clock.Advance(c.opts.Retention)
	w = newCollectWriter()
	serve(c, w, fetchRequest(t), fetch)
	if calls.Load() != 2 {
		t.Errorf("after retention the fill was not attempted again (calls = %d)", calls.Load())
	}
	assertStoreIdle(t, c)
}

func TestReservationFailureReleasesWithoutAbort(t *testing.T) {
	c, clock, reader := budgetCache(t, func(o *Options) {
		o.MaxDiskSize = 2 << 20
		o.MaxEntrySize = 1 << 20
	})
	first := make(chan struct{})
	headers := make(chan struct{})
	pr, pw := io.Pipe()
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(headers)
			return streamingResponse(contentTypeResult, pr), nil
		}
		return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(fetchResultBody(t, 1, 10)))), nil
	})
	var firstOut Outcome
	go func() {
		defer close(first)
		firstOut, _, _ = serve(c, newCollectWriter(), fetchRequest(t), fetch)
	}()
	<-headers
	waitFor(t, "the first reservation", func() bool {
		_, inflight, _ := c.store.usage()
		return inflight > 0
	})

	out, handled, aborted := serve(c, httptest.NewRecorder(), otherFetchRequest(t), fetch)
	if aborted || handled || out.Result != observability.ResultBypass {
		t.Fatalf("second fill with no budget: %+v handled %v aborted %v, want a bypass", out, handled, aborted)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonDiskBudget); got != 1 {
		t.Errorf("fills discarded disk_budget = %d, want 1", got)
	}
	_, _ = pw.Write(fetchResultBody(t, 1, 10))
	_ = pw.Close()
	<-first
	if !firstOut.Stored {
		t.Errorf("first fill = %+v, want stored", firstOut)
	}
	// The mark is the transient cooldown, not retention.
	if _, ok, _ := serve(c, httptest.NewRecorder(), otherFetchRequest(t), fetch); ok {
		t.Error("marked key was handled within the cooldown")
	}
	clock.Advance(2 * time.Minute)
	if out, ok, _ := serve(c, httptest.NewRecorder(), otherFetchRequest(t), fetch); !ok || !out.Stored {
		t.Errorf("after the cooldown = %+v handled %v, want a stored miss", out, ok)
	}
	assertStoreIdle(t, c)
}

func TestFillEvictsUnopenedEntriesButNotOpenOnes(t *testing.T) {
	c, _, reader := budgetCache(t, func(o *Options) {
		o.MaxDiskSize = 2 << 20
		o.MaxEntrySize = 1 << 20
	})
	kept := storeEntries(t, c, 1, 180) // about 900 KB, so a 1 MiB reservation must evict it
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 2, 100)}
	streaming := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(fetch.body))), nil
	})
	if out, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), streaming); !ok || !out.Stored {
		t.Fatalf("fill needing eviction = %+v handled %v, want a stored miss", out, ok)
	}
	if hits := hitsFor(t, c, 1, kept); hits != 0 {
		t.Error("the least recently used entry was not evicted to make room")
	}
	if got := sumInt64(t, reader, "haybale.response_cache.evictions.total"); got != 1 {
		t.Errorf("evictions = %d, want 1", got)
	}
	assertStoreIdle(t, c)

	// An entry held open by a reader cannot be evicted, so a fill that
	// needs its bytes is released instead. hitsFor refilled the evicted
	// entry, so it is stored again.
	key := entryKeyFor(t, c, fetchRequestFor(t, 100))
	held, err := c.store.Open(key.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	out, ok, aborted := serve(c, httptest.NewRecorder(), fetchRequestFor(t, 200), streaming)
	if aborted || ok || out.Result != observability.ResultBypass {
		t.Fatalf("fill needing an open entry = %+v handled %v aborted %v, want a bypass", out, ok, aborted)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonDiskBudget); got != 1 {
		t.Errorf("fills discarded disk_budget = %d, want 1", got)
	}
	if hits := hitsFor(t, c, 1, kept); hits != 1 {
		t.Error("the open entry was evicted")
	}
}
