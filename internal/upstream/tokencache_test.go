package upstream

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// fakeClock is an injectable, mutable clock for deterministically
// exercising tokenCache's expiry and early-refresh-boundary logic —
// wall-clock time would make those boundaries flaky to assert precisely.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// countingMint returns a mintFunc that mints a fixed-lifetime credential
// (relative to clock's current time) and tallies how many times it was
// actually invoked, so tests can assert "no second mint" / "exactly one
// mint" style expectations without a real network fake.
func countingMint(clock *fakeClock, lifetime time.Duration) (mintFunc, *atomic.Int64) {
	var calls atomic.Int64
	fn := func(_ context.Context, repo gitproto.Repo, verb gitproto.Verb) (BasicAuth, time.Time, error) {
		n := calls.Add(1)
		cred := BasicAuth{
			Username: "x-access-token",
			Password: fmt.Sprintf("token-%s-%s-%d", repo.Name, verb.String(), n),
		}
		return cred, clock.Now().Add(lifetime), nil
	}
	return fn, &calls
}

func TestTokenCacheServesFromCacheBeforeExpiry(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	cache := newTokenCache(clock.Now)
	mint, calls := countingMint(clock, time.Hour)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	first, err := cache.get(context.Background(), repo, gitproto.Read, mint)
	if err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 after first get", calls.Load())
	}

	// Well before expiry (and well before the 5-minute early-refresh
	// boundary) — must be served from cache, no second mint.
	clock.Set(clock.Now().Add(10 * time.Minute))
	second, err := cache.get(context.Background(), repo, gitproto.Read, mint)
	if err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want still 1 (served from cache)", calls.Load())
	}
	if second != first {
		t.Errorf("get() = %+v, want the cached credential %+v", second, first)
	}
}

func TestTokenCacheReMintsAfterExpiry(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	cache := newTokenCache(clock.Now)
	mint, calls := countingMint(clock, time.Hour)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}

	clock.Set(clock.Now().Add(time.Hour + time.Minute))
	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (re-minted after expiry)", calls.Load())
	}
}

// TestTokenCacheEarlyRefreshBoundary asserts the exact 5-minute
// early-refresh boundary: a token is still servable from cache at one
// nanosecond before the boundary, and must be re-minted at (and past)
// the boundary itself.
func TestTokenCacheEarlyRefreshBoundary(t *testing.T) {
	start := time.Unix(0, 0)
	clock := newFakeClock(start)
	cache := newTokenCache(clock.Now)
	mint, calls := countingMint(clock, time.Hour)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	// Minted at t=0 with a 1h lifetime: refreshAt = expiresAt - 5m = 55m.
	refreshAt := start.Add(time.Hour - earlyRefreshWindow)

	clock.Set(refreshAt.Add(-time.Nanosecond))
	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (one nanosecond before the boundary must still be cached)", calls.Load())
	}

	clock.Set(refreshAt)
	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (exactly at the 5-minute boundary must trigger a re-mint)", calls.Load())
	}
}

// TestTokenCacheWriteSatisfiesRead asserts a cached WRITE token also
// satisfies a subsequent READ request for the same repo, with no new
// mint — the cache-reduction rule the M4 plan calls out by name.
func TestTokenCacheWriteSatisfiesRead(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	cache := newTokenCache(clock.Now)
	mint, calls := countingMint(clock, time.Hour)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	writeCred, err := cache.get(context.Background(), repo, gitproto.Write, mint)
	if err != nil {
		t.Fatalf("get(write) unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 after the write mint", calls.Load())
	}

	readCred, err := cache.get(context.Background(), repo, gitproto.Read, mint)
	if err != nil {
		t.Fatalf("get(read) unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want still 1 (read satisfied by the cached write token)", calls.Load())
	}
	if readCred != writeCred {
		t.Errorf("get(read) = %+v, want the write-cache credential %+v", readCred, writeCred)
	}
}

// TestTokenCacheReadDoesNotSatisfyWrite asserts the converse of
// write-satisfies-read: a cached READ token never satisfies a WRITE
// request, so a write always mints its own (more privileged) token.
func TestTokenCacheReadDoesNotSatisfyWrite(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	cache := newTokenCache(clock.Now)
	mint, calls := countingMint(clock, time.Hour)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	if _, err := cache.get(context.Background(), repo, gitproto.Read, mint); err != nil {
		t.Fatalf("get(read) unexpected error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 after the read mint", calls.Load())
	}

	if _, err := cache.get(context.Background(), repo, gitproto.Write, mint); err != nil {
		t.Fatalf("get(write) unexpected error: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (write must mint its own token, not reuse the read cache)", calls.Load())
	}
}

// TestTokenCacheSingleflightCollapsesConcurrentMints fires N concurrent
// Get calls for the same (host, owner, repo, verb) and asserts exactly
// one mint call happened — the rest waited and shared its result. Run
// under `go test -race` per the M4 plan.
func TestTokenCacheSingleflightCollapsesConcurrentMints(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	cache := newTokenCache(clock.Now)
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	const n = 50
	var calls atomic.Int64
	release := make(chan struct{})

	// mint blocks on release until the test has given every one of the n
	// goroutines below a chance to reach cache.get and pile into the
	// same singleflight call — widening the concurrency window is what
	// makes "exactly one mint call" a meaningful assertion rather than a
	// scheduling accident.
	mint := func(_ context.Context, _ gitproto.Repo, _ gitproto.Verb) (BasicAuth, time.Time, error) {
		calls.Add(1)
		<-release
		return BasicAuth{Username: "x-access-token", Password: "shared-token"}, clock.Now().Add(time.Hour), nil
	}

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	results := make([]BasicAuth, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = cache.get(context.Background(), repo, gitproto.Read, mint)
		}(i)
	}
	start.Done()

	// Give every goroutine a chance to reach cache.get and pile into the
	// singleflight call before letting the (single) in-flight mint
	// finish.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	done.Wait()

	if calls.Load() != 1 {
		t.Fatalf("mint calls = %d, want exactly 1 for %d concurrent Get calls sharing the same key", calls.Load(), n)
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("get() goroutine %d unexpected error: %v", i, err)
		}
		if results[i].Password != "shared-token" {
			t.Errorf("get() goroutine %d = %+v, want the shared minted credential", i, results[i])
		}
	}
}
