package upstream

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
)

// sumPoints collects the named Int64 sum metric's data points.
func sumPoints(t *testing.T, reader *sdkmetric.ManualReader, name string) []metricdata.DataPoint[int64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != name {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q is %T, want Sum[int64]", name, md.Data)
			}
			return sum.DataPoints
		}
	}
	return nil
}

func attrOf(set attribute.Set, key string) string {
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return v.String()
}

// TestGitHubAppSourceRecordsMintAndCacheMetrics drives Credentials twice
// for the same repo/verb through the fake GitHub API: the first call is a
// cache miss that mints, the second is a cache hit that does not. It
// asserts the mint counter fires exactly once and the cache counter records
// one miss and one hit — the signals an operator uses to watch mint
// pressure against GitHub's REST budget.
func TestGitHubAppSourceRecordsMintAndCacheMetrics(t *testing.T) {
	fake := newGitHubFake(4278664)
	src := newTestSource(t, fake)

	metrics, reader := observability.NewTestMetrics()
	src.SetMetrics(metrics)

	repo := gitproto.Repo{Host: "github.com", Owner: "rxbynerd", Name: "haybale"}
	ctx := context.Background()

	if _, err := src.Credentials(ctx, repo, gitproto.Read); err != nil {
		t.Fatalf("first Credentials() error = %v", err)
	}
	if _, err := src.Credentials(ctx, repo, gitproto.Read); err != nil {
		t.Fatalf("second Credentials() error = %v", err)
	}

	// Sanity: the fake really did mint exactly once (second call served
	// from cache), so the metric should agree with the fake's own count.
	if got := fake.mintCallCount(); got != 1 {
		t.Fatalf("fake mint call count = %d, want 1", got)
	}

	mints := sumPoints(t, reader, "haybale.tokens.minted.total")
	if len(mints) != 1 || mints[0].Value != 1 {
		t.Errorf("tokens.minted = %+v, want a single point valued 1", mints)
	}
	if got := attrOf(mints[0].Attributes, "haybale.host"); got != "github.com" {
		t.Errorf("mint host label = %q, want github.com", got)
	}

	lookups := sumPoints(t, reader, "haybale.token_cache.lookups.total")
	results := map[string]int64{}
	for _, dp := range lookups {
		results[attrOf(dp.Attributes, "haybale.result")] += dp.Value
	}
	if results["miss"] != 1 {
		t.Errorf("cache miss count = %d, want 1", results["miss"])
	}
	if results["hit"] != 1 {
		t.Errorf("cache hit count = %d, want 1", results["hit"])
	}
}

// TestGitHubAppSourceWithoutMetricsDoesNotPanic confirms a source that was
// never given metrics (SetMetrics not called, or called with nil) still
// mints normally — the nil-guarded record path is a no-op, not a crash.
func TestGitHubAppSourceWithoutMetricsDoesNotPanic(t *testing.T) {
	fake := newGitHubFake(4278664)
	src := newTestSource(t, fake)
	src.SetMetrics(nil) // ignored; leaves the source recording nothing

	repo := gitproto.Repo{Host: "github.com", Owner: "rxbynerd", Name: "haybale"}
	if _, err := src.Credentials(context.Background(), repo, gitproto.Write); err != nil {
		t.Fatalf("Credentials() error = %v", err)
	}
	if got := fake.mintCallCount(); got != 1 {
		t.Errorf("mint call count = %d, want 1", got)
	}
}

// TestTokenCacheConcurrentLookupsRecordMissPerCaller pins the documented
// invariant that a miss is recorded for every caller that had no usable
// cached token — the leader that runs the mint AND every follower that
// merely waits on it — so the hit ratio reflects real mint pressure. N
// goroutines pile into one singleflight'd mint for the same key; exactly
// one mint runs, but all N must be counted as misses.
func TestTokenCacheConcurrentLookupsRecordMissPerCaller(t *testing.T) {
	cache := newTokenCache(time.Now)
	metrics, reader := observability.NewTestMetrics()
	cache.setMetrics(metrics)

	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

	const n = 40
	var mintCalls sync.WaitGroup
	mintCalls.Add(1)
	release := make(chan struct{})
	var once sync.Once
	mint := func(_ context.Context, _ gitproto.Repo, _ gitproto.Verb) (BasicAuth, time.Time, error) {
		once.Do(mintCalls.Done) // signal the first (and only) real mint
		<-release
		return BasicAuth{Username: "x-access-token", Password: "shared"}, time.Now().Add(time.Hour), nil
	}

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for i := 0; i < n; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			_, _ = cache.get(context.Background(), repo, gitproto.Read, mint)
		}()
	}
	start.Done()

	mintCalls.Wait() // every goroutine is now piled into the one in-flight mint
	time.Sleep(50 * time.Millisecond)
	close(release)
	done.Wait()

	misses := map[string]int64{}
	for _, dp := range sumPoints(t, reader, "haybale.token_cache.lookups.total") {
		misses[attrOf(dp.Attributes, "haybale.result")] += dp.Value
	}
	if misses["miss"] != n {
		t.Errorf("recorded %d misses, want %d (one per caller sharing the collapsed mint)", misses["miss"], n)
	}
}

// TestSetMetricsAndSetLoggerRaceFreeWithCredentials exercises the
// atomic.Pointer install contract under -race: installing metrics/logger
// concurrently with in-flight Credentials() calls must not race. Production
// only installs once at startup, but the atomics are documented as making
// concurrent install-vs-read safe, and only a concurrent test proves it.
func TestSetMetricsAndSetLoggerRaceFreeWithCredentials(t *testing.T) {
	fake := newGitHubFake(4278664)
	src := newTestSource(t, fake)
	repo := gitproto.Repo{Host: "github.com", Owner: "rxbynerd", Name: "haybale"}

	metrics, _ := observability.NewTestMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Installers: hammer SetMetrics/SetLogger.
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				src.SetMetrics(metrics)
				src.SetLogger(logger)
			}
		}
	})
	// Readers: concurrent Credentials() calls (each reads the atomics).
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = src.Credentials(context.Background(), repo, gitproto.Read)
				}
			}
		})
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}
