package upstream

import (
	"context"
	"testing"

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
