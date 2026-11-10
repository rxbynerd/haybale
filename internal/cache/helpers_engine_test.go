package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// assertStoreIdle waits for every fill to end and then checks the budget
// invariant: no reservation or pinned bytes remain, the committed bytes
// equal the entry files on disk, every fill and classification slot is
// free and no temporary file is left behind.
func assertStoreIdle(t *testing.T, c *Cache) {
	t.Helper()
	waitFor(t, "fills to end", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.fills) == 0 && c.refsFills == 0 && len(c.slots) == 0
	})
	if n := len(c.classifySlots); n != 0 {
		t.Errorf("classification slots still held = %d, want 0", n)
	}
	waitFor(t, "reservations and pinned bytes to drain", func() bool {
		_, inflight, pinned := c.store.usage()
		return inflight == 0 && pinned == 0
	})
	var onDisk int64
	for _, rel := range entryFiles(t, c.opts.Dir) {
		if strings.HasPrefix(filepath.Base(rel), tempNamePrefix) {
			t.Errorf("temporary file %s remains", rel)
			continue
		}
		info, err := os.Stat(filepath.Join(c.opts.Dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		onDisk += info.Size()
	}
	if committed, _, _ := c.store.usage(); committed != onDisk {
		t.Errorf("committed bytes = %d, entry files on disk hold %d", committed, onDisk)
	}
}

// logCapture collects JSON log lines from a Cache under test.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newLogCapture() (*slog.Logger, *logCapture) {
	lc := &logCapture{}
	return slog.New(slog.NewJSONHandler(lc, &slog.HandlerOptions{Level: slog.LevelDebug})), lc
}

func (lc *logCapture) Write(p []byte) (int, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buf.Write(p)
}

func (lc *logCapture) String() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buf.String()
}

// records returns the decoded log lines whose msg equals msg.
func (lc *logCapture) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(lc.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// securityEvents returns the security event records with the given event.
func (lc *logCapture) securityEvents(t *testing.T, event string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range lc.records(t, "security event") {
		if rec["event"] == event {
			out = append(out, rec)
		}
	}
	return out
}

// sumWhere totals the data points of the named int64 sum whose attribute
// set contains every key/value pair in want.
func sumWhere(t *testing.T, reader *sdkmetric.ManualReader, name string, want map[string]string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != name {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T", name, md.Data)
			}
			for _, dp := range sum.DataPoints {
				if attrsMatch(dp.Attributes, want) {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// attrsMatch reports whether set carries every pair in want; an empty
// wanted value matches an absent attribute.
func attrsMatch(set attribute.Set, want map[string]string) bool {
	for k, v := range want {
		got, ok := set.Value(attribute.Key(k))
		switch {
		case !ok && v == "":
		case !ok, got.AsString() != v:
			return false
		}
	}
	return true
}

// fillsWithReason is the fills.total count for a result and reason.
func fillsWithReason(t *testing.T, reader *sdkmetric.ManualReader, result, reason string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache.fills.total", map[string]string{"haybale.result": result, "haybale.reason": reason})
}

// lookups is the lookups.total count for a result.
func lookups(t *testing.T, reader *sdkmetric.ManualReader, result string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache.lookups.total", map[string]string{"haybale.result": result})
}

// storeErrors is the store_errors.total count for an operation.
func storeErrors(t *testing.T, reader *sdkmetric.ManualReader, operation string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache.store_errors.total", map[string]string{"haybale.operation": operation})
}

// otherFetchRequest is a cacheable v2 fetch for a different want than
// fetchRequest, so the two have distinct keys.
func otherFetchRequest(t testing.TB) *http.Request {
	t.Helper()
	return postV2(fetchBody(t, "want "+oidB+"\n", "done\n"))
}

// failAfterWriter fails every Write once limit bytes have been accepted,
// standing in for a client that disconnected.
type failAfterWriter struct {
	header  http.Header
	status  int
	written int
	limit   int
	failed  chan struct{}
	once    sync.Once
}

func newFailAfterWriter(limit int) *failAfterWriter {
	return &failAfterWriter{header: make(http.Header), limit: limit, failed: make(chan struct{})}
}

func (w *failAfterWriter) Header() http.Header { return w.header }

func (w *failAfterWriter) WriteHeader(status int) { w.status = status }

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		w.once.Do(func() { close(w.failed) })
		return 0, errors.New("client went away")
	}
	w.written += len(p)
	return len(p), nil
}

// entryPathOnDisk returns the one entry file under the cache directory.
func entryPathOnDisk(t *testing.T, c *Cache) string {
	t.Helper()
	files := entryFiles(t, c.opts.Dir)
	if len(files) != 1 {
		t.Fatalf("entries = %v, want exactly one", files)
	}
	return filepath.Join(c.opts.Dir, filepath.FromSlash(files[0]))
}

// readEntryFile reads an entry file under the cache directory.
func readEntryFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is within the test's own cache directory
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// waitForSubscribers waits until the single registered fill has n
// subscribers.
func waitForSubscribers(t *testing.T, c *Cache, n int) {
	t.Helper()
	waitFor(t, "subscribers to attach", func() bool { return subscribersAre(c, n) })
}

// subscribersAre reports whether exactly one fill is in flight and it has
// n subscribers.
func subscribersAre(c *Cache, n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.fills) != 1 {
		return false
	}
	for _, f := range c.fills {
		return f.subscribers == n
	}
	return false
}

// shortly is a bound for events that should happen promptly.
const shortly = 5 * time.Second

// receive returns the next value from ch, failing the test if none
// arrives shortly.
func receive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(shortly):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// waitGroupShortly waits for wg, failing the test if it is not done
// shortly.
func waitGroupShortly(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	receive(t, done, what)
}
