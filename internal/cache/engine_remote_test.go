package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// errCut is the error a memBlobStore body returns where a test cut it.
var errCut = errors.New("memblob: connection reset")

type memObject struct {
	data    []byte
	modTime time.Time
}

type blobCall struct {
	op     string
	key    string
	offset int64
}

// memBlobStore is an in-memory BlobStore that records every call. Its
// hooks inject faults; each is read under mu and called without it.
type memBlobStore struct {
	mu      sync.Mutex
	objects map[string]memObject
	calls   []blobCall
	puts    int64 // advances the modification time of every Put

	getHook  func(key string, offset int64) error
	statHook func(ctx context.Context, key string) error
	putHook  func(ctx context.Context, key string) error
	listErr  error
	// etags makes the store report an ETag for every object and honour
	// GetIfMatch.
	etags bool
	// wrapBody may replace the body a Get returns.
	wrapBody func(ctx context.Context, key string, offset int64, body io.Reader) io.Reader
}

var (
	_ BlobStore         = (*memBlobStore)(nil)
	_ ConditionalGetter = (*memBlobStore)(nil)
)

func newMemBlobStore() *memBlobStore {
	return &memBlobStore{objects: make(map[string]memObject)}
}

func (m *memBlobStore) record(op, key string, offset int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, blobCall{op: op, key: key, offset: offset})
}

func (m *memBlobStore) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	m.record("stat", key, 0)
	m.mu.Lock()
	hook := m.statHook
	m.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, key); err != nil {
			return ObjectInfo{}, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objects[key]
	if !ok {
		return ObjectInfo{}, ErrNotFound
	}
	return m.infoLocked(key, o), nil
}

func (m *memBlobStore) Get(ctx context.Context, key string, offset int64) (io.ReadCloser, ObjectInfo, error) {
	return m.get(ctx, key, offset, "")
}

func (m *memBlobStore) GetIfMatch(ctx context.Context, key string, offset int64, etag string) (io.ReadCloser, ObjectInfo, error) {
	return m.get(ctx, key, offset, etag)
}

func (m *memBlobStore) get(ctx context.Context, key string, offset int64, etag string) (io.ReadCloser, ObjectInfo, error) {
	m.record("get", key, offset)
	m.mu.Lock()
	hook, wrap := m.getHook, m.wrapBody
	o, ok := m.objects[key]
	info := m.infoLocked(key, o)
	m.mu.Unlock()
	if hook != nil {
		if err := hook(key, offset); err != nil {
			return nil, ObjectInfo{}, err
		}
	}
	if !ok {
		return nil, ObjectInfo{}, ErrNotFound
	}
	if etag != "" && etag != info.ETag {
		return nil, ObjectInfo{}, fmt.Errorf("memblob: 412 PreconditionFailed: %w", ErrObjectChanged)
	}
	if offset > int64(len(o.data)) {
		return nil, ObjectInfo{}, fmt.Errorf("memblob: offset %d beyond %d bytes", offset, len(o.data))
	}
	var body io.Reader = bytes.NewReader(o.data[offset:])
	if wrap != nil {
		body = wrap(ctx, key, offset, body)
	}
	return io.NopCloser(&ctxReader{ctx: ctx, r: body}), info, nil
}

// infoLocked describes o, stored at key. m.mu must be held.
func (m *memBlobStore) infoLocked(key string, o memObject) ObjectInfo {
	info := ObjectInfo{Key: key, Size: int64(len(o.data)), ModTime: o.modTime}
	if m.etags {
		sum := sha256.Sum256(o.data)
		info.ETag = hex.EncodeToString(sum[:8])
	}
	return info
}

func (m *memBlobStore) Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	m.record("put", key, 0)
	m.mu.Lock()
	hook := m.putHook
	m.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, key); err != nil {
			return err
		}
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("memblob: put %d bytes, declared %d", len(data), size)
	}
	m.store(key, data)
	return nil
}

func (m *memBlobStore) Delete(_ context.Context, key string) error {
	m.record("delete", key, 0)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

func (m *memBlobStore) List(_ context.Context, prefix string) iter.Seq2[ObjectInfo, error] {
	m.record("list", prefix, 0)
	return func(yield func(ObjectInfo, error) bool) {
		m.mu.Lock()
		if err := m.listErr; err != nil {
			m.mu.Unlock()
			yield(ObjectInfo{}, err)
			return
		}
		var infos []ObjectInfo
		for k, o := range m.objects {
			if strings.HasPrefix(k, prefix) {
				infos = append(infos, ObjectInfo{Key: k, Size: int64(len(o.data)), ModTime: o.modTime})
			}
		}
		m.mu.Unlock()
		sort.Slice(infos, func(i, j int) bool { return infos[i].Key < infos[j].Key })
		for _, info := range infos {
			if !yield(info, nil) {
				return
			}
		}
	}
}

// replaceInPlace swaps key's bytes without changing its modification
// time, as a second upload within the same second appears to a client
// that sees only one-second times.
func (m *memBlobStore) replaceInPlace(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.objects[key]
	o.data = bytes.Clone(data)
	m.objects[key] = o
}

// store sets key directly, as a peer's upload would.
func (m *memBlobStore) store(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	m.objects[key] = memObject{data: bytes.Clone(data), modTime: time.Unix(m.puts, 0)}
}

func (m *memBlobStore) object(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objects[key]
	return o.data, ok
}

// keys returns the stored keys under prefix.
func (m *memBlobStore) keys(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// count returns how many calls of op named a key beginning with prefix.
func (m *memBlobStore) count(op, prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.op == op && strings.HasPrefix(c.key, prefix) {
			n++
		}
	}
	return n
}

// getOffsets returns the offsets of every Get of key.
func (m *memBlobStore) getOffsets(key string) []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []int64
	for _, c := range m.calls {
		if c.op == "get" && c.key == key {
			out = append(out, c.offset)
		}
	}
	return out
}

// forgetCalls clears the recorded calls.
func (m *memBlobStore) forgetCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func (m *memBlobStore) set(fn func(m *memBlobStore)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m)
}

// ctxReader fails reads once ctx ends, as a network body does.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// cutReader returns n bytes of r and then errCut.
func cutReader(r io.Reader, n int64) io.Reader {
	return io.MultiReader(io.LimitReader(r, n), errorReader{errCut})
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

// gateReader returns n bytes of r, then blocks until release is closed
// or ctx ends.
type gateReader struct {
	ctx     context.Context
	r       io.Reader
	n       int64
	release <-chan struct{}
}

func (g *gateReader) Read(p []byte) (int, error) {
	if g.n <= 0 {
		select {
		case <-g.release:
		case <-g.ctx.Done():
			return 0, g.ctx.Err()
		}
		return g.r.Read(p)
	}
	if int64(len(p)) > g.n {
		p = p[:g.n]
	}
	k, err := g.r.Read(p)
	g.n -= int64(k)
	return k, err
}

const (
	packPrefix  = "v1/pack/"
	refsPrefix  = "v1/refs/"
	purgePrefix = "v1/purge/"
)

// remotePack is a multi-segment pack response body for the remote tests.
func remotePack(t testing.TB) []byte {
	t.Helper()
	return fetchResultBody(t, 40, 5000)
}

// newRemoteTestCache is newTestCache sharing store as its remote tier
// under the common test key, with metrics recorded for inspection.
func newRemoteTestCache(t *testing.T, store BlobStore, mutate func(*Options)) (*Cache, *fakeClock, *sdkmetric.ManualReader) {
	t.Helper()
	metrics, reader := observability.NewTestMetrics()
	c, clock := newTestCache(t, func(o *Options) {
		o.Remote = store
		o.Metrics = metrics
		if mutate != nil {
			mutate(o)
		}
	})
	return c, clock, reader
}

// refsFetcher answers ls-refs from upstream.
func refsFetcher(t testing.TB) *fixedFetcher {
	return &fixedFetcher{status: 200, contentType: contentTypeResult, body: lsRefsResultBody(t)}
}

// packFetcher answers a fetch from upstream with body.
func packFetcher(body []byte) *fixedFetcher {
	return &fixedFetcher{status: 200, contentType: contentTypeResult, body: body}
}

// lsRefs serves one ls-refs request, which renews the access record.
func lsRefs(t *testing.T, c *Cache, refs Fetcher) Outcome {
	t.Helper()
	out, handled, aborted := serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), refs)
	if !handled || aborted {
		t.Fatalf("ls-refs: handled %v aborted %v", handled, aborted)
	}
	return out
}

// seedPeer fills a peer cache with the ls-refs and clone fetch entries
// and waits until both are uploaded to store.
func seedPeer(t *testing.T, store *memBlobStore, pack []byte) *Cache {
	t.Helper()
	peer, _, _ := newRemoteTestCache(t, store, nil)
	lsRefs(t, peer, refsFetcher(t))
	if out, _, _ := serve(peer, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack)); !out.Stored {
		t.Fatalf("peer fetch = %+v, want a stored miss", out)
	}
	waitFor(t, "the peer's uploads", func() bool {
		return len(store.keys(packPrefix)) == 1 && len(store.keys(refsPrefix)) == 1
	})
	store.forgetCalls()
	return peer
}

func tierSum(t *testing.T, reader *sdkmetric.ManualReader, name, tier string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache."+name, map[string]string{"haybale.tier": tier})
}

func remoteStoreErrors(t *testing.T, reader *sdkmetric.ManualReader, operation string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache.store_errors.total", map[string]string{"haybale.tier": observability.TierRemote, "haybale.operation": operation})
}

func uploadsWith(t *testing.T, reader *sdkmetric.ManualReader, result string) int64 {
	t.Helper()
	return sumWhere(t, reader, "haybale.response_cache.uploads.total", map[string]string{"haybale.result": result})
}

func TestRemoteTierServesAPeersEntry(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) { o.ExposeStatus = true })
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	rec := newCollectWriter()
	out, handled, aborted := serve(c, rec, fetchRequest(t), upstream)
	if !handled || aborted || out.Result != observability.ResultMiss || !out.Stored || out.Collapsed {
		t.Fatalf("fetch = %+v handled %v aborted %v, want a stored miss", out, handled, aborted)
	}
	if upstream.calls.Load() != 0 {
		t.Errorf("upstream fetched %d times, want the remote copy served", upstream.calls.Load())
	}
	if status, body, _ := rec.result(); status != 200 || !bytes.Equal(body, pack) {
		t.Errorf("status %d, %d bytes; want 200 and the %d pack bytes", status, len(body), len(pack))
	}
	if got := rec.Header().Get("Cache-Status"); got != "haybale; fwd=miss" {
		t.Errorf("Cache-Status = %q, want the fill form", got)
	}
	if got := tierSum(t, reader, "fill_bytes.total", observability.TierRemote); got != int64(len(pack)) {
		t.Errorf("fill_bytes{tier=remote} = %d, want %d", got, len(pack))
	}
	if got := tierSum(t, reader, "served_bytes.total", observability.TierRemote); got != int64(len(pack)) {
		t.Errorf("served_bytes{tier=remote} = %d, want %d", got, len(pack))
	}

	hit := httptest.NewRecorder()
	if out, _, _ := serve(c, hit, fetchRequest(t), upstream); out.Result != observability.ResultHit || !bytes.Equal(hit.Body.Bytes(), pack) {
		t.Errorf("second fetch = %+v, want a disk hit of the same bytes", out)
	}
	assertStoreIdle(t, c)
	// The ls-refs refresh uploads; the entry read from the remote tier
	// does not.
	waitFor(t, "the refs refresh upload", func() bool { return store.count("put", refsPrefix) == 1 })
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.count("put", packPrefix); got != 0 {
		t.Errorf("pack uploads = %d, want none for an entry read from the remote tier", got)
	}
}

func TestRemoteFillCoalescesSubscribers(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	release := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, offset int64, body io.Reader) io.Reader {
			if !strings.HasPrefix(key, packPrefix) {
				return body
			}
			return &gateReader{ctx: ctx, r: body, n: 80000, release: release}
		}
	})

	c, _, reader := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	leader, follower := newCollectWriter(), newCollectWriter()
	var leaderOut, followerOut Outcome
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		leaderOut, _, _ = serve(c, leader, fetchRequest(t), upstream)
	}()
	<-leader.first
	wg.Add(1)
	go func() {
		defer wg.Done()
		followerOut, _, _ = serve(c, follower, fetchRequest(t), upstream)
	}()
	waitForSubscribers(t, c, 2)
	close(release)
	wg.Wait()

	if !leaderOut.Stored || leaderOut.Collapsed || !followerOut.Stored || !followerOut.Collapsed {
		t.Errorf("leader %+v, follower %+v; want both stored, the follower collapsed", leaderOut, followerOut)
	}
	for name, w := range map[string]*collectWriter{"leader": leader, "follower": follower} {
		if _, body, _ := w.result(); !bytes.Equal(body, pack) {
			t.Errorf("%s received %d bytes, want the %d pack bytes", name, len(body), len(pack))
		}
	}
	if got := store.getOffsets(store.keys(packPrefix)[0]); len(got) != 1 {
		t.Errorf("remote Gets of the pack = %v, want one", got)
	}
	if upstream.calls.Load() != 0 {
		t.Errorf("upstream fetched %d times", upstream.calls.Load())
	}
	if got := sumWhere(t, reader, "haybale.response_cache.collapsed.total", nil); got != 1 {
		t.Errorf("collapsed = %d, want 1", got)
	}
}

func TestRemoteMissAndFailureFallThroughToUpstream(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	c, _, reader := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))

	upstream := packFetcher(pack)
	rec := httptest.NewRecorder()
	if out, _, _ := serve(c, rec, fetchRequest(t), upstream); !out.Stored || !bytes.Equal(rec.Body.Bytes(), pack) {
		t.Fatalf("fetch with no remote copy = %+v, want a stored miss from upstream", out)
	}
	if store.count("get", packPrefix) != 1 || upstream.calls.Load() != 1 {
		t.Errorf("remote Gets %d, upstream fetches %d; want one of each", store.count("get", packPrefix), upstream.calls.Load())
	}
	if got := remoteStoreErrors(t, reader, observability.OperationGet); got != 0 {
		t.Errorf("a remote miss counted %d store errors", got)
	}

	store.set(func(m *memBlobStore) {
		m.getHook = func(key string, _ int64) error {
			if strings.HasPrefix(key, packPrefix) {
				return errors.New("memblob: 503 SlowDown")
			}
			return nil
		}
	})
	other := packFetcher(fetchResultBody(t, 3, 100))
	rec = httptest.NewRecorder()
	if out, _, _ := serve(c, rec, otherFetchRequest(t), other); !out.Stored || other.calls.Load() != 1 {
		t.Fatalf("fetch with a failing remote = %+v (upstream calls %d), want a stored miss from upstream", out, other.calls.Load())
	}
	if got := remoteStoreErrors(t, reader, observability.OperationGet); got != 1 {
		t.Errorf("store_errors{tier=remote,operation=get} = %d, want 1", got)
	}
	assertStoreIdle(t, c)
}

func TestRemoteFillResumesAfterAMidStreamFailure(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, offset int64, body io.Reader) io.Reader {
			switch {
			case !strings.HasPrefix(key, packPrefix):
				return body
			case offset == 0:
				return cutReader(body, 80000)
			case offset == 80000:
				return cutReader(body, 50000)
			default:
				return body
			}
		}
	})

	c, _, reader := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	rec := newCollectWriter()
	out, _, aborted := serve(c, rec, fetchRequest(t), upstream)
	if aborted || !out.Stored || upstream.calls.Load() != 0 {
		t.Fatalf("fetch = %+v aborted %v upstream %d, want a stored miss from the remote tier", out, aborted, upstream.calls.Load())
	}
	if _, body, _ := rec.result(); !bytes.Equal(body, pack) {
		t.Errorf("received %d bytes, want the %d pack bytes", len(body), len(pack))
	}
	if got := store.getOffsets(store.keys(packPrefix)[0]); fmt.Sprint(got) != "[0 80000 130000]" {
		t.Errorf("remote Get offsets = %v, want [0 80000 130000]", got)
	}
	if got := remoteStoreErrors(t, reader, observability.OperationGet); got != 2 {
		t.Errorf("store_errors{tier=remote,operation=get} = %d, want one per cut", got)
	}
	assertStoreIdle(t, c)
}

func TestRemoteFillAbortsAfterItsResumesAreSpent(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, key string, offset int64, body io.Reader) io.Reader {
			switch {
			case !strings.HasPrefix(key, packPrefix):
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
	upstream := packFetcher(pack)
	rec := newCollectWriter()
	_, _, aborted := serve(c, rec, fetchRequest(t), upstream)
	if !aborted {
		t.Fatal("the response was not aborted after the remote read could not continue")
	}
	if got := len(store.getOffsets(store.keys(packPrefix)[0])); got != 1+maxRemoteResumes {
		t.Errorf("remote Gets = %d, want the first and %d resumes", got, maxRemoteResumes)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonFetchError); got != 1 {
		t.Errorf("fills discarded with fetch_error = %d, want 1", got)
	}
	if got := store.count("delete", packPrefix); got != 0 {
		t.Errorf("remote deletes = %d, want none after a transport failure", got)
	}
	for _, f := range entryFiles(t, c.opts.Dir) {
		if strings.HasPrefix(f, packPrefix) {
			t.Errorf("pack entry %s was stored", f)
		}
	}
	assertStoreIdle(t, c)
}

func TestRemoteObjectReplacedDuringAResumeIsNotSpliced(t *testing.T) {
	store := newMemBlobStore()
	data := sealBytes(t, testKeyring(t), testHeader(), bytes.Repeat([]byte("x"), 3*segmentSize))
	store.store("k", data)
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, _ string, offset int64, body io.Reader) io.Reader {
			if offset == 0 {
				return cutReader(body, 1000)
			}
			return body
		}
	})
	r := &remoteReader{ctx: context.Background(), store: store, key: "k"}
	defer r.Close()
	if _, err := r.start(); err != nil {
		t.Fatal(err)
	}
	r.enableResumes()
	if _, err := io.ReadFull(r, make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	store.store("k", data)
	if _, err := r.Read(make([]byte, 10)); !errors.Is(err, errRemoteChanged) {
		t.Fatalf("Read after the object was replaced: err = %v, want errRemoteChanged", err)
	}
}

func TestRemoteResumeRequiresTheSameETag(t *testing.T) {
	store := newMemBlobStore()
	store.set(func(m *memBlobStore) { m.etags = true })
	data := bytes.Repeat([]byte("x"), 3*segmentSize)
	store.store("k", data)
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, _ string, offset int64, body io.Reader) io.Reader {
			if offset == 0 {
				return cutReader(body, 1000)
			}
			return body
		}
	})
	r := &remoteReader{ctx: context.Background(), store: store, key: "k"}
	defer r.Close()
	if _, err := r.start(); err != nil {
		t.Fatal(err)
	}
	r.enableResumes()
	if _, err := io.ReadFull(r, make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	// Same size and modification time: only the ETag tells the copies apart.
	store.replaceInPlace("k", bytes.Repeat([]byte("z"), len(data)))
	if _, err := r.Read(make([]byte, 10)); !errors.Is(err, errRemoteChanged) {
		t.Fatalf("Read after an in-place replacement: err = %v, want errRemoteChanged", err)
	}
}

func TestRemoteReaderResumesAStalledBody(t *testing.T) {
	store := newMemBlobStore()
	data := bytes.Repeat([]byte("y"), 10000)
	store.store("k", data)
	never := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, _ string, offset int64, body io.Reader) io.Reader {
			if offset == 0 {
				return &gateReader{ctx: ctx, r: body, n: 4000, release: never}
			}
			return body
		}
	})
	r := &remoteReader{ctx: context.Background(), store: store, key: "k", idle: 50 * time.Millisecond}
	defer r.Close()
	if _, err := r.start(); err != nil {
		t.Fatal(err)
	}
	r.enableResumes()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("ReadAll = %d bytes, %v; want the %d bytes after an idle resume", len(got), err, len(data))
	}
	if offsets := store.getOffsets("k"); fmt.Sprint(offsets) != "[0 4000]" {
		t.Errorf("Get offsets = %v, want [0 4000]", offsets)
	}
}

func TestRemoteHeaderFailingVerificationFallsThroughAndIsDeleted(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	corrupt, _ := store.object(key)
	corrupt = bytes.Clone(corrupt)
	corrupt[preambleLen+100] ^= 0xff
	store.store(key, corrupt)

	logger, logs := newLogCapture()
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	rec := httptest.NewRecorder()
	if out, _, _ := serve(c, rec, fetchRequest(t), upstream); !out.Stored || upstream.calls.Load() != 1 || !bytes.Equal(rec.Body.Bytes(), pack) {
		t.Fatalf("fetch = %+v upstream %d, want a stored miss from upstream", out, upstream.calls.Load())
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 1 || got[0]["tier"] != observability.TierRemote {
		t.Errorf("integrity events = %v, want one for the remote tier", got)
	}
	if got := remoteStoreErrors(t, reader, observability.OperationGet); got != 1 {
		t.Errorf("store_errors{tier=remote,operation=get} = %d, want 1", got)
	}
	waitFor(t, "the corrupt object to be replaced", func() bool {
		data, ok := store.object(key)
		return ok && !bytes.Equal(data, corrupt)
	})
	if store.count("delete", key) != 1 {
		t.Errorf("the corrupt remote object was not deleted")
	}
}

func TestRemoteBodyFailingVerificationAbortsTheFill(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	corrupt, _ := store.object(key)
	corrupt = bytes.Clone(corrupt)
	// The first segment verifies and reaches the client; the second does not.
	firstSegmentEnd := int64(headerFixedPrefix + segmentOverhead + segmentSize)
	corrupt[firstSegmentEnd+500] ^= 0xff
	store.store(key, corrupt)
	release := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.wrapBody = func(ctx context.Context, k string, offset int64, body io.Reader) io.Reader {
			if k != key || offset != 0 {
				return body
			}
			return &gateReader{ctx: ctx, r: body, n: firstSegmentEnd, release: release}
		}
	})

	logger, logs := newLogCapture()
	c, _, reader := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	lsRefs(t, c, refsFetcher(t))
	w := newCollectWriter()
	done := make(chan bool, 1)
	go func() {
		_, _, aborted := serve(c, w, fetchRequest(t), packFetcher(pack))
		done <- aborted
	}()
	select {
	case <-w.first:
	case <-time.After(shortly):
		t.Fatal("the first segment did not reach the client")
	}
	close(release)
	if aborted := <-done; !aborted {
		t.Fatal("a remote entry failing verification mid-stream did not abort the response")
	}
	assertStoreIdle(t, c)
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
		t.Errorf("fills discarded with store_error = %d, want 1", got)
	}
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) == 0 {
		t.Error("no cache_integrity_failed event was logged")
	}
	if _, ok := store.object(key); ok {
		t.Error("the corrupt remote object was not deleted")
	}
}

func TestRemoteFirstSegmentFailingVerificationReleasesTheRequest(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	corrupt, _ := store.object(key)
	corrupt = bytes.Clone(corrupt)
	corrupt[headerFixedPrefix+segmentOverhead+500] ^= 0xff
	store.store(key, corrupt)

	logger, logs := newLogCapture()
	c, _, _ := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
	lsRefs(t, c, refsFetcher(t))
	w := newCollectWriter()
	out, handled, aborted := serve(c, w, fetchRequest(t), packFetcher(pack))
	if handled || aborted || out.Result != observability.ResultBypass {
		t.Fatalf("fetch = %+v handled %v aborted %v, want a bypass", out, handled, aborted)
	}
	if _, body, _ := w.result(); len(body) != 0 {
		t.Errorf("%d bytes reached the client", len(body))
	}
	assertStoreIdle(t, c)
	if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 1 {
		t.Errorf("integrity events = %v, want one", got)
	}
	if _, ok := store.object(key); ok {
		t.Error("the corrupt remote object was not deleted")
	}
}

func TestRemotePackNeedsARecentRefsSuccess(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	c, _, _ := newRemoteTestCache(t, store, nil)
	upstream := packFetcher(pack)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultMiss || upstream.calls.Load() != 1 {
		t.Fatalf("fetch = %+v upstream %d, want an upstream miss", out, upstream.calls.Load())
	}
	if got := store.count("get", packPrefix); got != 0 {
		t.Errorf("the remote pack was read %d times without a recent refs success", got)
	}
}

func TestRemoteRefsHonourRefsMaxAge(t *testing.T) {
	store := newMemBlobStore()
	short := func(o *Options) { o.RefsMaxAge = time.Minute }
	peer, _, _ := newRemoteTestCache(t, store, short)
	lsRefs(t, peer, refsFetcher(t))
	waitFor(t, "the refs upload", func() bool { return len(store.keys(refsPrefix)) == 1 })

	c, clock, _ := newRemoteTestCache(t, store, short)
	refs := refsFetcher(t)
	if out := lsRefs(t, c, refs); !out.Stored || refs.calls.Load() != 0 {
		t.Fatalf("ls-refs = %+v upstream %d, want a stored miss from the remote tier", out, refs.calls.Load())
	}
	clock.Advance(2 * time.Minute)
	if out := lsRefs(t, c, refs); out.Result != observability.ResultMiss || refs.calls.Load() != 1 {
		t.Errorf("ls-refs past refsMaxAge = %+v upstream %d, want an upstream miss", out, refs.calls.Load())
	}
}

func TestRemoteEntryPastRetentionIsDeletedAndRefetched(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	key := store.keys(packPrefix)[0]
	old, _ := store.object(key)

	c, clock, _ := newRemoteTestCache(t, store, nil)
	clock.Advance(25 * time.Hour)
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); !out.Stored || upstream.calls.Load() != 1 {
		t.Fatalf("fetch = %+v upstream %d, want a stored miss from upstream", out, upstream.calls.Load())
	}
	if store.count("delete", key) != 1 {
		t.Error("the expired remote object was not deleted")
	}
	waitFor(t, "the fresh upload", func() bool {
		data, ok := store.object(key)
		return ok && !bytes.Equal(data, old)
	})
}

func TestUploadsSkipPresentPacksAndRefreshRefs(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	refsKey := store.keys(refsPrefix)[0]

	c, _, reader := newRemoteTestCache(t, store, nil)
	// Without a refs success the pack is fetched upstream, so its upload
	// finds the peer's copy.
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack)); !out.Stored {
		t.Fatalf("fetch = %+v, want a stored miss", out)
	}
	waitFor(t, "the pack upload to be skipped", func() bool {
		return uploadsWith(t, reader, observability.UploadResultSkipped) == 1
	})
	lsRefs(t, c, refsFetcher(t))
	waitFor(t, "the refs upload", func() bool {
		return uploadsWith(t, reader, observability.UploadResultUploaded) == 1
	})
	if got := store.count("put", packPrefix); got != 0 {
		t.Errorf("pack puts = %d, want the peer's copy kept", got)
	}
	if got := store.count("put", refsKey); got != 1 {
		t.Errorf("refs puts = %d, want the refresh", got)
	}
}

func TestUploadFailuresAreCountedByResult(t *testing.T) {
	cases := map[string]struct {
		err        error
		result     string
		storeError int64
	}{
		"over the store's limit": {fmt.Errorf("memblob: %w", ErrTooLarge), observability.UploadResultTooLarge, 0},
		"rejected by the store":  {errors.New("memblob: 403 AccessDenied"), observability.UploadResultFailed, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			store.set(func(m *memBlobStore) {
				m.putHook = func(context.Context, string) error { return tc.err }
			})
			c, _, reader := newRemoteTestCache(t, store, nil)
			serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(remotePack(t)))
			waitFor(t, "the upload result", func() bool { return uploadsWith(t, reader, tc.result) == 1 })
			if got := remoteStoreErrors(t, reader, observability.OperationPut); got != tc.storeError {
				t.Errorf("store_errors{tier=remote,operation=put} = %d, want %d", got, tc.storeError)
			}
		})
	}
}

func TestUploadOfARefsEntryAfterAPushIsSkipped(t *testing.T) {
	store := newMemBlobStore()
	c, _, _ := newRemoteTestCache(t, store, nil)
	key := entryKey{Group: GroupRefs, RepoHash: c.keyring.RepoHash(testBaseURL, testRepo)}
	job := uploadJob{key: key, repo: testRepo, gen: c.gens.current(key.RepoHash)}
	c.gens.bump(key.RepoHash)
	if got := c.upload(context.Background(), job); got != observability.UploadResultSkipped {
		t.Errorf("upload = %s, want skipped", got)
	}
	if store.count("put", "") != 0 || store.count("stat", "") != 0 {
		t.Error("a superseded refs entry reached the remote tier")
	}
}

func TestUploadQueueFullDropsEntries(t *testing.T) {
	store := newMemBlobStore()
	release := make(chan struct{})
	store.set(func(m *memBlobStore) {
		m.statHook = func(ctx context.Context, _ string) error {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		}
	})
	c, _, reader := newRemoteTestCache(t, store, nil)
	job := func(i int) uploadJob {
		k := entryKey{Group: GroupPack}
		binary.BigEndian.PutUint32(k.KeyHash[:], uint32(i)) //nolint:gosec // i is a small test index
		return uploadJob{key: k, repo: testRepo}
	}
	for i := range uploadWorkers {
		c.enqueueUpload(job(i))
	}
	waitFor(t, "every worker to be busy", func() bool { return store.count("stat", "") == uploadWorkers })
	for i := range uploadQueueSize {
		c.enqueueUpload(job(uploadWorkers + i))
	}
	if got := uploadsWith(t, reader, observability.UploadResultDropped); got != 0 {
		t.Fatalf("dropped = %d before the queue was full", got)
	}
	c.enqueueUpload(job(1 << 15))
	if got := uploadsWith(t, reader, observability.UploadResultDropped); got != 1 {
		t.Errorf("dropped = %d, want 1 once the queue is full", got)
	}
	close(release)
}

func TestInvalidateDeletesRemoteRefsEntries(t *testing.T) {
	store := newMemBlobStore()
	peer := seedPeer(t, store, remotePack(t))
	peer.Invalidate(context.Background(), testRepo, testBaseURL)
	waitFor(t, "the remote refs entries to go", func() bool { return len(store.keys(refsPrefix)) == 0 })
	if got := store.keys(packPrefix); len(got) != 1 {
		t.Errorf("pack objects = %v, want the pack kept", got)
	}

	c, _, reader := newRemoteTestCache(t, store, nil)
	store.set(func(m *memBlobStore) { m.listErr = errors.New("memblob: 403 AccessDenied") })
	c.Invalidate(context.Background(), testRepo, testBaseURL)
	waitFor(t, "the failed listing to be counted", func() bool {
		return remoteStoreErrors(t, reader, observability.OperationList) == 1
	})
}

func TestPurgeMarkerMakesAPeerDropOlderEntries(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	purger, purgerClock, _ := newRemoteTestCache(t, store, nil)
	lsRefs(t, purger, refsFetcher(t))
	serve(purger, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack))
	waitFor(t, "the uploads", func() bool { return len(store.keys(packPrefix)) == 1 && len(store.keys(refsPrefix)) == 1 })

	c, clock, _ := newRemoteTestCache(t, store, nil)
	lsRefs(t, c, refsFetcher(t))
	upstream := packFetcher(pack)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); !out.Stored || upstream.calls.Load() != 0 {
		t.Fatalf("peer fetch = %+v upstream %d, want a stored remote fill", out, upstream.calls.Load())
	}
	waitFor(t, "the peer's refs upload", func() bool { return store.count("put", refsPrefix) == 2 })

	purgerClock.Advance(time.Minute)
	n, err := purger.Purge(context.Background(), testRepo, testBaseURL, "")
	if err != nil || n != 4 {
		t.Fatalf("Purge = %d, %v; want 2 local and 2 remote entries", n, err)
	}
	if got := store.keys(purgePrefix); len(got) != 1 {
		t.Fatalf("purge markers = %v, want one", got)
	}
	if got := append(store.keys(packPrefix), store.keys(refsPrefix)...); len(got) != 0 {
		t.Fatalf("remote entries after the purge = %v", got)
	}

	// Until the peer's next refs request reads the marker, its local pack
	// still hits.
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultHit {
		t.Fatalf("fetch before the marker is read = %+v, want a hit", out)
	}
	clock.Advance(2 * time.Minute)
	lsRefs(t, c, refsFetcher(t))
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultMiss || upstream.calls.Load() != 1 {
		t.Errorf("fetch after the marker was read = %+v upstream %d, want an upstream miss", out, upstream.calls.Load())
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), upstream); out.Result != observability.ResultHit {
		t.Errorf("fetch of the entry stored after the purge = %+v, want a hit", out)
	}
}

func TestPurgeMarkerReadFailureBacksOff(t *testing.T) {
	store := newMemBlobStore()
	store.set(func(m *memBlobStore) {
		m.getHook = func(key string, _ int64) error {
			if strings.HasPrefix(key, purgePrefix) {
				return errors.New("memblob: dial tcp: connection refused")
			}
			return nil
		}
	})
	c, clock, reader := newRemoteTestCache(t, store, nil)
	refs := refsFetcher(t)
	lsRefs(t, c, refs)
	lsRefs(t, c, refs)
	if got := store.count("get", purgePrefix); got != 1 {
		t.Errorf("marker reads within the backoff = %d, want 1", got)
	}
	if got := remoteStoreErrors(t, reader, observability.OperationGet); got != 1 {
		t.Errorf("store_errors{tier=remote,operation=get} = %d, want 1", got)
	}
	clock.Advance(purgeCheckBackoff)
	lsRefs(t, c, refs)
	if got := store.count("get", purgePrefix); got != 2 {
		t.Errorf("marker reads after the backoff = %d, want 2", got)
	}
}

func TestForgedPurgeMarkersAreRejected(t *testing.T) {
	kr := testKeyring(t)
	repoHash := kr.RepoHash(testBaseURL, testRepo)
	other, err := NewKeyring(testKey(0x17))
	if err != nil {
		t.Fatal(err)
	}
	var elsewhere [32]byte
	elsewhere[0] = 1
	at := newFakeClock().Now().Add(time.Minute)
	cases := map[string]struct {
		kr       Keyring
		repoHash [32]byte
	}{
		"sealed under another key":      {other, repoHash},
		"sealed for another repository": {kr, elsewhere},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			store := newMemBlobStore()
			pack := remotePack(t)
			logger, logs := newLogCapture()
			c, _, _ := newRemoteTestCache(t, store, func(o *Options) { o.Logger = logger })
			lsRefs(t, c, refsFetcher(t))
			serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack))

			marker, err := sealPurgeMarker(tc.kr, tc.repoHash, testRepo, testBaseURL, at, purgeTimes{refs: at, pack: at})
			if err != nil {
				t.Fatal(err)
			}
			store.store(purgeMarkerPath(repoHash), marker)
			lsRefs(t, c, refsFetcher(t))
			if got := logs.securityEvents(t, security.EventCacheIntegrityFailed); len(got) != 1 {
				t.Errorf("integrity events = %d, want 1", len(got))
			}
			if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(pack)); out.Result != observability.ResultHit {
				t.Errorf("fetch = %+v, want the entry kept", out)
			}
		})
	}
}

func TestPurgeRemoteKeepsTheOtherGroupsTime(t *testing.T) {
	store := newMemBlobStore()
	kr := testKeyring(t)
	repoHash := kr.RepoHash(testBaseURL, testRepo)
	t0 := newFakeClock().Now()
	if _, err := PurgeRemote(context.Background(), store, kr, testRepo, testBaseURL, []Group{GroupPack}, t0); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Hour)
	if _, err := PurgeRemote(context.Background(), store, kr, testRepo, testBaseURL, []Group{GroupRefs}, t1); err != nil {
		t.Fatal(err)
	}
	times, found, err := readPurgeMarker(context.Background(), store, kr, repoHash, t1)
	if err != nil || !found {
		t.Fatalf("readPurgeMarker: found %v, %v", found, err)
	}
	if !times.pack.Equal(t0) || !times.refs.Equal(t1) {
		t.Errorf("marker times = %+v, want pack %v and refs %v", times, t0, t1)
	}
}

func TestPurgeRemoteDeletesOnlyEntryObjectsOfTheGroups(t *testing.T) {
	store := newMemBlobStore()
	kr := testKeyring(t)
	repoHash := kr.RepoHash(testBaseURL, testRepo)
	var keyHash [32]byte
	refs := entryKey{Group: GroupRefs, RepoHash: repoHash, KeyHash: keyHash}.Path()
	pack := entryKey{Group: GroupPack, RepoHash: repoHash, KeyHash: keyHash}.Path()
	stray := RepoPrefix(GroupPack, repoHash) + "not-an-entry"
	for _, k := range []string{refs, pack, stray} {
		store.store(k, []byte("x"))
	}
	n, err := PurgeRemote(context.Background(), store, kr, testRepo, testBaseURL, []Group{GroupPack}, newFakeClock().Now())
	if err != nil || n != 1 {
		t.Fatalf("PurgeRemote = %d, %v; want 1 deleted", n, err)
	}
	if got := store.keys("v1/"); fmt.Sprint(got) != fmt.Sprint([]string{stray, purgeMarkerPath(repoHash), refs}) {
		t.Errorf("objects left = %v", got)
	}
}

func TestCloseFlushesPendingUploads(t *testing.T) {
	store := newMemBlobStore()
	release := make(chan struct{})
	var putting atomic.Bool
	store.set(func(m *memBlobStore) {
		m.putHook = func(context.Context, string) error {
			putting.Store(true)
			<-release
			return nil
		}
	})
	c, _, _ := newRemoteTestCache(t, store, nil)
	serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(remotePack(t)))
	waitFor(t, "the upload to start", putting.Load)

	closed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), shortly)
		defer cancel()
		closed <- c.Close(ctx)
	}()
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v before the upload finished", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := store.keys(packPrefix); len(got) != 1 {
		t.Errorf("pack objects = %v, want the flushed upload", got)
	}
}

func TestCloseCancelsUploadsAtItsDeadline(t *testing.T) {
	store := newMemBlobStore()
	cancelled := make(chan struct{})
	var putting atomic.Bool
	store.set(func(m *memBlobStore) {
		m.putHook = func(ctx context.Context, _ string) error {
			putting.Store(true)
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		}
	})
	c, _, _ := newRemoteTestCache(t, store, nil)
	serve(c, httptest.NewRecorder(), fetchRequest(t), packFetcher(remotePack(t)))
	waitFor(t, "the upload to start", putting.Load)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); err == nil || !strings.Contains(err.Error(), "uploads still pending") {
		t.Fatalf("Close = %v, want the pending uploads reported", err)
	}
	select {
	case <-cancelled:
	case <-time.After(shortly):
		t.Fatal("the pending upload was not cancelled")
	}
}
