package cache

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

// integrityCache is a cache with captured logs and metrics for the tests
// that corrupt entries.
func integrityCache(t *testing.T, mutate func(*Options)) (*Cache, *logCapture, *sdkmetric.ManualReader) {
	t.Helper()
	logger, logs := newLogCapture()
	m, reader := observability.NewTestMetrics()
	c, _ := newTestCache(t, func(o *Options) {
		o.AccessRecheck = 0
		o.Logger = logger
		o.Metrics = m
		if mutate != nil {
			mutate(o)
		}
	})
	return c, logs, reader
}

// expectIntegrityEvent asserts exactly n cache_integrity_failed events
// carrying only the repository and class.
func expectIntegrityEvent(t *testing.T, logs *logCapture, n int) {
	t.Helper()
	events := logs.securityEvents(t, security.EventCacheIntegrityFailed)
	if len(events) != n {
		t.Fatalf("cache_integrity_failed events = %d, want %d", len(events), n)
	}
	for _, ev := range events {
		for _, k := range []string{"host", "owner", "repo", "class"} {
			if _, ok := ev[k]; !ok {
				t.Errorf("event lacks %q: %v", k, ev)
			}
		}
		for k := range ev {
			switch k {
			case "time", "level", "msg", "event", "host", "owner", "repo", "class":
			default:
				t.Errorf("event carries unexpected attribute %q: %v", k, ev)
			}
		}
		if ev["host"] != testRepo.Host || ev["owner"] != testRepo.Owner || ev["repo"] != testRepo.Name || ev["class"] != string(classFetch) {
			t.Errorf("event attributes = %v", ev)
		}
	}
}

// storeAndCorrupt stores one pack entry through the cache, then applies
// mutate to its bytes on disk and returns the file path.
func storeAndCorrupt(t *testing.T, c *Cache, fetch Fetcher, mutate func(data []byte) []byte) string {
	t.Helper()
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !handled || !out.Stored {
		t.Fatalf("first request = %+v handled %v, want a stored miss", out, handled)
	}
	path := entryPathOnDisk(t, c)
	writeEntry(t, path, mutate(readEntryFile(t, path)))
	// The index must learn the new size before the entry is opened.
	c.store.sweep(c.opts.Retention)
	return path
}

func TestCorruptEntryIsDeletedAndRefetched(t *testing.T) {
	c, logs, reader := integrityCache(t, nil)
	body := fetchResultBody(t, 60, 5000)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: body}
	path := storeAndCorrupt(t, c, fetch, func(data []byte) []byte {
		starts := segmentStarts(t, data)
		if len(starts) < 5 {
			t.Fatalf("entry has %d segments, want at least three body segments", len(starts)-1)
		}
		data[starts[1]+frameLen+100] ^= 0x01
		return data
	})
	baseline, _, _ := c.store.usage()

	rec := newCollectWriter()
	if _, _, aborted := serve(c, rec, fetchRequest(t), fetch); !aborted {
		t.Fatal("a segment corrupted after the first was served did not abort the response")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("corrupt entry still on disk (stat err = %v)", err)
	}
	if committed, inflight, pinned := c.store.usage(); committed != 0 || inflight != 0 || pinned != 0 {
		t.Errorf("usage after deletion = (%d, %d, %d), want all zero (baseline committed was %d)", committed, inflight, pinned, baseline)
	}
	expectIntegrityEvent(t, logs, 1)
	if got := storeErrors(t, reader, observability.OperationOpen); got != 1 {
		t.Errorf("store_errors(open) = %d, want 1", got)
	}
	if s := logs.String(); bytes.Contains([]byte(s), []byte(filepath.Base(path))) {
		t.Error("log output names the entry file")
	}

	out, handled, aborted := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch)
	if aborted || !handled || out.Result != observability.ResultMiss || !out.Stored {
		t.Fatalf("after deletion: %+v handled %v aborted %v, want a stored miss", out, handled, aborted)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
		t.Errorf("after refetch = %+v, want a hit", out)
	}
	if fetch.calls.Load() != 2 {
		t.Errorf("fetched %d times, want 2", fetch.calls.Load())
	}
	assertStoreIdle(t, c)
}

func TestCorruptHeaderIsDeletedBeforeAnyByteAndRefetched(t *testing.T) {
	c, logs, _ := integrityCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 30, 5000)}
	path := storeAndCorrupt(t, c, fetch, func(data []byte) []byte {
		data[preambleLen+10] ^= 0xff
		return data
	})
	rec := httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
	if aborted || !handled || out.Result != observability.ResultMiss || !out.Stored {
		t.Fatalf("after header corruption: %+v handled %v aborted %v, want a stored miss", out, handled, aborted)
	}
	if !bytes.Equal(rec.Body.Bytes(), fetch.body) {
		t.Error("refetched response does not match upstream")
	}
	expectIntegrityEvent(t, logs, 1)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("refetched entry is not on disk: %v", err)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
		t.Errorf("after refetch = %+v, want a hit", out)
	}
	assertStoreIdle(t, c)
}

func TestCorruptFirstSegmentIsAMissNotAnAbort(t *testing.T) {
	c, logs, _ := integrityCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 30, 5000)}
	storeAndCorrupt(t, c, fetch, func(data []byte) []byte {
		data[headerFixedPrefix+frameLen+10] ^= 0x01
		return data
	})
	rec := httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
	if aborted || !handled || out.Result != observability.ResultMiss || !out.Stored || !bytes.Equal(rec.Body.Bytes(), fetch.body) {
		t.Fatalf("corrupt first segment: %+v handled %v aborted %v, want a stored miss with the upstream body", out, handled, aborted)
	}
	expectIntegrityEvent(t, logs, 1)
	assertStoreIdle(t, c)
}

func TestTruncatedEntryOnDiskAbortsOnceThenRefills(t *testing.T) {
	c, logs, reader := integrityCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 60, 5000)}
	path := storeAndCorrupt(t, c, fetch, func(data []byte) []byte {
		return data[:len(data)/2]
	})
	if _, _, aborted := serve(c, newCollectWriter(), fetchRequest(t), fetch); !aborted {
		t.Fatal("truncated entry did not abort the response")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("truncated entry still on disk (stat err = %v)", err)
	}
	expectIntegrityEvent(t, logs, 1)
	if got := storeErrors(t, reader, observability.OperationOpen); got != 1 {
		t.Errorf("store_errors(open) = %d, want 1", got)
	}
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultMiss || !out.Stored {
		t.Errorf("after truncation = %+v, want a stored miss", out)
	}
	assertStoreIdle(t, c)
}

func TestRelocatedEntryFailsVerification(t *testing.T) {
	c, logs, _ := integrityCache(t, nil)
	fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 3, 5000)}
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !handled || !out.Stored {
		t.Fatalf("first request = %+v handled %v, want a stored miss", out, handled)
	}
	src := entryPathOnDisk(t, c)
	other, _, _ := classifyRequest(t, otherFetchRequest(t))
	dst := filepath.Join(c.opts.Dir, filepath.FromSlash(entryKey{Group: GroupPack, RepoHash: c.keyring.RepoHash(testBaseURL, testRepo), KeyHash: c.keyring.pathHash(other.Digest)}.Path()))
	writeEntry(t, dst, readEntryFile(t, src))
	c.store.sweep(c.opts.Retention)

	otherFetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 2, 100)}
	rec := httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, otherFetchRequest(t), otherFetch)
	if aborted || !handled || out.Result != observability.ResultMiss || !out.Stored || !bytes.Equal(rec.Body.Bytes(), otherFetch.body) {
		t.Fatalf("relocated entry: %+v handled %v aborted %v, want a stored miss with the upstream body", out, handled, aborted)
	}
	expectIntegrityEvent(t, logs, 1)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); out.Result != observability.ResultHit {
		t.Errorf("original entry = %+v, want a hit", out)
	}
	assertStoreIdle(t, c)
}

func TestDeleteEntryLeavesAReplacementAlone(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	p := entryPath(GroupPack, 1, 1)
	commitEntry(t, s, p, []byte("first"))
	first, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	commitEntry(t, s, p, []byte("second"))
	if err := s.DeleteEntry(first); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	mustClose(t, first)
	if got := readStoreEntry(t, s, p); string(got) != "second" {
		t.Fatalf("entry after deleting the stale handle = %q, want the replacement", got)
	}
	assertUsage(t, s, 6, 0, 0)
}

// entryKeyFor returns the cache key of a classified request.
func entryKeyFor(t *testing.T, c *Cache, r *http.Request) entryKey {
	t.Helper()
	req, _, _ := classifyRequest(t, r)
	return entryKey{Group: req.Class.Group(), RepoHash: c.keyring.RepoHash(testBaseURL, testRepo), KeyHash: c.keyring.pathHash(req.Digest)}
}

// plantEntry writes a sealed entry for key with the given creation time
// and indexes it.
func plantEntry(t *testing.T, c *Cache, key entryKey, class Class, createdAt time.Time, body []byte) string {
	t.Helper()
	hdr := entryHeader{
		Group:       key.Group,
		Class:       class,
		RepoHash:    key.RepoHash,
		KeyHash:     key.KeyHash,
		Repo:        testRepo.Host + "/" + testRepo.Owner + "/" + testRepo.Name,
		BaseURL:     testBaseURL.String(),
		CreatedAt:   createdAt,
		ContentType: responseContentType(class),
		Protocol:    "version=2",
	}
	path := filepath.Join(c.opts.Dir, filepath.FromSlash(key.Path()))
	data := sealBytes(t, c.keyring, hdr, body)
	// The janitor prunes empty entry directories concurrently, so the
	// directory created here can vanish before the file lands; retry
	// until the write succeeds.
	var err error
	for range 50 {
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			break
		}
		err = os.WriteFile(path, data, 0o600) //nolint:gosec // path is within the test's own cache directory
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	c.store.sweep(c.opts.Retention)
	return path
}

func TestReplayedEntryIsRejectedByItsCreationTime(t *testing.T) {
	c, clock := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute })
	pack := &fixedFetcher{status: 200, contentType: contentTypeResult, body: fetchResultBody(t, 3, 5000)}
	refs := &fixedFetcher{status: 200, contentType: contentTypeResult, body: lsRefsResultBody(t)}
	serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), refs)
	if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), pack); !out.Stored {
		t.Fatalf("pack not stored: %+v", out)
	}
	files := entryFiles(t, c.opts.Dir)
	var packFile string
	for _, f := range files {
		if strings.HasPrefix(f, "v1/pack/") {
			packFile = filepath.Join(c.opts.Dir, filepath.FromSlash(f))
		}
	}
	if packFile == "" {
		t.Fatalf("no pack entry among %v", files)
	}
	saved := readEntryFile(t, packFile)
	if n, err := c.Purge(context.Background(), testRepo, testBaseURL, GroupPack); err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v", n, err)
	}

	clock.Advance(48 * time.Hour)
	serve(c, httptest.NewRecorder(), postV2(lsRefsBody(t)), refs)
	// Purge removed the repository directory along with the entry.
	if err := os.MkdirAll(filepath.Dir(packFile), 0o700); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, packFile, saved)
	now := clock.Now()
	if err := os.Chtimes(packFile, now, now); err != nil {
		t.Fatal(err)
	}
	c.store.sweep(c.opts.Retention)

	out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), pack)
	if !handled || out.Result != observability.ResultMiss || !out.Stored {
		t.Fatalf("replayed entry: %+v handled %v, want a stored miss", out, handled)
	}
	if pack.calls.Load() != 2 {
		t.Errorf("pack fetched %d times, want 2", pack.calls.Load())
	}
	if bytes.Equal(readEntryFile(t, packFile), saved) {
		t.Error("the replayed file was served and kept")
	}
	assertStoreIdle(t, c)
}

func TestRefsFreshnessComesFromTheCreationTime(t *testing.T) {
	c, clock := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
	refs := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)}
	serve(c, httptest.NewRecorder(), get(), refs)
	path := entryPathOnDisk(t, c)
	clock.Advance(2 * time.Minute)
	now := clock.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	out, _, _ := serve(c, httptest.NewRecorder(), get(), refs)
	if out.Result != observability.ResultMiss || refs.calls.Load() != 2 {
		t.Fatalf("refs older than refsMaxAge with a fresh mtime: %+v, fetched %d times; want a miss and 2", out, refs.calls.Load())
	}
	assertStoreIdle(t, c)
}

func TestCreationTimeSkewTolerance(t *testing.T) {
	for name, tc := range map[string]struct {
		ahead     time.Duration
		wantHit   bool
		wantEvent int
	}{
		"four minutes ahead is served": {4 * time.Minute, true, 0},
		"six minutes ahead is corrupt": {6 * time.Minute, false, 1},
	} {
		t.Run(name, func(t *testing.T) {
			c, logs, _ := integrityCache(t, nil)
			body := fetchResultBody(t, 2, 100)
			key := entryKeyFor(t, c, fetchRequest(t))
			path := plantEntry(t, c, key, classFetch, c.now().Add(tc.ahead), body)
			fetch := &fixedFetcher{status: 200, contentType: contentTypeResult, body: body}
			rec := httptest.NewRecorder()
			out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
			if aborted || !handled || !bytes.Equal(rec.Body.Bytes(), body) {
				t.Fatalf("Serve = %+v handled %v aborted %v", out, handled, aborted)
			}
			if (out.Result == observability.ResultHit) != tc.wantHit {
				t.Errorf("result = %s, want hit %v", out.Result, tc.wantHit)
			}
			expectIntegrityEvent(t, logs, tc.wantEvent)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("entry missing after the request: %v", err)
			}
			assertStoreIdle(t, c)
		})
	}
}

func TestEntriesSealedUnderAnotherKeyAreRemovedAtStart(t *testing.T) {
	dir := cacheDir(t)
	body := fetchResultBody(t, 2, 100)
	store := func(t *testing.T, kr Keyring) {
		t.Helper()
		c, _ := newTestCache(t, func(o *Options) { o.Dir = dir; o.Keyring = kr; o.RefsMaxAge = time.Minute; o.AccessRecheck = 0 })
		serve(c, httptest.NewRecorder(), fetchRequest(t), &fixedFetcher{status: 200, contentType: contentTypeResult, body: body})
		serve(c, httptest.NewRecorder(), get(), &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)})
		if files := entryFiles(t, dir); len(files) != 2 {
			t.Fatalf("entries = %v, want two", files)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	reopen := func(t *testing.T, kr Keyring) (*Cache, *logCapture) {
		t.Helper()
		logger, logs := newLogCapture()
		c, _ := newTestCache(t, func(o *Options) {
			o.Dir = dir
			o.Keyring = kr
			o.Logger = logger
			o.RefsMaxAge = time.Minute
			o.AccessRecheck = 0
		})
		return c, logs
	}

	t.Run("same configured key keeps entries", func(t *testing.T) {
		store(t, testKeyring(t))
		c, logs := reopen(t, testKeyring(t))
		if files := entryFiles(t, dir); len(files) != 2 {
			t.Fatalf("entries after reopen = %v, want two", files)
		}
		if recs := logs.records(t, "removed cache entries sealed under another key"); len(recs) != 0 {
			t.Errorf("removal logged although nothing was removed: %v", recs)
		}
		if out, _, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), &fixedFetcher{}); out.Result != observability.ResultHit {
			t.Errorf("after reopen = %+v, want a hit", out)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ephemeral key removes every entry", func(t *testing.T) {
		kr, err := EphemeralKeyring()
		if err != nil {
			t.Fatal(err)
		}
		c, logs := reopen(t, kr)
		if files := entryFiles(t, dir); len(files) != 0 {
			t.Fatalf("entries after reopen = %v, want none", files)
		}
		recs := logs.records(t, "removed cache entries sealed under another key")
		if len(recs) != 1 || recs[0]["entries"] != float64(2) {
			t.Errorf("removal log = %v, want one line with entries=2", recs)
		}
		if committed, inflight, pinned := c.store.usage(); committed != 0 || inflight != 0 || pinned != 0 {
			t.Errorf("usage = (%d, %d, %d), want zero", committed, inflight, pinned)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("different configured key removes every entry", func(t *testing.T) {
		store(t, testKeyring(t))
		other, err := NewKeyring(testKey(0x43))
		if err != nil {
			t.Fatal(err)
		}
		c, _ := reopen(t, other)
		if files := entryFiles(t, dir); len(files) != 0 {
			t.Fatalf("entries after reopen = %v, want none", files)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("short and wrong-magic files are removed", func(t *testing.T) {
		store(t, testKeyring(t))
		files := entryFiles(t, dir)
		short := filepath.Join(dir, filepath.FromSlash(files[0]))
		writeEntry(t, short, []byte("HBC"))
		wrong := filepath.Join(dir, filepath.FromSlash(files[1]))
		data := readEntryFile(t, wrong)
		copy(data, "NOPE")
		writeEntry(t, wrong, data)
		c, logs := reopen(t, testKeyring(t))
		if files := entryFiles(t, dir); len(files) != 0 {
			t.Fatalf("entries after reopen = %v, want none", files)
		}
		if recs := logs.records(t, "removed cache entries sealed under another key"); len(recs) != 1 || recs[0]["entries"] != float64(2) {
			t.Errorf("removal log = %v, want one line with entries=2", recs)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRemoveForeignEntriesRunsBeforeTheJanitor(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	kr := testKeyring(t)
	foreign, err := NewKeyring(testKey(0x44))
	if err != nil {
		t.Fatal(err)
	}
	commitEntry(t, s, entryPath(GroupPack, 1, 1), sealBytes(t, kr, testHeader(), []byte("mine")))
	commitEntry(t, s, entryPath(GroupPack, 1, 2), sealBytes(t, foreign, testHeader(), []byte("theirs")))
	commitEntry(t, s, entryPath(GroupPack, 1, 3), []byte("not even a preamble"))
	removed, err := s.removeForeignEntries(kr.activeID())
	if err != nil || removed != 2 {
		t.Fatalf("removeForeignEntries = %d, %v; want 2", removed, err)
	}
	if _, err := s.Open(entryPath(GroupPack, 1, 1)); err != nil {
		t.Errorf("entry under the active key was removed: %v", err)
	}
	for _, k := range []byte{2, 3} {
		if _, err := s.Open(entryPath(GroupPack, 1, k)); err == nil {
			t.Errorf("entry %d survived", k)
		}
	}
}
