package cache

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rxbynerd/haybale/internal/observability"
)

// fakeClock is a settable clock safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func cacheDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustClose(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// stressChoice returns deterministic pseudo-random bytes for worker w's
// step i, so a failing schedule is the same on every run.
func stressChoice(w, i int) []byte {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%d/%d", w, i) // writes to a hash never fail
	return h.Sum(nil)
}

func openStore(t *testing.T, dir string, budget int64, clock *fakeClock) *diskStore {
	t.Helper()
	var now func() time.Time
	if clock != nil {
		now = clock.Now
	}
	s, err := openDiskStore(dir, budget, nil, nil, now)
	if err != nil {
		t.Fatalf("openDiskStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func hex64(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func entryPath(group Group, repo, key byte) string {
	return "v1/" + string(group) + "/" + hex64(repo) + "/" + hex64(key)
}

func commitEntry(t *testing.T, s *diskStore, path string, data []byte) {
	t.Helper()
	sp, err := s.Create(path, int64(len(data)))
	if err != nil {
		t.Fatalf("Create(%s): %v", path, err)
	}
	if _, err := sp.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sp.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func readStoreEntry(t *testing.T, s *diskStore, path string) []byte {
	t.Helper()
	e, err := s.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer mustClose(t, e)
	data, err := io.ReadAll(e)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertUsage(t *testing.T, s *diskStore, committed, inflight, pinned int64) {
	t.Helper()
	c, i, p := s.usage()
	if c != committed || i != inflight || p != pinned {
		t.Fatalf("Usage() = (%d, %d, %d), want (%d, %d, %d)", c, i, p, committed, inflight, pinned)
	}
}

func TestOpenDiskStoreRejectsPermissiveModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o705, 0o770, 0o777, 0o701} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		_, err := openDiskStore(dir, 1<<20, nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "chmod 700") {
			t.Errorf("mode %04o: err = %v, want a chmod 700 error", mode, err)
		}
	}
}

func TestOpenDiskStoreCreatesLeafDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	s := openStore(t, dir, 1<<20, nil)
	mustClose(t, s)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != entryDirPerm {
		t.Fatalf("created dir mode = %v, want a directory with mode %04o", info.Mode(), entryDirPerm)
	}
}

func TestOpenDiskStoreRejectsUnusableDirs(t *testing.T) {
	dir := cacheDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]string{"missing parent": filepath.Join(dir, "missing", "cache"), "file": file} {
		if _, err := openDiskStore(d, 1<<20, nil, nil, nil); err == nil {
			t.Errorf("%s: openDiskStore succeeded", name)
		}
	}
	if _, err := openDiskStore(dir, 0, nil, nil, nil); err == nil {
		t.Error("zero budget: openDiskStore succeeded")
	}
}

// ownedInfo is a FileInfo for a directory whose Sys reports an owner.
type ownedInfo struct {
	fs.FileInfo
	sys any
}

func (i ownedInfo) Sys() any { return i.sys }

// ownerCase is one checkCacheDir owner-check case; see ownerCases.
type ownerCase struct {
	name    string
	sys     any
	uid     int
	wantErr bool
}

func TestCheckCacheDirOwner(t *testing.T) {
	info, err := os.Stat(cacheDir(t))
	if err != nil {
		t.Fatal(err)
	}
	type statNoUID struct{ Mode uint32 }

	cases := []ownerCase{
		{"unknown sys type", &statNoUID{}, 1000, false},
		{"nil sys", nil, 1000, false},
	}
	cases = append(cases, ownerCases()...)
	for _, tc := range cases {
		err := checkCacheDir("/cache", ownedInfo{FileInfo: info, sys: tc.sys}, tc.uid)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "chown") {
			t.Errorf("%s: error %q does not say how to fix it", tc.name, err)
		}
	}
	if _, ok := fileOwner(info); !ok && os.Getuid() >= 0 {
		t.Error("fileOwner does not report the owner on this platform")
	}
}

func TestDiskStoreRejectsInvalidPaths(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	h := hex64(0xab)
	invalid := []string{
		"",
		"v1",
		"v1/pack",
		"v1/pack/" + h,
		"v1/pack/" + h + "/",
		"v2/pack/" + h + "/" + h,
		"v1/other/" + h + "/" + h,
		"v1/pack/" + strings.ToUpper(h) + "/" + h,
		"v1/pack/" + h[:63] + "/" + h,
		"v1/pack/" + h + "/" + h + "0",
		"/v1/pack/" + h + "/" + h,
		"./v1/pack/" + h + "/" + h,
		"v1/pack/" + h + "/" + h + "/x",
		"v1/pack/../pack/" + h + "/" + h,
		"v1/pack/" + h + "/../" + h,
		"../v1/pack/" + h + "/" + h,
		"v1//pack/" + h + "/" + h,
		"v1/pack/" + h + "/" + h[:62] + "..",
		".tmp-0123456789abcdef-0123456789abcdef",
	}
	for _, p := range invalid {
		if _, err := s.Open(p); !errors.Is(err, errInvalidPath) {
			t.Errorf("Open(%q) err = %v", p, err)
		}
		if _, err := s.Create(p, 1); !errors.Is(err, errInvalidPath) {
			t.Errorf("Create(%q) err = %v", p, err)
		}
		if err := s.Delete(p); !errors.Is(err, errInvalidPath) {
			t.Errorf("Delete(%q) err = %v", p, err)
		}
	}
	for _, p := range []string{"", "v1/pack/", "v1/pack/" + h, "v1/pack/" + h + "/" + h + "/", "v1/x/" + h + "/", "v1/pack/../" + h + "/"} {
		if _, err := s.DeletePrefix(p); !errors.Is(err, errInvalidPath) {
			t.Errorf("DeletePrefix(%q) err = %v", p, err)
		}
	}
	assertUsage(t, s, 0, 0, 0)
}

func TestDiskStoreSymlinksCannotEscape(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, hex64(2))
	if err := os.WriteFile(secret, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("group directory symlink", func(t *testing.T) {
		dir := cacheDir(t)
		if err := os.MkdirAll(filepath.Join(dir, "v1"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "v1", "pack")); err != nil {
			t.Fatal(err)
		}
		s := openStore(t, dir, 1<<20, nil)
		sp, err := s.Create(entryPath(GroupPack, 1, 2), 10)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Write([]byte("escape")); err != nil {
			t.Fatal(err)
		}
		if err := sp.Commit(); err == nil {
			t.Fatal("Commit through a symlink leading outside the cache succeeded")
		}
		names, _ := os.ReadDir(outside)
		if len(names) != 1 {
			t.Fatalf("outside directory now holds %d files", len(names))
		}
		assertUsage(t, s, 0, 0, 0)
	})

	t.Run("repository directory symlink", func(t *testing.T) {
		dir := cacheDir(t)
		if err := os.MkdirAll(filepath.Join(dir, "v1", "pack"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "v1", "pack", hex64(1))); err != nil {
			t.Fatal(err)
		}
		s := openStore(t, dir, 1<<20, nil)
		p := entryPath(GroupPack, 1, 2)
		if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Open through the symlink: err = %v, want ErrNotFound", err)
		}
		if err := s.Delete(p); err == nil {
			t.Fatal("Delete through a symlink leading outside the cache succeeded")
		}
		if n, err := s.DeletePrefix(entryPath(GroupPack, 1, 2)[:len("v1/pack/")+64+1]); n != 0 || err == nil {
			t.Fatalf("DeletePrefix through the symlink = %d, %v", n, err)
		}
		s.sweep(time.Nanosecond)
		if _, err := os.Stat(secret); err != nil {
			t.Fatalf("file outside the cache was removed: %v", err)
		}
	})

	t.Run("entry file symlink", func(t *testing.T) {
		dir := cacheDir(t)
		repoDir := filepath.Join(dir, "v1", "pack", hex64(1))
		if err := os.MkdirAll(repoDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(secret, filepath.Join(repoDir, hex64(2))); err != nil {
			t.Fatal(err)
		}
		s := openStore(t, dir, 1<<20, nil)
		if _, err := s.Open(entryPath(GroupPack, 1, 2)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Open of a symlinked entry: err = %v, want ErrNotFound", err)
		}
		assertUsage(t, s, 0, 0, 0)
		s.sweep(time.Nanosecond)
		if err := s.Delete(entryPath(GroupPack, 1, 2)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(secret); err != nil {
			t.Fatalf("symlink target outside the cache was removed: %v", err)
		}
	})
}

func TestDiskStoreFilePermissions(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	p := entryPath(GroupRefs, 1, 2)
	commitEntry(t, s, p, []byte("data"))
	for _, rel := range []string{p, "v1", "v1/refs", "v1/refs/" + hex64(1)} {
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %04o", rel, perm)
		}
	}
}

func TestDiskStoreRoundTripAndReopen(t *testing.T) {
	dir := cacheDir(t)
	clock := newFakeClock()
	s := openStore(t, dir, 1<<20, clock)
	p := entryPath(GroupPack, 1, 2)
	if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open before commit: err = %v, want ErrNotFound", err)
	}
	commitEntry(t, s, p, []byte("sealed bytes"))

	e, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if e.Size() != 12 || !e.ModTime().Equal(clock.Now()) {
		t.Fatalf("Size() = %d, ModTime() = %v", e.Size(), e.ModTime())
	}
	if _, err := e.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if rest, _ := io.ReadAll(e); string(rest) != "bytes" {
		t.Fatalf("after Seek read %q", rest)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir, 1<<20, clock)
	assertUsage(t, s2, 12, 0, 0)
	e, err = s2.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, e)
	if !e.ModTime().Equal(clock.Now()) {
		t.Fatalf("reopened ModTime() = %v, want %v", e.ModTime(), clock.Now())
	}
}

func TestDiskStoreReservation(t *testing.T) {
	s := openStore(t, cacheDir(t), 1000, nil)
	a, err := s.Create(entryPath(GroupPack, 1, 1), 600)
	if err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 0, 600, 0)
	if _, err := s.Create(entryPath(GroupPack, 1, 2), 600); !errors.Is(err, errBudget) {
		t.Fatalf("over-budget Create: err = %v, want errBudget", err)
	}
	if _, err := s.Create(entryPath(GroupPack, 1, 2), 2000); !errors.Is(err, errBudget) {
		t.Fatalf("Create larger than the budget: err = %v, want errBudget", err)
	}
	if _, err := s.Create(entryPath(GroupPack, 1, 2), -1); err == nil {
		t.Fatal("negative reservation accepted")
	}
	if _, err := a.Write(make([]byte, 601)); !errors.Is(err, errOverReservation) {
		t.Fatalf("write past the reservation: err = %v", err)
	}
	if _, err := a.Write(make([]byte, 600)); err != nil {
		t.Fatal(err)
	}
	if err := a.Reserve(500); !errors.Is(err, errBudget) {
		t.Fatalf("Reserve past the budget: err = %v, want errBudget", err)
	}
	if err := a.Reserve(400); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write(make([]byte, 400)); err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 0, 1000, 0)
	a.Abort()
	assertUsage(t, s, 0, 0, 0)

	b, err := s.Create(entryPath(GroupPack, 1, 3), 900)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 100, 0, 0)
	if err := b.Reserve(1); !errors.Is(err, errSpoolCommitted) {
		t.Fatalf("Reserve after Commit: err = %v", err)
	}
}

func TestDiskStoreLRUEviction(t *testing.T) {
	m, reader := observability.NewTestMetrics()
	clock := newFakeClock()
	s, err := openDiskStore(cacheDir(t), 300, nil, m, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, s)
	a, b, c := entryPath(GroupPack, 1, 1), entryPath(GroupPack, 1, 2), entryPath(GroupRefs, 1, 3)
	for _, p := range []string{a, b, c} {
		commitEntry(t, s, p, make([]byte, 100))
		clock.Advance(time.Second)
	}
	readStoreEntry(t, s, a) // a is now the most recently used

	commitEntry(t, s, entryPath(GroupPack, 1, 4), make([]byte, 100))
	if _, err := s.Open(b); !errors.Is(err, ErrNotFound) {
		t.Fatalf("least recently used entry survived: err = %v", err)
	}

	// c is now least recently used but open, so a is evicted instead.
	held, err := s.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	commitEntry(t, s, entryPath(GroupPack, 1, 5), make([]byte, 100))
	if _, err := s.Open(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a to be evicted: err = %v", err)
	}
	if _, err := s.Create(entryPath(GroupPack, 1, 6), 250); !errors.Is(err, errBudget) {
		t.Fatalf("Create needing the open entry's space: err = %v, want errBudget", err)
	}
	// A failed reservation evicts nothing.
	assertUsage(t, s, 300, 0, 0)
	mustClose(t, held)

	if got := sumInt64(t, reader, "haybale.response_cache.evictions.total"); got != 2 {
		t.Fatalf("evictions counter = %d, want 2", got)
	}
	if got := sumInt64(t, reader, "haybale.response_cache.disk_bytes"); got != 300 {
		t.Fatalf("disk bytes gauge = %d, want 300", got)
	}
}

// sumInt64 returns the total of every data point of the named int64 sum.
func sumInt64(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
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
				total += dp.Value
			}
		}
	}
	return total
}

// readAsync reads from r in a goroutine until EOF or an error.
func readAsync(r io.Reader) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(r)
		ch <- readResult{data, err}
	}()
	return ch
}

type readResult struct {
	data []byte
	err  error
}

func assertBlocked(t *testing.T, ch <-chan readResult) {
	t.Helper()
	select {
	case res := <-ch:
		t.Fatalf("reader returned early: %q, %v", res.data, res.err)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSpoolReaderFollowsGrowthUntilCommit(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	p := entryPath(GroupPack, 1, 1)
	sp, err := s.Create(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, r)

	if _, err := sp.Write([]byte("first ")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "first " {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}

	done := readAsync(r)
	assertBlocked(t, done)
	if _, err := sp.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	assertBlocked(t, done)
	if err := sp.Commit(); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil || string(res.data) != "second" {
		t.Fatalf("after Commit read %q, %v", res.data, res.err)
	}
	if got := readStoreEntry(t, s, p); string(got) != "first second" {
		t.Fatalf("committed entry = %q", got)
	}
	if _, err := sp.NewReader(); !errors.Is(err, errSpoolCommitted) {
		t.Fatalf("NewReader after Commit: err = %v", err)
	}
}

func TestSpoolTwoReadersAtDifferentOffsets(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	sp, err := s.Create(entryPath(GroupPack, 1, 1), 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("0123456789"), 1000)
	if _, err := sp.Write(body[:5000]); err != nil {
		t.Fatal(err)
	}
	r1, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, r1)
	r2, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	defer mustClose(t, r2)

	head1 := make([]byte, 4000)
	if _, err := io.ReadFull(r1, head1); err != nil {
		t.Fatal(err)
	}
	head2 := make([]byte, 10)
	if _, err := io.ReadFull(r2, head2); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Write(body[5000:]); err != nil {
		t.Fatal(err)
	}
	if err := sp.Commit(); err != nil {
		t.Fatal(err)
	}
	rest1, err1 := io.ReadAll(r1)
	rest2, err2 := io.ReadAll(r2)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if !bytes.Equal(append(head1, rest1...), body) || !bytes.Equal(append(head2, rest2...), body) {
		t.Fatal("readers saw different bytes")
	}
}

func TestSpoolAbortAndFailReachReaders(t *testing.T) {
	sentinel := errors.New("upstream reset")
	cases := map[string]struct {
		end  func(*spool)
		want error
	}{
		"abort":    {func(sp *spool) { sp.Abort() }, errSpoolAborted},
		"fail":     {func(sp *spool) { sp.Fail(sentinel) }, sentinel},
		"fail nil": {func(sp *spool) { sp.Fail(nil) }, errSpoolAborted},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := cacheDir(t)
			s := openStore(t, dir, 1<<20, nil)
			p := entryPath(GroupPack, 1, 1)
			sp, err := s.Create(p, 100)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sp.Write([]byte("partial")); err != nil {
				t.Fatal(err)
			}
			blocked, err := sp.NewReader()
			if err != nil {
				t.Fatal(err)
			}
			behind, err := sp.NewReader()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(blocked, make([]byte, 7)); err != nil {
				t.Fatal(err)
			}
			done := readAsync(blocked)
			assertBlocked(t, done)

			tc.end(sp)
			if res := <-done; !errors.Is(res.err, tc.want) {
				t.Fatalf("blocked reader err = %v, want %v", res.err, tc.want)
			}
			// A reader with unread bytes gets the failure, not the bytes.
			if n, err := behind.Read(make([]byte, 10)); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("lagging reader = %d, %v", n, err)
			}
			if _, err := sp.Write([]byte("x")); !errors.Is(err, tc.want) {
				t.Fatalf("Write after failure: err = %v", err)
			}
			if _, err := sp.NewReader(); !errors.Is(err, tc.want) {
				t.Fatalf("NewReader after failure: err = %v", err)
			}
			if err := sp.Commit(); !errors.Is(err, tc.want) {
				t.Fatalf("Commit after failure: err = %v", err)
			}
			assertUsage(t, s, 0, 0, 7)
			mustClose(t, blocked)
			assertUsage(t, s, 0, 0, 7)
			mustClose(t, behind)
			assertUsage(t, s, 0, 0, 0)

			if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
				t.Fatalf("aborted entry is visible: err = %v", err)
			}
			names, _ := os.ReadDir(dir)
			if len(names) != 0 {
				t.Fatalf("cache dir still holds %v", names)
			}
		})
	}
}

func TestSpoolReaderCloseUnblocksRead(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	sp, err := s.Create(entryPath(GroupPack, 1, 1), 10)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	done := readAsync(r)
	assertBlocked(t, done)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if res := <-done; !errors.Is(res.err, errSpoolReaderClosed) {
		t.Fatalf("err = %v", res.err)
	}
	sp.Abort()
	assertUsage(t, s, 0, 0, 0)
}

func TestPinnedBytesReleasedOnLastClose(t *testing.T) {
	s := openStore(t, cacheDir(t), 1000, nil)
	p := entryPath(GroupPack, 1, 1)
	commitEntry(t, s, p, make([]byte, 400))
	e1, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(p); err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 0, 0, 400)
	if _, err := s.Create(entryPath(GroupPack, 1, 2), 700); !errors.Is(err, errBudget) {
		t.Fatalf("pinned bytes not counted against the budget: err = %v", err)
	}
	if data, err := io.ReadAll(e1); err != nil || len(data) != 400 {
		t.Fatalf("deleted entry unreadable: %d bytes, %v", len(data), err)
	}
	mustClose(t, e1)
	assertUsage(t, s, 0, 0, 400)
	mustClose(t, e2)
	assertUsage(t, s, 0, 0, 0)

	// Replacing an open entry pins the old bytes.
	commitEntry(t, s, p, make([]byte, 100))
	old, err := s.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	commitEntry(t, s, p, make([]byte, 200))
	assertUsage(t, s, 200, 0, 100)
	mustClose(t, old)
	assertUsage(t, s, 200, 0, 0)
}

func TestSpoolReadersPinCommittedEntry(t *testing.T) {
	s := openStore(t, cacheDir(t), 1000, nil)
	p := entryPath(GroupPack, 1, 1)
	sp, err := s.Create(p, 300)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Write(make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	if err := sp.Commit(); err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 300, 0, 0)
	// The spool reader holds the committed entry open, so it is not
	// evictable.
	if _, err := s.Create(entryPath(GroupPack, 1, 2), 800); !errors.Is(err, errBudget) {
		t.Fatalf("entry held by a spool reader was evicted: err = %v", err)
	}
	if err := s.Delete(p); err != nil {
		t.Fatal(err)
	}
	assertUsage(t, s, 0, 0, 300)
	if data, err := io.ReadAll(r); err != nil || len(data) != 300 {
		t.Fatalf("spool reader after delete: %d bytes, %v", len(data), err)
	}
	mustClose(t, r)
	assertUsage(t, s, 0, 0, 0)
}

func TestOpenDiskStoreSweepsOtherProcessTemps(t *testing.T) {
	dir := cacheDir(t)
	own := tempNamePrefix + processTempToken() + "-0123456789abcdef"
	other := tempNamePrefix + "fedcba9876543210-0123456789abcdef"
	keep := []string{own, ".tmp-notours", "unrelated.txt", ".tmp-0123456789ABCDEF-0123456789abcdef"}
	for _, name := range append([]string{other}, keep...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := openStore(t, dir, 1<<20, nil)
	if _, err := os.Stat(filepath.Join(dir, other)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("another process's temp file survived: %v", err)
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
	assertUsage(t, s, 0, 0, 0)
}

func TestDiskStoreDeletePrefix(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	for k := byte(1); k <= 3; k++ {
		commitEntry(t, s, entryPath(GroupRefs, 1, k), []byte("refs"))
	}
	commitEntry(t, s, entryPath(GroupPack, 1, 1), []byte("pack"))
	commitEntry(t, s, entryPath(GroupRefs, 2, 1), []byte("other"))
	if err := os.WriteFile(filepath.Join(dir, "v1", "refs", hex64(1), "README"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	prefix := "v1/refs/" + hex64(1) + "/"
	n, err := s.DeletePrefix(prefix)
	if err != nil || n != 3 {
		t.Fatalf("DeletePrefix = %d, %v; want 3", n, err)
	}
	if n, err := s.DeletePrefix(prefix); err != nil || n != 0 {
		t.Fatalf("second DeletePrefix = %d, %v; want 0", n, err)
	}
	if n, err := s.DeletePrefix("v1/pack/" + hex64(9) + "/"); err != nil || n != 0 {
		t.Fatalf("DeletePrefix of an absent repository = %d, %v", n, err)
	}
	assertUsage(t, s, 9, 0, 0)
	readStoreEntry(t, s, entryPath(GroupPack, 1, 1))
	readStoreEntry(t, s, entryPath(GroupRefs, 2, 1))
	if _, err := os.Stat(filepath.Join(dir, "v1", "refs", hex64(1), "README")); err != nil {
		t.Fatalf("a name outside the entry pattern was deleted: %v", err)
	}
	if err := s.Delete(entryPath(GroupRefs, 1, 1)); err != nil {
		t.Fatalf("Delete of an absent entry: %v", err)
	}
}

func TestDiskStoreCloseFailsLiveSpools(t *testing.T) {
	s := openStore(t, cacheDir(t), 1<<20, nil)
	sp, err := s.Create(entryPath(GroupPack, 1, 1), 10)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	done := readAsync(r)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if res := <-done; !errors.Is(res.err, errStoreClosed) {
		t.Fatalf("reader err = %v", res.err)
	}
	mustClose(t, r)
	if _, err := s.Open(entryPath(GroupPack, 1, 1)); !errors.Is(err, errStoreClosed) {
		t.Fatalf("Open after Close: err = %v", err)
	}
	if _, err := s.Create(entryPath(GroupPack, 1, 1), 1); !errors.Is(err, errStoreClosed) {
		t.Fatalf("Create after Close: err = %v", err)
	}
}

// TestDiskStoreConcurrentStress runs creates, reads, deletes and sweeps
// against a small budget; run it with -race. Every entry's bytes are one
// repeated value, so a reader can tell a torn or mixed entry.
func TestDiskStoreConcurrentStress(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 4096, nil)
	paths := make([]string, 8)
	for i := range paths {
		paths[i] = entryPath([]Group{GroupRefs, GroupPack}[i%2], byte(i%3), byte(i))
	}

	var wg sync.WaitGroup
	errc := make(chan error, 64)
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 300 {
				c := stressChoice(w, i)
				p := paths[int(c[0])%len(paths)]
				var err error
				switch op := int(c[1]) % 10; {
				case op < 4:
					n := 1 + (int(c[3])<<8|int(c[4]))%1500
					err = stressWrite(s, p, c[2], n, c[5]%5 == 0)
				case op < 8:
					err = stressRead(s, p)
				case op < 9:
					err = s.Delete(p)
				default:
					_, err = s.DeletePrefix(p[:len(p)-64])
				}
				if err != nil {
					errc <- err
					return
				}
			}
		}()
	}
	stop := make(chan struct{})
	sweeper := make(chan struct{})
	go func() {
		defer close(sweeper)
		for {
			select {
			case <-stop:
				return
			default:
				s.sweep(time.Hour)
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-sweeper
	close(errc)
	for err := range errc {
		t.Error(err)
	}

	committed, inflight, pinned := s.usage()
	if inflight != 0 || pinned != 0 {
		t.Fatalf("after all spools and readers closed: inflight %d, pinned %d", inflight, pinned)
	}
	var onDisk int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasPrefix(d.Name(), tempNamePrefix) {
			return fmt.Errorf("temp file %s left behind", d.Name())
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		onDisk += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if committed != onDisk {
		t.Fatalf("committed %d bytes, %d on disk", committed, onDisk)
	}
	if committed > 4096 {
		t.Fatalf("committed %d bytes over a 4096-byte budget", committed)
	}
}

func stressWrite(s *diskStore, p string, value byte, n int, abort bool) (err error) {
	sp, err := s.Create(p, int64(n))
	if errors.Is(err, errBudget) {
		return nil
	}
	if err != nil {
		return err
	}
	r, err := sp.NewReader()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	if _, err := sp.Write(bytes.Repeat([]byte{value}, n)); err != nil {
		return err
	}
	if abort {
		sp.Abort()
		if _, err := io.ReadAll(r); !errors.Is(err, errSpoolAborted) {
			return fmt.Errorf("reader after abort: %w", err)
		}
		return nil
	}
	if err := sp.Commit(); err != nil {
		return err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, bytes.Repeat([]byte{value}, n)) {
		return fmt.Errorf("spool reader saw %d bytes that differ from the %d written", len(data), n)
	}
	return nil
}

func stressRead(s *diskStore, p string) (err error) {
	e, err := s.Open(p)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	data, err := io.ReadAll(e)
	if err != nil {
		return err
	}
	if int64(len(data)) != e.Size() || len(data) == 0 {
		return fmt.Errorf("entry %s: read %d bytes, size %d", p, len(data), e.Size())
	}
	if bytes.Count(data, data[:1]) != len(data) {
		return fmt.Errorf("entry %s has mixed content", p)
	}
	return nil
}

func TestSpoolDiscardDrainsReaders(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	p := entryPath(GroupPack, 1, 1)
	sp, err := s.Create(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	ahead, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	behind, err := sp.NewReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Write([]byte("complete response")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ahead, make([]byte, 17)); err != nil {
		t.Fatal(err)
	}
	done := readAsync(ahead)
	assertBlocked(t, done)

	sp.Discard()
	if res := <-done; res.err != nil || len(res.data) != 0 {
		t.Fatalf("reader at the end after Discard: %q, %v", res.data, res.err)
	}
	if got, err := io.ReadAll(behind); err != nil || string(got) != "complete response" {
		t.Fatalf("lagging reader after Discard: %q, %v", got, err)
	}
	assertUsage(t, s, 0, 0, 17)
	if _, err := sp.Write([]byte("x")); !errors.Is(err, errSpoolDiscarded) {
		t.Fatalf("Write after Discard: err = %v", err)
	}
	if _, err := sp.NewReader(); !errors.Is(err, errSpoolDiscarded) {
		t.Fatalf("NewReader after Discard: err = %v", err)
	}
	if err := sp.Commit(); !errors.Is(err, errSpoolDiscarded) {
		t.Fatalf("Commit after Discard: err = %v", err)
	}
	mustClose(t, ahead)
	mustClose(t, behind)
	assertUsage(t, s, 0, 0, 0)
	if _, err := s.Open(p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("discarded entry is visible: err = %v", err)
	}
	if names, _ := os.ReadDir(dir); len(names) != 0 {
		t.Fatalf("cache dir still holds %v", names)
	}
}

// TestSealedEntryThroughSpool writes a sealed entry into a spool while a
// sealedReader follows it, for both ways a fill can end cleanly.
func TestSealedEntryThroughSpool(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 3*segmentSize+99)
	for name, end := range map[string]func(*spool) error{
		"commit":  (*spool).Commit,
		"discard": func(sp *spool) error { sp.Discard(); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := openStore(t, cacheDir(t), 1<<24, nil)
			sp, err := s.Create(entryPath(GroupPack, 1, 1), sealedSize(int64(len(body)))+segmentOverhead)
			if err != nil {
				t.Fatal(err)
			}
			r, err := sp.NewReader()
			if err != nil {
				t.Fatal(err)
			}
			defer mustClose(t, r)

			read := make(chan readResult, 1)
			go func() {
				sr, err := newSealedReader(r, kr)
				if err != nil {
					read <- readResult{nil, err}
					return
				}
				data, err := io.ReadAll(sr)
				read <- readResult{data, err}
			}()

			w, err := newSealedWriter(sp, kr, testHeader())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(body[:10]); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(body[10:]); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := end(sp); err != nil {
				t.Fatal(err)
			}
			res := <-read
			if res.err != nil || !bytes.Equal(res.data, body) {
				t.Fatalf("read %d bytes, err %v", len(res.data), res.err)
			}
		})
	}
}

func TestPurgeDiskPrefixLeavesLiveServerAlone(t *testing.T) {
	dir := cacheDir(t)
	s := openStore(t, dir, 1<<20, nil)
	for k := byte(1); k <= 2; k++ {
		commitEntry(t, s, entryPath(GroupRefs, 1, k), []byte("refs"))
	}
	commitEntry(t, s, entryPath(GroupPack, 1, 1), []byte("pack"))
	live, err := s.Create(entryPath(GroupRefs, 1, 3), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}

	n, err := PurgeDiskPrefix(dir, "v1/refs/"+hex64(1)+"/")
	if err != nil || n != 2 {
		t.Fatalf("PurgeDiskPrefix = %d, %v; want 2", n, err)
	}
	if _, err := s.Open(entryPath(GroupRefs, 1, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("server Open of a purged entry: err = %v", err)
	}
	s.sweep(time.Hour)
	assertUsage(t, s, 4, 10, 0)
	if err := live.Commit(); err != nil {
		t.Fatalf("live spool broken by purge: %v", err)
	}
	readStoreEntry(t, s, entryPath(GroupPack, 1, 1))

	if _, err := PurgeDiskPrefix(dir, "v1/refs/"+hex64(1)); !errors.Is(err, errInvalidPath) {
		t.Fatalf("invalid prefix: err = %v", err)
	}
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeDiskPrefix(loose, "v1/refs/"+hex64(1)+"/"); err == nil {
		t.Fatal("PurgeDiskPrefix accepted a group-accessible directory")
	}
}
