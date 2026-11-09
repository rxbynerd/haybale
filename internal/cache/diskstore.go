package cache

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
)

var (
	// ErrBudget is returned when a reservation cannot fit within the disk
	// budget even after evicting every unopened entry.
	ErrBudget = errors.New("cache: disk budget exhausted")
	// ErrSpoolAborted is the error spool readers receive after Abort.
	ErrSpoolAborted = errors.New("cache: spool aborted")

	errStoreClosed = errors.New("cache: disk store is closed")
	errInvalidPath = errors.New("cache: invalid entry path")
)

const (
	// cacheDirModeMask is the set of permission bits (group and other) that
	// must be unset on the cache directory.
	cacheDirModeMask = 0o077
	entryDirPerm     = 0o700
	entryFilePerm    = 0o600

	layoutVersionDir = "v1"
	tempNamePrefix   = ".tmp-"
	tempTokenLen     = 16 // hex characters in each part of a temp name
)

// processTempToken identifies temporary files created by this process. It
// is random rather than the process id because container processes often
// run as pid 1 across restarts.
var processTempToken = sync.OnceValue(func() string { return randomHex(tempTokenLen / 2) })

// DiskStore is the local disk tier: committed sealed entries addressed by
// "v1/<group>/<repoHash hex>/<keyHash hex>" paths, and spools for entries
// being written. It moves opaque bytes and knows nothing about
// repositories or keys. Every file operation goes through an os.Root
// opened on the cache directory, so no path or symlink can reach outside
// it, and every name is validated against the strict entry or temp-file
// pattern before it is opened or deleted.
//
// A budget bounds committed bytes, spool reservations, and pinned bytes
// (entries removed from the index while readers still hold them open).
// Recency for least-recently-used eviction is kept in an in-memory index
// built from file modification times when the store opens and updated on
// every Open and Commit; modification times are never changed by reads, so
// they always record when an entry was committed and retention is measured
// from that.
//
// One lock orders reader attach and detach, commits, deletions and
// eviction, so a reader can never open an entry that is being evicted and
// eviction never touches an entry or spool that is open. A directory must
// be served by one DiskStore at a time: opening a store deletes temporary
// files left by any other process.
type DiskStore struct {
	root       *os.Root
	dir        string
	budget     int64
	logger     *slog.Logger
	metrics    *observability.Metrics
	now        func() time.Time
	tempPrefix string

	mu        sync.Mutex
	closed    bool
	entries   map[string]*entryState
	lru       list.List // of *entryState; front is most recently used
	spools    map[string]*Spool
	seq       uint64
	committed int64
	inflight  int64
	pinned    int64
	reported  int64 // committed+pinned last added to the disk-bytes gauge
}

// entryState is one committed entry in the index, or a removed entry whose
// bytes stay pinned while readers hold it open (elem is then nil).
type entryState struct {
	path    string
	size    int64
	modTime time.Time
	elem    *list.Element
	readers int
	seq     uint64
}

// OpenDiskStore opens the cache directory dir with a budget of budget
// bytes. dir must exist, be a directory owned by the process user (where
// the platform reports ownership), and grant no group or other
// permissions. Committed entries are indexed for the budget, and temporary
// files from other processes are deleted. A nil logger discards, nil
// metrics record nothing, and a nil now uses time.Now.
func OpenDiskStore(dir string, budget int64, logger *slog.Logger, metrics *observability.Metrics, now func() time.Time) (*DiskStore, error) {
	if budget <= 0 {
		return nil, fmt.Errorf("cache: disk budget must be greater than zero, got %d", budget)
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if metrics == nil {
		metrics = observability.NewNoopMetrics()
	}
	if now == nil {
		now = time.Now
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("cache: open dir %q: %w", dir, err)
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("cache: stat dir %q: %w", dir, err)
	}
	if err := checkCacheDir(dir, info, os.Getuid()); err != nil {
		_ = root.Close()
		return nil, err
	}
	s := &DiskStore{
		root:       root,
		dir:        dir,
		budget:     budget,
		logger:     logger,
		metrics:    metrics,
		now:        now,
		tempPrefix: tempNamePrefix + processTempToken() + "-",
		entries:    make(map[string]*entryState),
		spools:     make(map[string]*Spool),
	}
	res, err := s.scan()
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("cache: scan dir %q: %w", dir, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Slice(res.entries, func(i, j int) bool { return res.entries[i].modTime.Before(res.entries[j].modTime) })
	for _, e := range res.entries {
		es := s.indexLocked(e.path, e.size, e.modTime)
		es.elem = s.lru.PushFront(es)
	}
	for _, name := range res.temps {
		if !strings.HasPrefix(name, s.tempPrefix) {
			s.removeLocked(name, "sweep")
		}
	}
	for _, name := range res.irregular {
		s.logger.Warn("cache: ignoring a non-regular file at an entry path", "path", name)
	}
	s.reportLocked()
	return s, nil
}

// checkCacheDir verifies that info describes a directory private to the
// user uid. A negative uid, or a platform that does not report ownership,
// skips the owner check.
func checkCacheDir(dir string, info fs.FileInfo, uid int) error {
	if !info.IsDir() {
		return fmt.Errorf("cache: dir %q is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&cacheDirModeMask != 0 {
		return fmt.Errorf("cache: dir %q has mode %04o, which grants group or other access; chmod 700 (owner only) before starting haybale", dir, perm)
	}
	if owner, ok := fileOwner(info); ok {
		if uid >= 0 && owner != uint64(uid) {
			return fmt.Errorf("cache: dir %q is owned by uid %d, not the haybale process uid %d; chown it to the process user", dir, owner, uid)
		}
	}
	return nil
}

// fileOwner returns the owning uid recorded in info.Sys() on platforms
// whose stat structure has a numeric Uid field, and false elsewhere.
// Reflection keeps this portable without per-platform files.
func fileOwner(info fs.FileInfo) (uint64, bool) {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return 0, false
	}
	uid := v.Elem().FieldByName("Uid")
	if !uid.IsValid() || !uid.CanUint() {
		return 0, false
	}
	return uid.Uint(), true
}

// Entry is an open committed entry. It reads the sealed bytes from a
// descriptor of its own, so it stays readable after the entry is deleted,
// evicted or replaced; its bytes count against the budget until Close.
type Entry struct {
	f       *os.File
	store   *DiskStore
	state   *entryState
	size    int64
	modTime time.Time
	once    sync.Once
}

// Open opens the committed entry at path and marks it most recently used.
// It returns ErrNotFound when there is no such entry.
func (s *DiskStore) Open(path string) (*Entry, error) {
	if !validEntryPath(path) {
		return nil, fmt.Errorf("%w %q", errInvalidPath, path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStoreClosed
	}
	es, ok := s.entries[path]
	if !ok {
		return nil, ErrNotFound
	}
	f, err := s.root.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.dropLocked(es)
			s.reportLocked()
			return nil, ErrNotFound
		}
		s.storeError("open", err)
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("cache: entry %q is not a regular file", path)
	}
	if err != nil {
		_ = f.Close()
		s.storeError("open", err)
		return nil, err
	}
	if info.Size() != es.size {
		s.committed += info.Size() - es.size
		es.size = info.Size()
		s.reportLocked()
	}
	es.readers++
	s.lru.MoveToFront(es.elem)
	return &Entry{f: f, store: s, state: es, size: es.size, modTime: es.modTime}, nil
}

// Read reads sealed bytes.
func (e *Entry) Read(p []byte) (int, error) { return e.f.Read(p) }

// Seek sets the offset of the next Read.
func (e *Entry) Seek(offset int64, whence int) (int64, error) { return e.f.Seek(offset, whence) }

// Size returns the sealed size of the entry in bytes.
func (e *Entry) Size() int64 { return e.size }

// ModTime returns the time the entry was committed.
func (e *Entry) ModTime() time.Time { return e.modTime }

// Close closes the entry, releasing its pinned bytes if it was removed
// while open. Calling Close again returns nil.
func (e *Entry) Close() error {
	var err error
	e.once.Do(func() {
		err = e.f.Close()
		e.store.mu.Lock()
		e.store.releaseLocked(e.state)
		e.store.reportLocked()
		e.store.mu.Unlock()
	})
	return err
}

// Delete removes the entry at path. Readers that hold it open keep
// reading it. Deleting an absent entry returns nil.
func (s *DiskStore) Delete(path string) error {
	if !validEntryPath(path) {
		return fmt.Errorf("%w %q", errInvalidPath, path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}
	if err := s.root.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.storeError("delete", err)
		return err
	}
	if es, ok := s.entries[path]; ok {
		s.dropLocked(es)
	}
	s.reportLocked()
	return nil
}

// DeletePrefix removes every entry under prefix, which must have the form
// "v1/<group>/<repoHash hex>/", and returns the number of files removed.
func (s *DiskStore) DeletePrefix(prefix string) (int, error) {
	dir, ok := strings.CutSuffix(prefix, "/")
	if !ok || !validRepoDir(dir) {
		return 0, fmt.Errorf("%w prefix %q", errInvalidPath, prefix)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errStoreClosed
	}
	defer s.reportLocked()

	names, err := fs.ReadDir(s.root.FS(), dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.storeError("delete", err)
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, d := range names {
		path := dir + "/" + d.Name()
		if !validEntryPath(path) {
			continue
		}
		if err := s.root.Remove(path); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				s.storeError("delete", err)
				if firstErr == nil {
					firstErr = err
				}
			}
			continue
		}
		removed++
		if es, ok := s.entries[path]; ok {
			s.dropLocked(es)
		}
	}
	for path, es := range s.entries {
		if strings.HasPrefix(path, prefix) {
			if _, err := s.root.Lstat(path); errors.Is(err, fs.ErrNotExist) {
				s.dropLocked(es)
			}
		}
	}
	// Removing the repository directory fails harmlessly if anything is
	// left in it.
	_ = s.root.Remove(dir)
	return removed, firstErr
}

// Usage returns the bytes held by committed entries, reserved by live
// spools, and pinned by readers of removed entries or aborted spools.
func (s *DiskStore) Usage() (committed, inflight, pinned int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed, s.inflight, s.pinned
}

// Close fails every live spool and closes the directory. Open entries and
// readers stay readable until they are closed.
func (s *DiskStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	for _, sp := range s.spools {
		s.failLocked(sp, errStoreClosed)
	}
	s.closed = true
	return s.root.Close()
}

// indexLocked adds a committed entry to the index without placing it in
// the LRU list.
func (s *DiskStore) indexLocked(path string, size int64, modTime time.Time) *entryState {
	s.seq++
	es := &entryState{path: path, size: size, modTime: modTime, seq: s.seq}
	s.entries[path] = es
	s.committed += size
	return es
}

// dropLocked removes es from the index. Its bytes become pinned while it
// has readers.
func (s *DiskStore) dropLocked(es *entryState) {
	if es.elem == nil {
		return
	}
	s.lru.Remove(es.elem)
	es.elem = nil
	delete(s.entries, es.path)
	s.committed -= es.size
	if es.readers > 0 {
		s.pinned += es.size
	}
}

// releaseLocked detaches one reader from es.
func (s *DiskStore) releaseLocked(es *entryState) {
	es.readers--
	if es.readers == 0 && es.elem == nil {
		s.pinned -= es.size
	}
}

// reserveLocked reserves n bytes for a spool, evicting unopened entries
// from the least recently used end as needed.
func (s *DiskStore) reserveLocked(n int64) error {
	if n > s.budget {
		return fmt.Errorf("%w: %d bytes exceed the %d-byte budget", ErrBudget, n, s.budget)
	}
	if over := s.committed + s.inflight + s.pinned + n - s.budget; over > 0 {
		if err := s.evictLocked(over); err != nil {
			return err
		}
	}
	s.inflight += n
	return nil
}

// evictLocked frees at least need bytes by deleting unopened entries from
// the least recently used end. It evicts nothing when that cannot free
// enough.
func (s *DiskStore) evictLocked(need int64) error {
	var candidates []*entryState
	var available int64
	for e := s.lru.Back(); e != nil && available < need; e = e.Prev() {
		if es := e.Value.(*entryState); es.readers == 0 {
			candidates = append(candidates, es)
			available += es.size
		}
	}
	if available < need {
		return fmt.Errorf("%w: cannot free %d bytes", ErrBudget, need)
	}
	var freed, evicted int64
	for _, es := range candidates {
		if !s.removeLocked(es.path, "evict") {
			continue
		}
		freed += es.size
		evicted++
		s.dropLocked(es)
	}
	if evicted > 0 {
		s.metrics.RecordResponseCacheEvictions(context.Background(), evicted)
	}
	if freed < need {
		return fmt.Errorf("%w: cannot free %d bytes", ErrBudget, need)
	}
	return nil
}

// removeLocked deletes name if it is an entry path or temp-file name, and
// reports whether it is gone.
func (s *DiskStore) removeLocked(name, operation string) bool {
	if !validEntryPath(name) && !validTempName(name) {
		s.storeError(operation, fmt.Errorf("%w %q", errInvalidPath, name))
		return false
	}
	if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.storeError(operation, err)
		return false
	}
	return true
}

// reportLocked brings the disk-bytes gauge up to date with committed and
// pinned bytes.
func (s *DiskStore) reportLocked() {
	if cur := s.committed + s.pinned; cur != s.reported {
		s.metrics.ResponseCacheDiskBytesAdd(context.Background(), cur-s.reported)
		s.reported = cur
	}
}

func (s *DiskStore) storeError(operation string, err error) {
	s.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierDisk, operation)
	s.logger.Warn("cache: disk store operation failed", "operation", operation, "error", err)
}

// validEntryPath reports whether p is "v1/<refs|pack>/<64 hex>/<64 hex>".
func validEntryPath(p string) bool {
	dir, name, ok := cutLast(p)
	return ok && validRepoDir(dir) && isHex64(name)
}

// validRepoDir reports whether p is "v1/<refs|pack>/<64 hex>".
func validRepoDir(p string) bool {
	dir, name, ok := cutLast(p)
	return ok && validGroupDir(dir) && isHex64(name)
}

// validGroupDir reports whether p is "v1/refs" or "v1/pack".
func validGroupDir(p string) bool {
	return p == layoutVersionDir+"/"+string(GroupRefs) || p == layoutVersionDir+"/"+string(GroupPack)
}

func cutLast(p string) (dir, name string, ok bool) {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "", "", false
	}
	return p[:i], p[i+1:], true
}

func isHex64(s string) bool { return len(s) == 64 && isLowerHex(s) }

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validTempName reports whether name is ".tmp-<16 hex>-<16 hex>".
func validTempName(name string) bool {
	rest, ok := strings.CutPrefix(name, tempNamePrefix)
	if !ok || len(rest) != 2*tempTokenLen+1 || rest[tempTokenLen] != '-' {
		return false
	}
	return isLowerHex(rest[:tempTokenLen]) && isLowerHex(rest[tempTokenLen+1:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error; it aborts the process if
	// the system source fails.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
