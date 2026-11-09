package cache

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sync"
	"sync/atomic"

	"github.com/rxbynerd/haybale/internal/observability"
)

var (
	errSpoolCommitted    = errors.New("cache: spool is committed; open the entry instead")
	errOverReservation   = errors.New("cache: spool write exceeds its reservation")
	errSpoolReaderClosed = errors.New("cache: spool reader is closed")
	errSpoolDiscarded    = errors.New("cache: spool is discarded")
)

type spoolState uint8

const (
	spoolOpen spoolState = iota
	spoolCommitted
	spoolDiscarded
	spoolFailed
)

// spool is an entry being written: a temporary file in the cache
// directory that readers can follow while it grows. It has a single
// writer; Write, Reserve, Commit and Discard must not be called
// concurrently with each other. Abort, Fail and NewReader may be called
// from any goroutine.
type spool struct {
	store *diskStore
	path  string
	temp  string
	f     *os.File

	reserved atomic.Int64

	// Guarded by store.mu.
	readers int
	entry   *entryState // the committed entry, after Commit
	pinned  int64       // bytes held by readers after Discard or failure

	mu      sync.Mutex
	cond    *sync.Cond
	written int64
	state   spoolState
	err     error
}

// Create starts a spool for the entry at path with reserve bytes reserved
// against the budget, evicting unopened least-recently-used entries to make
// room. It returns errBudget when the reservation cannot fit.
func (s *diskStore) Create(path string, reserve int64) (*spool, error) {
	if !validEntryPath(path) {
		return nil, fmt.Errorf("%w %q", errInvalidPath, path)
	}
	if reserve < 0 {
		return nil, fmt.Errorf("cache: reservation must not be negative, got %d", reserve)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStoreClosed
	}
	if err := s.reserveLocked(reserve); err != nil {
		s.reportLocked()
		return nil, err
	}
	temp := s.tempPrefix + randomHex(tempTokenLen/2)
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, entryFilePerm)
	if err != nil {
		s.inflight -= reserve
		s.reportLocked()
		s.storeError(observability.OperationCreate, err)
		return nil, err
	}
	sp := &spool{store: s, path: path, temp: temp, f: f}
	sp.cond = sync.NewCond(&sp.mu)
	sp.reserved.Store(reserve)
	s.spools[temp] = sp
	s.reportLocked()
	return sp, nil
}

// Write appends sealed bytes and wakes readers. Writing past the
// reservation fails; call Reserve first.
func (sp *spool) Write(p []byte) (int, error) {
	sp.mu.Lock()
	state, written, err := sp.state, sp.written, sp.err
	sp.mu.Unlock()
	switch state {
	case spoolCommitted:
		return 0, errSpoolCommitted
	case spoolDiscarded, spoolFailed:
		return 0, err
	}
	if reserved := sp.reserved.Load(); written+int64(len(p)) > reserved {
		return 0, fmt.Errorf("%w of %d bytes", errOverReservation, reserved)
	}
	n, err := sp.f.Write(p)
	sp.mu.Lock()
	if sp.state == spoolOpen {
		sp.written += int64(n)
		sp.cond.Broadcast()
	}
	sp.mu.Unlock()
	if err != nil {
		sp.store.storeError(observability.OperationWrite, err)
	}
	return n, err
}

// Reserve grows the reservation by additional bytes, with the same
// eviction and errBudget behaviour as Create.
func (sp *spool) Reserve(additional int64) error {
	if additional < 0 {
		return fmt.Errorf("cache: reservation must not be negative, got %d", additional)
	}
	s := sp.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := sp.openErr(); err != nil {
		return err
	}
	err := s.reserveLocked(additional)
	if err == nil {
		sp.reserved.Add(additional)
	}
	s.reportLocked()
	return err
}

// NewReader returns a reader over the bytes written so far that blocks for
// more until the spool is committed, aborted or failed.
func (sp *spool) NewReader() (*spoolReader, error) {
	s := sp.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := sp.openErr(); err != nil {
		return nil, err
	}
	f, err := s.root.Open(sp.temp)
	if err != nil {
		s.storeError(observability.OperationOpen, err)
		return nil, err
	}
	sp.readers++
	return &spoolReader{sp: sp, f: f}, nil
}

// Commit syncs the spool and renames it to its entry path, replacing any
// entry already there. The reservation becomes committed bytes and
// existing readers keep reading to EOF. On failure the spool is failed
// with the returned error.
func (sp *spool) Commit() error {
	if err := sp.openErr(); err != nil {
		return err
	}
	if err := sp.f.Sync(); err != nil {
		return sp.failCommit(err)
	}
	if err := sp.f.Close(); err != nil {
		return sp.failCommit(err)
	}

	s := sp.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := sp.openErr(); err != nil {
		return err
	}
	if err := s.root.MkdirAll(path.Dir(sp.path), entryDirPerm); err != nil {
		return sp.failCommitLocked(err)
	}
	if err := s.root.Rename(sp.temp, sp.path); err != nil {
		return sp.failCommitLocked(err)
	}
	now := s.now()
	if err := s.root.Chtimes(sp.path, now, now); err != nil {
		s.logger.Warn("set entry modification time", "error", err)
	}

	sp.mu.Lock()
	written := sp.written
	sp.state = spoolCommitted
	sp.cond.Broadcast()
	sp.mu.Unlock()

	if old, ok := s.entries[sp.path]; ok {
		s.dropLocked(old)
	}
	es := s.indexLocked(sp.path, written, now)
	es.readers = sp.readers
	es.elem = s.lru.PushFront(es)
	sp.entry = es
	s.inflight -= sp.reserved.Load()
	delete(s.spools, sp.temp)
	s.reportLocked()
	return nil
}

// Abort discards the spool and releases its reservation. Readers receive
// errSpoolAborted. Aborting a finished spool does nothing.
func (sp *spool) Abort() { sp.Fail(errSpoolAborted) }

// Fail discards the spool like Abort, and readers receive err (or
// errSpoolAborted when err is nil).
func (sp *spool) Fail(err error) {
	if err == nil {
		err = errSpoolAborted
	}
	s := sp.store
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(sp, err)
}

func (sp *spool) failCommit(err error) error {
	sp.store.mu.Lock()
	defer sp.store.mu.Unlock()
	return sp.failCommitLocked(err)
}

func (sp *spool) failCommitLocked(err error) error {
	sp.store.storeError(observability.OperationCommit, err)
	sp.store.failLocked(sp, err)
	return err
}

// Discard ends the spool without committing it: readers receive every byte
// already written and then io.EOF, and the file is removed and the
// reservation released. Call it after the last Write. The written bytes
// stay pinned until its readers close. Discarding a finished spool does
// nothing.
func (sp *spool) Discard() {
	s := sp.store
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endLocked(sp, spoolDiscarded, errSpoolDiscarded)
}

// failLocked moves an open spool to the failed state; see endLocked.
func (s *diskStore) failLocked(sp *spool, err error) { s.endLocked(sp, spoolFailed, err) }

// endLocked moves an open spool to state, which is spoolDiscarded or
// spoolFailed, removes its file and releases its reservation. err is what
// later spool operations return. Bytes already written stay pinned until
// its readers close.
func (s *diskStore) endLocked(sp *spool, state spoolState, err error) {
	sp.mu.Lock()
	if sp.state != spoolOpen {
		sp.mu.Unlock()
		return
	}
	sp.state = state
	sp.err = err
	written := sp.written
	sp.cond.Broadcast()
	sp.mu.Unlock()

	_ = sp.f.Close()
	s.removeLocked(sp.temp, observability.OperationAbort)
	s.inflight -= sp.reserved.Load()
	delete(s.spools, sp.temp)
	if sp.readers > 0 {
		sp.pinned = written
		s.pinned += written
	}
	s.reportLocked()
}

// openErr returns nil while the spool is open, and otherwise the error an
// operation that needs an open spool reports.
func (sp *spool) openErr() error {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	switch sp.state {
	case spoolCommitted:
		return errSpoolCommitted
	case spoolDiscarded, spoolFailed:
		return sp.err
	}
	return nil
}

// spoolReader reads a spool from the start through its own descriptor,
// waiting for bytes that have not been written yet. It is not safe for
// concurrent use, except that Close may be called to stop a blocked Read.
type spoolReader struct {
	sp     *spool
	f      *os.File
	off    int64
	closed bool // guarded by sp.mu
}

// Read returns written bytes, blocking until more are written. After the
// spool is committed or discarded it returns io.EOF once every byte has
// been read; after Abort or Fail it returns the failure error immediately.
func (r *spoolReader) Read(p []byte) (int, error) {
	sp := r.sp
	sp.mu.Lock()
	var avail int64
	for {
		if r.closed {
			sp.mu.Unlock()
			return 0, errSpoolReaderClosed
		}
		if sp.state == spoolFailed {
			err := sp.err
			sp.mu.Unlock()
			return 0, err
		}
		if avail = sp.written - r.off; avail > 0 {
			break
		}
		if sp.state == spoolCommitted || sp.state == spoolDiscarded {
			sp.mu.Unlock()
			return 0, io.EOF
		}
		if len(p) == 0 {
			sp.mu.Unlock()
			return 0, nil
		}
		sp.cond.Wait()
	}
	sp.mu.Unlock()

	if int64(len(p)) > avail {
		p = p[:avail]
	}
	n, err := r.f.ReadAt(p, r.off)
	r.off += int64(n)
	if errors.Is(err, io.EOF) {
		if n > 0 {
			err = nil
		} else {
			err = io.ErrUnexpectedEOF
		}
	}
	return n, err
}

// Close closes the reader and wakes a blocked Read. Calling Close again
// returns nil.
func (r *spoolReader) Close() error {
	sp := r.sp
	s := sp.store
	s.mu.Lock()
	sp.mu.Lock()
	if r.closed {
		sp.mu.Unlock()
		s.mu.Unlock()
		return nil
	}
	r.closed = true
	state := sp.state
	sp.cond.Broadcast()
	sp.mu.Unlock()

	sp.readers--
	switch state {
	case spoolCommitted:
		s.releaseLocked(sp.entry)
	case spoolDiscarded, spoolFailed:
		if sp.readers == 0 {
			s.pinned -= sp.pinned
			sp.pinned = 0
		}
	}
	s.reportLocked()
	s.mu.Unlock()

	if err := r.f.Close(); err != nil && !errors.Is(err, fs.ErrClosed) {
		return err
	}
	return nil
}
