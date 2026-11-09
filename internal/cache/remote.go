package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

const (
	// uploadWorkers is the number of goroutines uploading committed
	// entries to the remote tier.
	uploadWorkers = 4
	// uploadQueueSize bounds the entries waiting for an upload worker; an
	// entry committed while the queue is full is not uploaded.
	uploadQueueSize = 256
	// uploadTimeout bounds one upload, including its Stat.
	uploadTimeout = 15 * time.Minute
	// remoteMaintenanceTimeout bounds one background deletion pass on the
	// remote tier.
	remoteMaintenanceTimeout = time.Minute
	// maxRemoteResumes is how many ranged Gets a remote fill issues after
	// its body read fails before the fill cannot continue.
	maxRemoteResumes = 3
	// remoteResumeBackoff is the pause before the first resume; each later
	// resume waits twice as long as the one before.
	remoteResumeBackoff = 100 * time.Millisecond
	// remoteSizeSlack is how far a remote object may exceed the sealed size
	// of maxEntrySize, covering the segments that flushes seal early.
	remoteSizeSlack = 1 << 20
)

var (
	// errRemoteChanged reports that a remote object was replaced while a
	// fill was reading it, so its bytes cannot be resumed.
	errRemoteChanged = errors.New("cache: remote object changed during the read")
	// errRemoteRead reports a remote read that failed past its resumes.
	errRemoteRead = errors.New("cache: remote read failed")
)

// remoteEligible reports whether a fill may be served from the remote
// tier: the same freshness rules as a disk hit, so a pack needs a recent
// upstream refs success and a refs entry needs a positive refsMaxAge.
func (f *fill) remoteEligible() bool {
	if f.c.remote == nil || !f.shared {
		return false
	}
	switch f.key.Group {
	case GroupPack:
		return f.c.access.recent(f.key.RepoHash, f.c.now())
	case GroupRefs:
		return f.c.opts.RefsMaxAge > 0
	default:
		return false
	}
}

// fillFromRemote serves the fill from the remote tier's copy of the entry.
// It returns false, having spooled nothing, when the remote tier has no
// usable copy or fails before the first byte; the fill then goes
// upstream. Once it returns true the fill is settled. The remote object is
// the sealed entry, so its bytes are spooled as they are and verified as
// they pass; a verification failure is a store error and a
// cache_integrity_failed event.
func (f *fill) fillFromRemote() bool {
	c := f.c
	path := f.key.Path()
	src := &remoteReader{
		ctx:     f.ctx,
		store:   c.remote,
		key:     path,
		idle:    c.opts.IdleTimeout,
		onError: func(err error) { f.remoteReadFailed(err) },
	}
	defer src.Close()
	info, err := src.start()
	switch {
	case errors.Is(err, ErrNotFound):
		return false
	case err != nil:
		f.remoteReadFailed(err)
		return false
	case info.Size < sealedSize(0) || info.Size > sealedSize(c.opts.MaxEntrySize)+remoteSizeSlack:
		f.logger().Debug("remote entry size is out of range; fetching upstream", "size", info.Size)
		return false
	}
	// A failed read here has already been recorded by src.
	prefix := make([]byte, headerFixedPrefix)
	if _, err := io.ReadFull(src, prefix); err != nil {
		return false
	}
	tee := &spoolTee{src: src}
	sr, err := newSealedReader(io.MultiReader(bytes.NewReader(prefix), tee), c.keyring)
	if err == nil {
		err = f.checkRemoteHeader(sr.Header())
	}
	if err != nil {
		f.remoteIntegrityFailed(err)
		return false
	}
	h := sr.Header()
	if !f.remoteFresh(h) {
		return false
	}

	sp, err := c.store.Create(path, info.Size, true)
	if err != nil {
		f.release(storeReason(err), transientCooldown)
		return true
	}
	f.spool = sp
	f.source = observability.TierRemote
	if _, err := sp.Write(prefix); err != nil {
		f.abort(err, storeReason(err))
		return true
	}
	tee.w = sp
	f.setOutcome(fillOutcome{kind: fillStreaming, contentType: h.ContentType, tier: observability.TierRemote})
	f.streamRemote(sr, tee)
	return true
}

// checkRemoteHeader requires a remote entry's verified header to belong at
// the fill's key, for its class, with the class's Content-Type.
func (f *fill) checkRemoteHeader(h entryHeader) error {
	if err := verifyHeader(h, f.key, f.c.now()); err != nil {
		return err
	}
	if h.Class != f.req.Class || h.ContentType != responseContentType(f.req.Class) {
		return fmt.Errorf("%w: header class does not match the request", ErrIntegrity)
	}
	return nil
}

// remoteFresh applies the hit freshness rules to a remote entry. An entry
// past retention or older than the repository's last purge is deleted
// from the remote tier.
func (f *fill) remoteFresh(h entryHeader) bool {
	c := f.c
	age := c.now().Sub(h.CreatedAt)
	switch {
	case age > c.opts.Retention || c.purges.covers(f.key, h.CreatedAt):
		c.deleteRemote(f.key.Path())
		return false
	case f.key.Group == GroupRefs && age > c.opts.RefsMaxAge:
		return false
	}
	return true
}

// streamRemote reads the remote entry through sr, which verifies every
// segment while tee writes the sealed bytes into the spool, then commits
// or discards the spool.
func (f *fill) streamRemote(sr *sealedReader, tee *spoolTee) {
	defer func() {
		if h := f.c.hooks.afterDecision; h != nil {
			h(f.key)
		}
	}()
	buf := make([]byte, segmentSize)
	for {
		_, err := sr.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		switch {
		case err == nil:
			continue
		case tee.err != nil:
			f.abort(tee.err, storeReason(tee.err))
		case errors.Is(err, ErrIntegrity):
			f.remoteIntegrityFailed(err)
			f.abort(err, observability.FillReasonStoreError)
		default:
			f.abort(err, observability.FillReasonStoreError)
		}
		return
	}
	f.fetched, _ = sr.bodyLength()
	switch {
	case f.fetched > f.c.opts.MaxEntrySize:
		f.discard(observability.FillReasonTooLarge, 0)
	case f.key.Group == GroupRefs && f.c.gens.current(f.key.RepoHash) != f.gen:
		f.discard(observability.FillReasonGeneration, 0)
	default:
		f.commit()
	}
}

// remoteReadFailed records a failed remote read. A read cut short because
// the fill itself ended is not a store error.
func (f *fill) remoteReadFailed(err error) {
	if f.ctx.Err() != nil {
		return
	}
	f.c.remoteError(observability.OperationGet, err)
}

// remoteIntegrityFailed records a remote entry that failed verification
// and deletes it from the remote tier, so a later upload can replace it.
func (f *fill) remoteIntegrityFailed(err error) {
	c := f.c
	c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierRemote, observability.OperationGet)
	security.Log(c.logger, security.EventCacheIntegrityFailed, "host", f.repo.Host, "owner", f.repo.Owner, "repo", f.repo.Name, "class", f.req.Class, "tier", observability.TierRemote)
	c.logger.Debug("remote entry failed verification; deleting it", "host", f.repo.Host, "class", f.req.Class, "error", err)
	c.deleteRemote(f.key.Path())
}

// spoolTee passes reads from src through, writing every byte read to w.
// w must be set before the first Read.
type spoolTee struct {
	src io.Reader
	w   io.Writer
	err error
}

func (t *spoolTee) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		if _, werr := t.w.Write(p[:n]); werr != nil {
			t.err = werr
			return 0, werr
		}
	}
	return n, err
}

// remoteReader reads one remote object of known size from the start. When
// a body read fails, or stalls for idle, it resumes with a ranged Get from
// the current offset, up to maxRemoteResumes times, provided the object's
// size and modification time are unchanged. It ends with io.EOF exactly
// at the object's size. It is not safe for concurrent use.
type remoteReader struct {
	ctx     context.Context
	store   BlobStore
	key     string
	idle    time.Duration
	onError func(error)

	size    int64
	modTime time.Time
	off     int64
	rc      io.ReadCloser
	cancel  context.CancelFunc
	timer   *time.Timer
	resumes int
	lastErr error
}

// start issues the first Get and returns the object's description.
func (r *remoteReader) start() (ObjectInfo, error) {
	ctx, cancel := context.WithCancel(r.ctx)
	rc, info, err := r.store.Get(ctx, r.key, 0)
	if err != nil {
		cancel()
		return ObjectInfo{}, err
	}
	r.size, r.modTime = info.Size, info.ModTime
	r.attach(rc, cancel)
	return info, nil
}

func (r *remoteReader) Read(p []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if rest := r.size - r.off; int64(len(p)) > rest {
		p = p[:rest]
	}
	for {
		if r.rc != nil {
			n, err := r.rc.Read(p)
			if n > 0 {
				r.off += int64(n)
				if r.timer != nil {
					r.timer.Reset(r.idle)
				}
				return n, nil
			}
			if err == nil {
				continue
			}
			r.detach()
			if cerr := r.ctx.Err(); cerr != nil {
				return 0, cerr
			}
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			r.failed(err)
		}
		if r.resumes >= maxRemoteResumes {
			return 0, fmt.Errorf("%w after %d resumes: %w", errRemoteRead, r.resumes, r.lastErr)
		}
		if err := r.resume(); err != nil {
			return 0, err
		}
	}
}

// resume waits out the backoff and issues a ranged Get from the current
// offset. A Get that fails counts as a used resume and leaves the reader
// detached; the error returned is fatal.
func (r *remoteReader) resume() error {
	wait := remoteResumeBackoff << r.resumes
	r.resumes++
	t := time.NewTimer(wait)
	select {
	case <-r.ctx.Done():
		t.Stop()
		return r.ctx.Err()
	case <-t.C:
	}
	ctx, cancel := context.WithCancel(r.ctx)
	rc, info, err := r.store.Get(ctx, r.key, r.off)
	switch {
	case err != nil:
		cancel()
		if cerr := r.ctx.Err(); cerr != nil {
			return cerr
		}
		r.failed(err)
		return nil
	case info.Size != r.size || !info.ModTime.Equal(r.modTime):
		_ = rc.Close()
		cancel()
		return errRemoteChanged
	}
	r.attach(rc, cancel)
	return nil
}

func (r *remoteReader) failed(err error) {
	r.lastErr = err
	if r.onError != nil {
		r.onError(err)
	}
}

// attach makes rc the current body. A body that delivers no bytes for idle
// is cancelled, which fails its next read and triggers a resume.
func (r *remoteReader) attach(rc io.ReadCloser, cancel context.CancelFunc) {
	r.rc, r.cancel = rc, cancel
	if r.idle > 0 {
		r.timer = time.AfterFunc(r.idle, cancel)
	}
}

func (r *remoteReader) detach() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	if r.rc != nil {
		_ = r.rc.Close()
		r.rc = nil
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}

// Close releases the current body.
func (r *remoteReader) Close() { r.detach() }

// uploadJob is a committed entry waiting to be uploaded.
type uploadJob struct {
	key  entryKey
	repo gitproto.Repo
	// gen is the repository's generation when the fill began; a refs
	// entry is not uploaded once a push has moved it on.
	gen uint64
	// createdAt is the entry's header creation time.
	createdAt time.Time
}

// enqueueUpload queues a committed entry for upload, recording a drop
// when the queue is full or closed.
func (c *Cache) enqueueUpload(job uploadJob) {
	c.mu.Lock()
	queued := false
	if !c.remoteClosed {
		select {
		case c.uploads <- job:
			queued = true
		default:
		}
	}
	c.mu.Unlock()
	if !queued {
		c.metrics.RecordResponseCacheUpload(context.Background(), observability.UploadResultDropped)
		c.logger.Debug("upload queue is full; the entry is not uploaded", "host", job.repo.Host, "group", job.key.Group)
	}
}

// runUploads is the body of an upload worker. It returns once the queue is
// closed and drained.
func (c *Cache) runUploads() {
	defer c.remoteWG.Done()
	for job := range c.uploads {
		c.uploadOne(job)
	}
}

func (c *Cache) uploadOne(job uploadJob) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("upload panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			c.metrics.RecordResponseCacheUpload(context.Background(), observability.UploadResultFailed)
		}
	}()
	ctx, cancel := context.WithTimeout(c.remoteCtx, uploadTimeout)
	defer cancel()
	result := c.upload(ctx, job)
	c.metrics.RecordResponseCacheUpload(context.Background(), result)
	c.logger.Debug("upload finished", "host", job.repo.Host, "group", job.key.Group, "result", result)
}

// upload stores one committed entry in the remote tier and returns the
// upload result. A pack entry already present remotely is skipped, since
// its content is fixed by its key; a refs entry always replaces the
// remote copy so peers see the latest tips.
func (c *Cache) upload(ctx context.Context, job uploadJob) string {
	if job.key.Group == GroupRefs && c.gens.current(job.key.RepoHash) != job.gen {
		return observability.UploadResultSkipped
	}
	if c.purges.covers(job.key, job.createdAt) {
		return observability.UploadResultSkipped
	}
	path := job.key.Path()
	if job.key.Group == GroupPack {
		_, err := c.remote.Stat(ctx, path)
		switch {
		case err == nil:
			return observability.UploadResultSkipped
		case !errors.Is(err, ErrNotFound):
			c.remoteError(observability.OperationStat, err)
			return observability.UploadResultFailed
		}
	}
	e, err := c.store.Open(path)
	if err != nil {
		return observability.UploadResultSkipped
	}
	defer func() { _ = e.Close() }()
	if err := c.remote.Put(ctx, path, e, e.Size()); err != nil {
		if errors.Is(err, ErrTooLarge) {
			return observability.UploadResultTooLarge
		}
		c.remoteError(observability.OperationPut, err)
		return observability.UploadResultFailed
	}
	return observability.UploadResultUploaded
}

// goRemote runs fn in the background with the remote tier's context. Close
// waits for it with the uploads. fn is not run once Close has begun
// flushing.
func (c *Cache) goRemote(fn func(ctx context.Context)) {
	c.mu.Lock()
	if c.remoteClosed {
		c.mu.Unlock()
		return
	}
	c.remoteWG.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.remoteWG.Done()
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error("remote tier task panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			}
		}()
		ctx, cancel := context.WithTimeout(c.remoteCtx, remoteMaintenanceTimeout)
		defer cancel()
		fn(ctx)
	}()
}

// deleteRemote deletes the remote object at path before returning, so the
// upload that follows an upstream fill never finds it still present.
func (c *Cache) deleteRemote(path string) {
	ctx, cancel := context.WithTimeout(c.remoteCtx, remoteMaintenanceTimeout)
	defer cancel()
	if err := c.remote.Delete(ctx, path); err != nil {
		c.remoteError(observability.OperationDelete, err)
	}
}

// invalidateRemote deletes repoHash's refs entries from the remote tier.
// It is best effort: a failure is logged and counted, never returned.
func (c *Cache) invalidateRemote(ctx context.Context, repo gitproto.Repo, repoHash [32]byte) {
	n, err := deleteRemotePrefix(ctx, c.remote, RepoPrefix(GroupRefs, repoHash))
	var opErr *remoteOpError
	if errors.As(err, &opErr) {
		c.remoteError(opErr.op, opErr.err)
	}
	c.logger.Debug("cache: invalidated remote refs entries after a push", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
}

// remoteError counts and logs a failed remote-tier operation. The error is
// logged as the BlobStore formats it, which for the s3 backend is the
// operation, error code and status only.
func (c *Cache) remoteError(operation string, err error) {
	c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierRemote, operation)
	c.logger.Warn("remote cache tier operation failed", "operation", operation, "error", err)
}

// checkPurgeMarker reads repoHash's purge marker and, when it records a
// purge this process has not seen, deletes the local entries it covers.
// A read that fails is logged and counted, and the marker is not read
// again for purgeCheckBackoff.
func (c *Cache) checkPurgeMarker(ctx context.Context, repo gitproto.Repo, repoHash [32]byte) {
	now := c.now()
	if !c.purges.shouldCheck(repoHash, now) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, purgeMarkerTimeout)
	defer cancel()
	times, found, err := readPurgeMarker(ctx, c.remote, c.keyring, repoHash, now)
	switch {
	case errors.Is(err, ErrIntegrity):
		c.purges.checkFailed(repoHash, now)
		c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierRemote, observability.OperationGet)
		security.Log(c.logger, security.EventCacheIntegrityFailed, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "class", string(groupPurge), "tier", observability.TierRemote)
		return
	case err != nil:
		if ctx.Err() == nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			c.purges.checkFailed(repoHash, now)
			c.remoteError(observability.OperationGet, err)
		}
		return
	case !found:
		return
	}
	merged, advanced := c.purges.observe(repoHash, times, now)
	if !advanced {
		return
	}
	n := c.dropPurged(repoHash, merged)
	c.logger.Info("cache: removed entries older than the repository's purge marker", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
}

// dropPurged deletes repoHash's local entries created before the purge
// times of their group, and entries whose header cannot be read, and
// returns how many it deleted.
func (c *Cache) dropPurged(repoHash [32]byte, times purgeTimes) int {
	n := 0
	for _, g := range []Group{GroupRefs, GroupPack} {
		if times.of(g).IsZero() {
			continue
		}
		for _, path := range c.store.pathsUnder(RepoPrefix(g, repoHash)) {
			e, err := c.store.Open(path)
			if err != nil {
				continue
			}
			sr, err := newSealedReader(e, c.keyring)
			if err != nil || times.covers(g, sr.Header().CreatedAt) {
				if c.store.DeleteEntry(e) == nil {
					n++
				}
			}
			_ = e.Close()
		}
	}
	return n
}

// purgeCheck is a purge marker read running alongside a refs fill.
type purgeCheck struct {
	done chan struct{}
}

// startPurgeCheck begins reading the repository's purge marker for a refs
// fill from upstream, when the cache has a remote tier. wait blocks until
// the read has finished; it may be called any number of times.
func (f *fill) startPurgeCheck() *purgeCheck {
	pc := &purgeCheck{done: make(chan struct{})}
	if f.c.remote == nil || f.key.Group != GroupRefs {
		close(pc.done)
		return pc
	}
	go func() {
		defer close(pc.done)
		defer func() {
			if r := recover(); r != nil {
				f.c.logger.Error("purge marker check panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			}
		}()
		f.c.checkPurgeMarker(f.ctx, f.repo, f.key.RepoHash)
	}()
	return pc
}

func (pc *purgeCheck) wait() { <-pc.done }
