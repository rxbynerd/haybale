package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"sync/atomic"
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
	// maxRemoteTasks bounds the background remote tasks running at once; a
	// task started beyond it is dropped.
	maxRemoteTasks = 8
	// maxRemoteResumes is how many ranged Gets a remote fill issues after
	// its body read fails before the fill cannot continue.
	maxRemoteResumes = 3
	// remoteResumeBackoff is the pause before the first resume; each later
	// resume waits twice as long as the one before.
	remoteResumeBackoff = 100 * time.Millisecond
	// maxEmptyReads is how many consecutive reads returning no bytes and no
	// error a remote body may make before it counts as a failed read.
	maxEmptyReads = 100
	// remoteSizeSlack is how far a remote object may exceed the sealed size
	// of maxEntrySize, covering the segments that flushes seal early.
	remoteSizeSlack = 1 << 20
)

var (
	// errRemoteChanged reports that a remote object was replaced while a
	// fill was reading it, so its bytes cannot be resumed.
	errRemoteChanged = errors.New("cache: remote object changed during the read")
	// errRemoteGone reports that a remote object was deleted while a fill
	// was reading it, for example by a purge or a lifecycle rule.
	errRemoteGone = errors.New("cache: remote object was deleted during the read")
	// errRemoteRead reports a remote read that failed before resumes were
	// enabled or past its resumes. The error that wraps it never wraps the
	// transport error too, so a short read is not mistaken for a
	// truncated entry.
	errRemoteRead = errors.New("cache: remote read failed")
	// errRemoteHeaderTimeout reports a remote entry whose header did not
	// arrive within the remote tier's header timeout.
	errRemoteHeaderTimeout = errors.New("cache: remote entry header did not arrive within the header timeout")
	// errRemoteHeaderIdle reports a remote entry whose header did not
	// arrive within the idle timeout, the bound when the header timeout is
	// zero.
	errRemoteHeaderIdle = errors.New("cache: remote entry header did not arrive within the idle timeout")
)

// uploadsGroup reports whether committed entries of group are uploaded
// to the remote tier. Packs always are. Refs are uploaded only when a
// replica can serve them back: as hits with a positive refsMaxAge, or as
// stale answers with stale-if-error enabled.
func (c *Cache) uploadsGroup(group Group) bool {
	return group == GroupPack || c.opts.RefsMaxAge > 0 || c.staleEnabled()
}

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

// fillFromRemote serves the fill from the remote tier's sealed copy,
// spooled as it is and verified as it passes. It returns false, having
// spooled nothing, when there is no usable copy or the Get or header read
// fails before the outcome is published; the fill then goes upstream.
// Once it returns true the fill is settled. With st set the copy is stale
// service: the stale rules decide whether it is usable instead of the hit
// freshness rules, and subscribers serve it as stale.
func (f *fill) fillFromRemote(st *staleService) bool {
	c := f.c
	path := f.key.Path()
	src := &remoteReader{
		ctx:           f.ctx,
		store:         c.remote,
		key:           path,
		idle:          c.opts.IdleTimeout,
		prefixTimeout: c.opts.RemoteHeaderTimeout,
		onError:       func(err error) { f.remoteReadFailed(err) },
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
	src.endPrefix()
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
	usable := f.remoteFresh
	if st != nil {
		usable = f.staleAcceptable
	}
	if !usable(h) {
		return false
	}

	f.source = observability.TierRemote
	sp, err := c.store.Create(path, info.Size, true)
	if err != nil {
		f.release(storeReason(err), transientCooldown)
		return true
	}
	f.spool = sp
	if _, err := sp.Write(prefix); err != nil {
		f.abort(err, storeReason(err))
		return true
	}
	tee.w = sp
	out := fillOutcome{kind: fillStreaming, contentType: h.ContentType, tier: observability.TierRemote}
	if st != nil {
		st.createdAt = h.CreatedAt
		out.stale = st
	}
	f.setOutcome(out)
	src.enableResumes()
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

// remoteFresh applies the hit freshness rules to a remote entry, and
// misses a refs entry created before this process's last push to the
// repository. An entry past retention or older than the repository's last
// purge is deleted from the remote tier in the background.
func (f *fill) remoteFresh(h entryHeader) bool {
	c := f.c
	age := c.now().Sub(h.CreatedAt)
	switch {
	case age > c.opts.Retention || c.purges.covers(f.key, h.CreatedAt):
		f.expireRemote()
		return false
	case f.key.Group == GroupRefs && age > c.opts.RefsMaxAge:
		return false
	case f.prePushRefs(h):
		return false
	}
	return true
}

// prePushRefs reports whether h is a refs entry created no later than
// this process's last push to the repository, so it may hold the
// pre-push tips. A peer may still serve it; it is left for the push's own
// deletion.
func (f *fill) prePushRefs(h entryHeader) bool {
	return f.key.Group == GroupRefs && !h.CreatedAt.After(f.c.gens.pushedAt(f.key.RepoHash))
}

// expireRemote deletes the fill's remote object, past retention or
// covered by a purge, in the background so a slow bucket does not delay
// the fall-through. It can race the upload that follows, which then finds
// the old object, skips, and leaves the key absent until a later miss
// uploads it.
func (f *fill) expireRemote() {
	c := f.c
	path := f.key.Path()
	c.goRemote(func(ctx context.Context) {
		if err := c.remote.Delete(ctx, path); err != nil {
			c.remoteErrorUnlessClosed(observability.OperationDelete, err)
		}
	})
}

// streamRemote reads the remote entry through sr, which verifies every
// segment while tee writes the sealed bytes into the spool, then commits
// or discards the spool. Only a failure of sr's own verification is an
// integrity failure; a read the remote tier could not complete ends the
// fill as a fetch error and leaves the object alone.
func (f *fill) streamRemote(sr *sealedReader, tee *spoolTee) {
	defer func() {
		if h := f.c.hooks.afterDecision; h != nil {
			h(f.key)
		}
	}()
	buf := make([]byte, segmentSize)
	for {
		n, err := sr.Read(buf)
		f.fetched += int64(n)
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
			f.abort(err, observability.FillReasonFetchError)
		}
		return
	}
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

// remoteReader reads one remote object of known size from the start,
// ending with io.EOF exactly at its size. Before enableResumes a failure
// is final and the header read is bounded; after it a failed or idle body
// resumes with a ranged Get, up to maxRemoteResumes times, while the
// object is unchanged. It is not safe for concurrent use.
type remoteReader struct {
	ctx           context.Context
	store         BlobStore
	key           string
	idle          time.Duration
	prefixTimeout time.Duration
	onError       func(error)

	size      int64
	modTime   time.Time
	etag      string
	off       int64
	rc        io.ReadCloser
	cancel    context.CancelFunc
	timer     *time.Timer
	expired   atomic.Bool
	prefixErr error
	resumable bool
	resumes   int
	lastErr   error
}

// start issues the first Get and returns the object's description.
func (r *remoteReader) start() (ObjectInfo, error) {
	ctx, cancel := context.WithCancel(r.ctx)
	rc, info, err := r.store.Get(ctx, r.key, 0)
	if err != nil {
		cancel()
		return ObjectInfo{}, err
	}
	r.size, r.modTime, r.etag = info.Size, info.ModTime, info.ETag
	r.rc, r.cancel = rc, cancel
	bound, cause := r.prefixTimeout, errRemoteHeaderTimeout
	if bound <= 0 {
		bound, cause = r.idle, errRemoteHeaderIdle
	}
	if bound > 0 {
		r.prefixErr = cause
		r.timer = time.AfterFunc(bound, func() {
			r.expired.Store(true)
			cancel()
		})
	}
	return info, nil
}

// endPrefix stops the first-body bound once the header has been read.
func (r *remoteReader) endPrefix() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

// enableResumes ends the first-body phase: from here a failed or idle
// body is resumed.
func (r *remoteReader) enableResumes() {
	r.resumable = true
	r.endPrefix()
	if r.rc != nil && r.idle > 0 {
		r.timer = time.AfterFunc(r.idle, r.cancel)
	}
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
	empty := 0
	for {
		if r.rc != nil {
			n, err := r.rc.Read(p)
			if n > 0 {
				r.off += int64(n)
				if r.timer != nil && r.resumable {
					r.timer.Reset(r.idle)
				}
				return n, nil
			}
			if err == nil {
				if empty++; empty < maxEmptyReads {
					continue
				}
				err = io.ErrNoProgress
			}
			empty = 0
			r.detach()
			if cerr := r.ctx.Err(); cerr != nil {
				return 0, cerr
			}
			switch {
			case r.expired.Load() && !r.resumable:
				err = r.prefixErr
			case errors.Is(err, io.EOF):
				err = io.ErrUnexpectedEOF
			}
			r.failed(err)
			if !r.resumable {
				return 0, fmt.Errorf("%w: %v", errRemoteRead, err)
			}
		}
		if r.resumes >= maxRemoteResumes {
			return 0, fmt.Errorf("%w after %d resumes: %v", errRemoteRead, r.resumes, r.lastErr)
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
	rc, info, err := r.resumeGet(ctx)
	switch {
	case errors.Is(err, ErrObjectChanged):
		cancel()
		return errRemoteChanged
	case errors.Is(err, ErrNotFound):
		cancel()
		return errRemoteGone
	case err != nil:
		cancel()
		if cerr := r.ctx.Err(); cerr != nil {
			return cerr
		}
		r.failed(err)
		return nil
	case info.Size != r.size || !info.ModTime.Equal(r.modTime) || info.ETag != r.etag:
		_ = rc.Close()
		cancel()
		return errRemoteChanged
	}
	r.attach(rc, cancel)
	return nil
}

// resumeGet issues the ranged Get of a resume, conditional on the
// object's ETag when the store supports it.
func (r *remoteReader) resumeGet(ctx context.Context) (io.ReadCloser, ObjectInfo, error) {
	if cg, ok := r.store.(ConditionalGetter); ok && r.etag != "" {
		return cg.GetIfMatch(ctx, r.key, r.off, r.etag)
	}
	return r.store.Get(ctx, r.key, r.off)
}

func (r *remoteReader) failed(err error) {
	r.lastErr = err
	if r.onError != nil {
		r.onError(err)
	}
}

// attach makes rc the current body of a resume. A body that delivers no
// bytes for idle is cancelled, which fails its next read and triggers
// another resume.
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
// closed and drained. Once Close has cancelled the remote tier's context,
// each job left is counted as dropped without reaching the store.
func (c *Cache) runUploads() {
	defer c.remoteWG.Done()
	for job := range c.uploads {
		if c.remoteCtx.Err() != nil {
			c.metrics.RecordResponseCacheUpload(context.Background(), observability.UploadResultDropped)
			continue
		}
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
// remote copy so peers see the latest tips. An upload cut short by Close
// is dropped, not failed.
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
		case c.remoteCtx.Err() != nil:
			return observability.UploadResultDropped
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
		switch {
		case errors.Is(err, ErrTooLarge):
			return observability.UploadResultTooLarge
		case c.remoteCtx.Err() != nil:
			return observability.UploadResultDropped
		}
		c.remoteError(observability.OperationPut, err)
		return observability.UploadResultFailed
	}
	if job.key.Group == GroupRefs && c.gens.current(job.key.RepoHash) != job.gen {
		// A push landed during the Put, and its deletion may have run
		// before the object existed.
		c.deleteRemote(path)
		return observability.UploadResultSkipped
	}
	return observability.UploadResultUploaded
}

// goRemote runs fn in the background with the remote tier's context,
// bounded by remoteMaintenanceTimeout. Close waits for it with the
// uploads. fn is not run once Close has begun flushing, nor when
// maxRemoteTasks are already running; it is then dropped without
// blocking the caller.
func (c *Cache) goRemote(fn func(ctx context.Context)) {
	c.mu.Lock()
	if c.remoteClosed {
		c.mu.Unlock()
		return
	}
	select {
	case c.remoteTasks <- struct{}{}:
	default:
		c.mu.Unlock()
		c.logger.Debug("remote tier task limit reached; the task is dropped")
		return
	}
	c.remoteWG.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.remoteWG.Done()
		defer func() { <-c.remoteTasks }()
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

// deleteRemote deletes the remote object at path within remoteBound
// before returning, so the upload that follows an upstream fill never
// finds it still present.
func (c *Cache) deleteRemote(path string) {
	ctx, cancel := context.WithTimeout(c.remoteCtx, c.remoteBound())
	defer cancel()
	if err := c.remote.Delete(ctx, path); err != nil {
		c.remoteErrorUnlessClosed(observability.OperationDelete, err)
	}
}

// remoteBound bounds remote-tier work a request waits on beyond a single
// Stat or Get: RemoteHeaderTimeout, or remoteMaintenanceTimeout when that
// is unbounded.
func (c *Cache) remoteBound() time.Duration {
	if t := c.opts.RemoteHeaderTimeout; t > 0 {
		return t
	}
	return remoteMaintenanceTimeout
}

// invalidateRemote deletes repoHash's refs entries from the remote tier
// within remoteBound, under the remote tier's context so shutdown cancels
// it. It is best effort: a failure is logged and counted, never returned.
func (c *Cache) invalidateRemote(repo gitproto.Repo, repoHash [32]byte) {
	ctx, cancel := context.WithTimeout(c.remoteCtx, c.remoteBound())
	defer cancel()
	n, err := deleteRemotePrefix(ctx, c.remote, RepoPrefix(GroupRefs, repoHash))
	var opErr *remoteOpError
	if errors.As(err, &opErr) {
		c.remoteErrorUnlessClosed(opErr.op, opErr.err)
		return
	}
	c.logger.Debug("cache: invalidated remote refs entries after a push", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
}

// remoteError counts and logs a failed remote-tier operation. The error is
// logged as the BlobStore formats it: for the s3 backend a failed request
// is the operation, error code and status only, but a body read that fails
// mid-stream is the transport's error, which can name peer addresses.
func (c *Cache) remoteError(operation string, err error) {
	c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierRemote, operation)
	c.logger.Warn("remote cache tier operation failed", "operation", operation, "error", err)
}

// remoteErrorUnlessClosed is remoteError for background remote work,
// which records nothing once Close has cancelled the remote tier's
// context: the failure is then the shutdown, not the store.
func (c *Cache) remoteErrorUnlessClosed(operation string, err error) {
	if c.remoteCtx.Err() != nil {
		return
	}
	c.remoteError(operation, err)
}

// checkPurgeMarker applies repoHash's purge marker and reports whether
// the repository's purge state is known current: read and verified, or
// confirmed absent, now or within the check interval. Concurrent fills of
// one repository share one read; a failed read or marker starts
// purgeCheckBackoff, during which the state is not current.
func (c *Cache) checkPurgeMarker(ctx context.Context, repo gitproto.Repo, repoHash [32]byte) bool {
	now := c.now()
	start, mc := c.purges.beginCheck(repoHash, now)
	switch start {
	case checkCurrent:
		return true
	case checkBackoff:
		return false
	case checkJoin:
		if h := c.hooks.markerCheckJoined; h != nil {
			h()
		}
		select {
		case <-mc.done:
			return mc.current
		case <-ctx.Done():
			return false
		}
	}
	// A read that panics finishes as failed, so the joiners wake and the
	// backoff starts.
	current, failed := false, true
	defer func() { c.purges.finishCheck(repoHash, mc, current, failed, now) }()
	current, failed = c.readMarker(ctx, repo, repoHash, now)
	return current
}

// purgeCurrent reports whether repoHash's purge state is known current
// for stale service, checking its purge marker when the cache has a
// remote tier. Without one, the purges this process made itself are the
// only ones, and the state is always current.
func (c *Cache) purgeCurrent(ctx context.Context, repo gitproto.Repo, repoHash [32]byte) bool {
	return c.remote == nil || c.checkPurgeMarker(ctx, repo, repoHash)
}

// readMarker reads and applies repoHash's purge marker for
// checkPurgeMarker. failed reports a read or verification failure, as
// opposed to a read cut short because ctx ended.
func (c *Cache) readMarker(ctx context.Context, repo gitproto.Repo, repoHash [32]byte, now time.Time) (current, failed bool) {
	ctx, cancel := context.WithTimeout(ctx, c.markerTimeout)
	defer cancel()
	times, found, err := readPurgeMarker(ctx, c.remote, c.keyring, repoHash, now)
	switch {
	case errors.Is(err, ErrIntegrity):
		c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierRemote, observability.OperationGet)
		security.Log(c.logger, security.EventCacheIntegrityFailed, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "class", string(groupPurge), "tier", observability.TierRemote)
		return false, true
	case err != nil:
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, false
		}
		c.remoteError(observability.OperationGet, err)
		return false, true
	case !found:
		return true, false
	}
	merged, advanced := c.purges.observe(repoHash, times, now)
	if advanced {
		n := c.dropPurged(repoHash, merged)
		c.logger.Info("cache: removed entries older than the repository's purge marker", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
	}
	return true, false
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

// purgeCheck is a purge marker check running alongside a refs fill.
// current is valid once done is closed.
type purgeCheck struct {
	done    chan struct{}
	current bool
}

// startPurgeCheck begins checking the repository's purge marker for a
// refs fill from upstream, when the cache has a remote tier. Without a
// remote tier, or for a pack fill, the check is immediately current.
func (f *fill) startPurgeCheck() *purgeCheck {
	pc := &purgeCheck{done: make(chan struct{})}
	if f.c.remote == nil || f.key.Group != GroupRefs {
		pc.current = true
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
		pc.current = f.c.checkPurgeMarker(f.ctx, f.repo, f.key.RepoHash)
	}()
	return pc
}

// wait blocks until the check has finished and reports whether the
// repository's purge state is known current. It may be called any number
// of times.
func (pc *purgeCheck) wait() bool {
	<-pc.done
	return pc.current
}
