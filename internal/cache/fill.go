package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
)

const (
	// sharedBodyLimit bounds the body of a non-200 upstream response that
	// is relayed to every subscriber; a larger body releases them to the
	// passthrough path instead.
	sharedBodyLimit = 64 << 10
	// fillIdleGrace is how long a fill keeps running after its last
	// subscriber leaves before it is cancelled.
	fillIdleGrace = 2 * time.Second
	// sealFlushInterval bounds how long body bytes wait in the sealed
	// writer before they are sealed into a segment subscribers can read,
	// so upload-pack keepalives and progress reach clients promptly.
	sealFlushInterval = 200 * time.Millisecond
	// transientCooldown is how long a key stays uncacheable after a fill
	// fails for any reason other than an oversize response.
	transientCooldown = time.Minute
	// reserveStep is the smallest amount by which a fill grows its spool
	// reservation once the sealed output outruns it.
	reserveStep = 4 * SegmentSize
	// fetchBufferSize is the read size for upstream bodies.
	fetchBufferSize = 32 << 10
	// contentTypeAdvertisement is the Content-Type a stored advertisement
	// response must carry.
	contentTypeAdvertisement = "application/x-git-upload-pack-advertisement"
)

type fillOutcomeKind uint8

const (
	// fillStreaming: upstream answered 200 with the allowlisted
	// Content-Type and subscribers read the spool.
	fillStreaming fillOutcomeKind = iota + 1
	// fillShared: upstream answered something else and every subscriber
	// writes the one buffered response.
	fillShared
	// fillReleased: the fill cannot serve its subscribers, which take the
	// passthrough path instead.
	fillReleased
)

// fillOutcome is the header outcome of a fill, fixed once headerReady is
// closed.
type fillOutcome struct {
	kind        fillOutcomeKind
	contentType string
	status      int
	header      http.Header
	body        []byte
}

// fill is one upstream round trip spooled on disk for its subscribers. Its
// context derives from the cache's lifetime, not from any request, so it
// outlives the subscriber that started it.
type fill struct {
	c       *Cache
	key     Key
	req     Request
	repo    gitproto.Repo
	baseURL *url.URL
	fetch   Fetcher
	// shared fills are registered in Cache.fills for later requests to
	// join; a refs fill with refsMaxAge zero is not shared.
	shared bool
	// gen is the repository's invalidation generation when the fill began.
	gen uint64

	ctx       context.Context
	cancel    context.CancelFunc
	abandoned atomic.Bool

	spool       *Spool
	headerReady chan struct{}
	outcomeOnce sync.Once
	outcome     fillOutcome // valid once headerReady is closed
	done        chan struct{}
	stored      bool  // valid once done is closed
	fetched     int64 // body bytes read from upstream; fill goroutine only
	finished    bool  // the fill metric has been recorded; fill goroutine only

	// seal guards the sealed writer, which the fill goroutine and the
	// flush timer share.
	seal struct {
		mu     sync.Mutex
		w      *SealedWriter
		timer  *time.Timer
		armed  bool
		closed bool
		err    error
	}

	// Guarded by Cache.mu.
	subscribers int
	ended       bool
	idle        *time.Timer
}

func (c *Cache) newFill(key Key, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, shared bool) *fill {
	ctx, cancel := context.WithCancel(c.ctx)
	return &fill{
		c:           c,
		key:         key,
		req:         req,
		repo:        repo,
		baseURL:     baseURL,
		fetch:       fetch,
		shared:      shared,
		gen:         c.gens.current(key.RepoHash),
		ctx:         ctx,
		cancel:      cancel,
		headerReady: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// run performs the fill. It is the body of the fill goroutine; a panic
// anywhere in it aborts this fill and its subscribers, never the process.
func (f *fill) run() {
	defer close(f.done)
	defer f.c.wg.Done()
	defer func() { <-f.c.slots }()
	defer f.end()
	defer func() {
		if r := recover(); r != nil {
			f.c.logger.Error("cache: fill panicked", "class", f.req.Class, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			f.abort(fmt.Errorf("cache: fill panicked: %v", r), observability.FillReasonStoreError)
		}
	}()
	f.perform()
}

func (f *fill) perform() {
	resp, err := f.fetchHeaders()
	if err != nil {
		f.logger().Debug("cache: upstream fetch failed", "error", err)
		f.release(observability.FillReasonFetchError, transientCooldown)
		return
	}
	body := newIdleReader(resp.Body, f.c.opts.IdleTimeout, f.cancel)
	defer func() { _ = body.Close() }()

	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != responseContentType(f.req.Class) {
		f.share(resp, body)
		return
	}
	now := f.c.now()
	if f.key.Group == GroupRefs {
		f.c.access.record(f.key.RepoHash, now)
	}
	if resp.ContentLength > f.c.opts.MaxEntrySize {
		f.release(observability.FillReasonTooLarge, f.c.opts.Retention)
		return
	}
	if !f.openSpool(resp.ContentLength, now) {
		return
	}
	f.setOutcome(fillOutcome{kind: fillStreaming, contentType: resp.Header.Get("Content-Type")})
	f.streamBody(resp.ContentLength, body)
}

// fetchHeaders performs the upstream round trip, cancelling the fill if
// response headers do not arrive within the response-header timeout. The
// timer is stopped once headers arrive so the body is not bounded by it.
func (f *fill) fetchHeaders() (*http.Response, error) {
	if t := f.c.opts.ResponseHeaderTimeout; t > 0 {
		timer := time.AfterFunc(t, f.cancel)
		defer timer.Stop()
	}
	resp, err := f.fetch.Fetch(f.ctx, f.req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("cache: fetcher returned no response body")
	}
	return resp, nil
}

// share relays a non-streamable upstream response to every subscriber:
// the body is buffered up to sharedBodyLimit and, with the response
// headers and status, becomes the one response they all write.
func (f *fill) share(resp *http.Response, body io.Reader) {
	buf, err := io.ReadAll(io.LimitReader(body, sharedBodyLimit+1))
	switch {
	case err != nil:
		f.release(observability.FillReasonFetchError, transientCooldown)
		return
	case len(buf) > sharedBodyLimit:
		f.release(observability.FillReasonUpstreamStatus, transientCooldown)
		return
	}
	h := make(http.Header, len(resp.Header))
	for k, vs := range resp.Header {
		if !hopByHopHeader(k) && k != "Content-Length" {
			h[k] = vs
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(buf)))
	f.setOutcome(fillOutcome{kind: fillShared, status: resp.StatusCode, header: h, body: buf})
	f.finish(observability.FillResultDiscarded, observability.FillReasonUpstreamStatus, transientCooldown)
}

// openSpool reserves disk for the response and writes the sealed header.
// contentLength is the upstream Content-Length, or -1 when unknown, in
// which case the whole maxEntrySize is reserved up front.
func (f *fill) openSpool(contentLength int64, now time.Time) bool {
	expected := f.c.opts.MaxEntrySize
	if contentLength >= 0 {
		expected = contentLength
	}
	reserve := SealedSize(expected)
	sp, err := f.c.store.Create(f.key.Path(), reserve)
	if err != nil {
		f.release(storeReason(err), transientCooldown)
		return false
	}
	f.spool = sp
	hdr := Header{
		Group:       f.key.Group,
		Class:       f.req.Class,
		RepoHash:    f.key.RepoHash,
		KeyHash:     f.key.KeyHash,
		Repo:        f.repo.Host + "/" + f.repo.Owner + "/" + f.repo.Name,
		BaseURL:     f.baseURL.String(),
		CreatedAt:   now,
		ContentType: responseContentType(f.req.Class),
		Protocol:    f.req.Protocol,
	}
	sw, err := NewSealedWriter(&spoolWriter{sp: sp, reserved: reserve}, f.c.keyring, hdr)
	if err != nil {
		sp.Abort()
		f.release(storeReason(err), transientCooldown)
		return false
	}
	f.seal.w = sw
	return true
}

// streamBody copies the upstream body into the spool through the sealed
// writer and the storability scanner, then commits or discards the spool.
func (f *fill) streamBody(contentLength int64, body io.Reader) {
	scanner := pktline.NewScanner(scanMode(f.req))
	buf := make([]byte, fetchBufferSize)
	for {
		k, rerr := body.Read(buf)
		if k > 0 {
			f.fetched += int64(k)
			_, _ = scanner.Write(buf[:k])
			if err := f.write(buf[:k]); err != nil {
				f.abort(err, storeReason(err))
				return
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			f.abort(rerr, observability.FillReasonFetchError)
			return
		}
	}
	// The trailer is written before the storability decision so that
	// subscribers of a discarded spool still read a complete entry.
	if err := f.closeSeal(); err != nil {
		f.abort(err, storeReason(err))
		return
	}

	cleanEOF := contentLength < 0 || f.fetched == contentLength
	verdict := scanner.Verdict(cleanEOF)
	switch {
	case f.fetched > f.c.opts.MaxEntrySize:
		f.discard(observability.FillReasonTooLarge, f.c.opts.Retention)
	case !cleanEOF:
		f.discard(observability.FillReasonTruncated, transientCooldown)
	case !verdict.Storable:
		f.discard(verdictReason(verdict.Reason), transientCooldown)
	case f.key.Group == GroupRefs && f.c.gens.current(f.key.RepoHash) != f.gen:
		f.discard(observability.FillReasonGeneration, 0)
	default:
		if err := f.spool.Commit(); err != nil {
			f.abort(err, observability.FillReasonStoreError)
			return
		}
		f.stored = true
		f.finish(observability.FillResultStored, "", 0)
	}
}

// write seals p into the spool and arms the flush timer so that bytes
// short of a full segment still reach subscribers.
func (f *fill) write(p []byte) error {
	f.seal.mu.Lock()
	defer f.seal.mu.Unlock()
	if f.seal.err != nil {
		return f.seal.err
	}
	if _, err := f.seal.w.Write(p); err != nil {
		f.seal.err = err
		return err
	}
	if !f.seal.armed {
		f.seal.armed = true
		if f.seal.timer == nil {
			f.seal.timer = time.AfterFunc(f.c.flushInterval, f.flushSeal)
		} else {
			f.seal.timer.Reset(f.c.flushInterval)
		}
	}
	return nil
}

// flushSeal runs on the flush timer and seals whatever is buffered.
func (f *fill) flushSeal() {
	f.seal.mu.Lock()
	defer f.seal.mu.Unlock()
	f.seal.armed = false
	if f.seal.closed || f.seal.err != nil {
		return
	}
	if err := f.seal.w.Flush(); err != nil {
		f.seal.err = err
	}
}

// closeSeal stops the flush timer and writes the trailer.
func (f *fill) closeSeal() error {
	f.seal.mu.Lock()
	defer f.seal.mu.Unlock()
	f.seal.closed = true
	if f.seal.timer != nil {
		f.seal.timer.Stop()
	}
	if f.seal.err != nil {
		return f.seal.err
	}
	return f.seal.w.Close()
}

// setOutcome fixes the header outcome and wakes waiting subscribers. Only
// the first call has any effect.
func (f *fill) setOutcome(o fillOutcome) {
	f.outcomeOnce.Do(func() {
		f.outcome = o
		close(f.headerReady)
	})
}

// release settles a fill that cannot serve its subscribers from the spool:
// those still waiting for the header outcome take the passthrough path.
func (f *fill) release(reason string, markFor time.Duration) {
	f.setOutcome(fillOutcome{kind: fillReleased})
	f.finish(observability.FillResultDiscarded, reason, markFor)
}

// discard ends a spool that served its subscribers but is not storable:
// readers receive every byte and then EOF, and the file is removed.
func (f *fill) discard(reason string, markFor time.Duration) {
	f.spool.Discard()
	f.finish(observability.FillResultDiscarded, reason, markFor)
}

// abort ends a fill that cannot continue: readers of the spool receive err
// and abort their clients' connections, and subscribers that have not yet
// started reading take the passthrough path.
func (f *fill) abort(err error, reason string) {
	if f.abandoned.Load() {
		f.logger().Debug("cache: fill cancelled after its subscribers left")
	} else {
		f.logger().Warn("cache: fill aborted", "reason", reason, "error", err)
	}
	if f.spool != nil {
		f.spool.Fail(err)
	}
	f.release(reason, transientCooldown)
}

// finish records the fill's result once and marks the key uncacheable for
// markFor when it is positive. A fill cancelled because its subscribers
// left marks nothing: the next request for the key should start afresh.
func (f *fill) finish(result, reason string, markFor time.Duration) {
	if f.finished {
		return
	}
	f.finished = true
	ctx := context.Background()
	f.c.metrics.RecordResponseCacheFill(ctx, f.repo.Host, string(f.req.Class), result, reason)
	if f.fetched > 0 {
		f.c.metrics.RecordResponseCacheFillBytes(ctx, f.repo.Host, string(f.req.Class), observability.TierUpstream, f.fetched)
	}
	if markFor > 0 && !f.abandoned.Load() {
		f.c.marks.mark(f.key, f.c.now().Add(markFor))
	}
	f.logger().Debug("cache: fill finished", "result", result, "reason", reason, "bytes", f.fetched)
}

// end detaches the fill from the cache so no request can join it, and
// cancels its context.
func (f *fill) end() {
	c := f.c
	c.mu.Lock()
	f.ended = true
	if f.idle != nil {
		f.idle.Stop()
	}
	if f.shared && c.fills[f.key] == f {
		delete(c.fills, f.key)
	}
	c.mu.Unlock()
	f.cancel()
}

// attachLocked adds a subscriber. Cache.mu must be held.
func (f *fill) attachLocked() {
	f.subscribers++
	if f.idle != nil {
		f.idle.Stop()
		f.idle = nil
	}
}

// detach removes a subscriber and, when none remain, schedules the fill's
// cancellation after the idle grace period.
func (f *fill) detach() {
	c := f.c
	c.mu.Lock()
	defer c.mu.Unlock()
	f.subscribers--
	if f.subscribers == 0 && !f.ended {
		f.idle = time.AfterFunc(c.idleGrace, f.abandon)
	}
}

// abandon cancels a fill that still has no subscribers when the grace
// period ends.
func (f *fill) abandon() {
	c := f.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.subscribers == 0 && !f.ended {
		f.abandoned.Store(true)
		f.cancel()
	}
}

func (f *fill) logger() *slog.Logger {
	return f.c.logger.With("host", f.repo.Host, "owner", f.repo.Owner, "repo", f.repo.Name, "class", f.req.Class)
}

// spoolWriter writes sealed bytes to a spool, growing the reservation
// ahead of the bytes so that a write never exceeds it.
type spoolWriter struct {
	sp       *Spool
	written  int64
	reserved int64
}

func (w *spoolWriter) Write(p []byte) (int, error) {
	if need := w.written + int64(len(p)) - w.reserved; need > 0 {
		add := max(need, reserveStep)
		if err := w.sp.Reserve(add); err != nil {
			return 0, err
		}
		w.reserved += add
	}
	n, err := w.sp.Write(p)
	w.written += int64(n)
	return n, err
}

// idleReader cancels the fill when no body bytes arrive for idle. A zero
// idle leaves the body unbounded.
type idleReader struct {
	rc    io.ReadCloser
	idle  time.Duration
	timer *time.Timer
}

func newIdleReader(rc io.ReadCloser, idle time.Duration, cancel context.CancelFunc) *idleReader {
	r := &idleReader{rc: rc, idle: idle}
	if idle > 0 {
		r.timer = time.AfterFunc(idle, cancel)
	}
	return r
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if r.timer != nil && err == nil {
		r.timer.Reset(r.idle)
	}
	return n, err
}

func (r *idleReader) Close() error {
	if r.timer != nil {
		r.timer.Stop()
	}
	return r.rc.Close()
}

// responseContentType is the Content-Type a storable response of class
// must carry.
func responseContentType(class Class) string {
	if class == ClassAdvertisement {
		return contentTypeAdvertisement
	}
	return contentTypeResult
}

// scanMode selects the response grammar for a request.
func scanMode(req Request) pktline.Mode {
	switch req.Class {
	case ClassAdvertisement:
		return pktline.ModeAdvertisement
	case ClassLsRefs:
		return pktline.ModeV2Result
	case ClassFetch:
		if isProtocolV2(req.Protocol) {
			return pktline.ModeV2Fetch
		}
		return pktline.ModeV0UploadPack
	default:
		return 0
	}
}

// isProtocolV2 reports whether a validated Git-Protocol value selects
// protocol version 2.
func isProtocolV2(protocol string) bool {
	return protocol == "version=2" || strings.HasPrefix(protocol, "version=2:")
}

// verdictReason maps a scanner reason onto the fill-reason label set.
func verdictReason(reason string) string {
	switch reason {
	case pktline.ReasonErrorPacket:
		return observability.FillReasonErrorPacket
	case pktline.ReasonSidebandError:
		return observability.FillReasonSidebandError
	case pktline.ReasonTruncated:
		return observability.FillReasonTruncated
	default:
		return observability.FillReasonFraming
	}
}

// storeReason labels a spool error: a budget failure or any other store
// error.
func storeReason(err error) string {
	if errors.Is(err, ErrBudget) {
		return observability.FillReasonDiskBudget
	}
	return observability.FillReasonStoreError
}

// hopByHopHeader reports whether name is a hop-by-hop header that must
// not be relayed from an upstream response.
func hopByHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}
