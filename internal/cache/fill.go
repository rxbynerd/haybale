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
	// lateSubscriberGrace bounds how long a discarded spool waits for
	// subscribers that attached before the fill ended to open it.
	lateSubscriberGrace = 2 * time.Second
	// sealFlushInterval bounds how long body bytes wait in the sealed
	// writer before they are sealed into a segment subscribers can read,
	// so upload-pack keepalives and progress reach clients promptly.
	sealFlushInterval = 200 * time.Millisecond
	// transientCooldown is how long a key stays uncacheable after a fill
	// fails for any reason other than an oversize response.
	transientCooldown = time.Minute
	// reserveStep is the smallest amount by which a fill grows its spool
	// reservation once the sealed output outruns it, and the headroom a
	// pack fill reserves above the sealed size of the expected body.
	reserveStep = 4 * segmentSize
	// refsInitialReservation is the disk a refs fill reserves up front.
	// Refs responses are kilobytes, so they neither reserve maxEntrySize
	// like a pack of unknown length nor take a pack fill slot; see
	// maxRefsFills.
	refsInitialReservation = 1 << 20
	// maxRefsFills bounds concurrent refs fills; beyond it a refs request
	// passes through unstored. It is fixed because a refs fill holds only
	// refsInitialReservation and a slot is cheap.
	maxRefsFills = 64
	// fetchBufferSize is the read size for upstream bodies.
	fetchBufferSize = 32 << 10
	// contentTypeAdvertisement is the Content-Type a stored advertisement
	// response must carry.
	contentTypeAdvertisement = "application/x-git-upload-pack-advertisement"
)

// Values of fill.headerCut.
const (
	headerCutNone uint32 = iota
	// headerCutTimeout: the response-header timeout expired.
	headerCutTimeout
	// headerCutProbe: the probe deadline of a gate probe holding a
	// qualifying stale entry expired.
	headerCutProbe
)

// errOversizeGrowth reports that a response outgrew the entry size limit
// and the free disk budget could not hold the rest of it.
var errOversizeGrowth = errors.New("cache: response exceeds the entry size limit and the free budget")

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
	// fillStale: upstream could not answer and every subscriber serves the
	// stale tier-1 entry itself, or the fallback outcome when it cannot
	// open that entry.
	fillStale
)

// fillOutcome is the header outcome of a fill, fixed once headerReady is
// closed.
type fillOutcome struct {
	kind        fillOutcomeKind
	contentType string
	// tier is where a streaming fill's body comes from: TierUpstream or
	// TierRemote.
	tier   string
	status int
	header http.Header
	body   []byte
	// stale is set for a fillStale outcome and for a streaming outcome
	// that spools a stale remote entry.
	stale *staleService
	// fallback is the shared or released outcome of a fillStale outcome.
	fallback *fillOutcome
}

// fill is one response spooled on disk for its subscribers, read from the
// remote tier when it holds a usable copy and otherwise from upstream. Its
// context derives from the cache's lifetime, not from any request, so it
// outlives the subscriber that started it.
type fill struct {
	c       *Cache
	key     entryKey
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
	// headerCut records which timer, if any, cancelled the upstream
	// request before its response headers arrived: headerCutTimeout or
	// headerCutProbe.
	headerCut atomic.Uint32

	spool       *spool
	headerReady chan struct{}
	outcomeOnce sync.Once
	outcome     fillOutcome // valid once headerReady is closed
	done        chan struct{}
	stored      bool // valid once done is closed
	// The fields below belong to the fill goroutine. fetched counts body
	// bytes read from source, the tier the body came from; createdAt is
	// the creation time sealed into the entry's header; finished records
	// that the fill metric has been recorded.
	fetched   int64
	source    string
	createdAt time.Time
	finished  bool

	// seal guards the sealed writer, which the fill goroutine and the
	// flush timer share.
	seal struct {
		mu     sync.Mutex
		w      *sealedWriter
		timer  *time.Timer
		armed  bool
		closed bool
		err    error
	}

	// Guarded by Cache.mu. pending counts subscribers that have attached
	// but not yet opened the spool or left; noPending is closed once the
	// fill has ended and pending is zero.
	subscribers   int
	pending       int
	ended         bool
	idle          *time.Timer
	noPending     chan struct{}
	pendingClosed bool

	// dropEntry marks a committed refs entry that a push superseded. It is
	// deleted by releaseSpool once pending subscribers have opened it.
	dropEntry bool
}

func (c *Cache) newFill(key entryKey, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, shared bool) *fill {
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
		source:      observability.TierUpstream,
		ctx:         ctx,
		cancel:      cancel,
		headerReady: make(chan struct{}),
		done:        make(chan struct{}),
		noPending:   make(chan struct{}),
	}
}

// run performs the fill. It is the body of the fill goroutine; a panic
// anywhere in it aborts this fill and its subscribers, never the process.
func (f *fill) run() {
	defer close(f.done)
	defer f.c.wg.Done()
	defer f.c.releaseSlot(f.key.Group)
	defer f.releaseSpool()
	defer f.end()
	defer func() {
		if r := recover(); r != nil {
			f.c.logger.Error("fill panicked", "class", f.req.Class, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			f.abort(fmt.Errorf("cache: fill panicked: %v", r), observability.FillReasonStoreError)
		}
	}()
	f.perform()
}

func (f *fill) perform() {
	if f.remoteEligible() && f.fillFromRemote(nil) {
		return
	}
	probing := false
	if f.c.staleEnabled() {
		held, probe := f.c.gates.admit(f.repo.Host, f.c.now())
		if held && f.serveStale(upstreamResult{eligible: true, reason: staleReasonHealthGate}, fillOutcome{kind: fillReleased}, "") {
			return
		}
		probing = probe
	}
	// The probe ends once upstream headers or the fetch error arrive, not
	// when the body has streamed, so a newer failure can admit the next.
	endProbe := func() {
		if probing {
			probing = false
			f.c.gates.endProbe(f.repo.Host)
		}
	}
	defer endProbe()
	probeDeadline := probing && f.holdsStaleEntry()
	// A refs fill from upstream renews the repository's access record, so
	// the purge marker is checked first, alongside the upstream request.
	purge := f.startPurgeCheck()
	defer purge.wait()
	started := f.c.now()
	resp, done, err := f.fetchHeaders(probeDeadline)
	if err != nil {
		// The error is not logged: a credential source's error may carry
		// upstream response bytes.
		f.logger().Debug("upstream fetch failed")
		var res upstreamResult
		switch {
		case f.ctx.Err() != nil:
			// A cancelled fill's dial error says nothing about upstream.
		case f.headerCut.Load() == headerCutProbe:
			res = upstreamResult{eligible: true, reason: staleReasonHealthGate}
		default:
			res = classifyFetchError(err, f.headerCut.Load() == headerCutTimeout)
		}
		f.reportHealth(res, started)
		endProbe()
		f.releaseOrServeStale(res, observability.FillReasonFetchError)
		return
	}
	defer done()
	res := classifyStatus(upstreamStatus(resp))
	f.reportHealth(res, started)
	endProbe()
	body := newIdleReader(resp.Body, f.c.opts.IdleTimeout, f.cancel)
	defer func() { _ = body.Close() }()

	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != responseContentType(f.req.Class) {
		f.share(resp, body, res)
		return
	}
	if !identityEncoded(resp.Header) {
		f.release(observability.FillReasonEncoding, transientCooldown)
		return
	}
	now := f.c.now()
	// While the purge state is not known current, pack hits lapse within
	// accessRecheck rather than outlive a purge on another replica.
	if f.key.Group == GroupRefs && purge.wait() {
		f.c.access.record(f.key.RepoHash, now)
	}
	if !f.openSpool(resp.ContentLength, now) {
		return
	}
	f.setOutcome(fillOutcome{kind: fillStreaming, contentType: resp.Header.Get("Content-Type"), tier: observability.TierUpstream})
	f.streamBody(resp.ContentLength, body)
}

// fetchHeaders performs the upstream round trip under a context of its
// own, cancelled if response headers do not arrive within the
// response-header timeout or, with probeDeadline set, within the gate's
// probe interval, whichever expires first; headerCut records which. The
// timers are stopped once headers arrive so the body is not bounded by
// them. The caller calls done once it has finished with the body.
func (f *fill) fetchHeaders(probeDeadline bool) (resp *http.Response, done context.CancelFunc, err error) {
	ctx, cancel := context.WithCancel(f.ctx)
	cut := func(reason uint32) func() {
		return func() {
			if f.headerCut.CompareAndSwap(headerCutNone, reason) {
				cancel()
			}
		}
	}
	if t := f.c.opts.ResponseHeaderTimeout; t > 0 {
		timer := time.AfterFunc(t, cut(headerCutTimeout))
		defer timer.Stop()
	}
	if probeDeadline {
		timer := time.AfterFunc(f.c.gates.interval, cut(headerCutProbe))
		defer timer.Stop()
	}
	resp, err = f.fetch.Fetch(ctx, f.req)
	if err == nil && (resp == nil || resp.Body == nil) {
		err = errors.New("cache: fetcher returned no response body")
	}
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return resp, cancel, nil
}

// share relays a non-streamable upstream response to every subscriber:
// the body is buffered up to sharedBodyLimit and, with the response
// headers and status, becomes the one response they all write. A status
// eligible for stale service is answered from a stale entry instead when
// one qualifies.
func (f *fill) share(resp *http.Response, body io.Reader, res upstreamResult) {
	buf, err := io.ReadAll(io.LimitReader(body, sharedBodyLimit+1))
	switch {
	case err != nil:
		f.releaseOrServeStale(res, observability.FillReasonFetchError)
		return
	case len(buf) > sharedBodyLimit:
		f.releaseOrServeStale(res, observability.FillReasonUpstreamStatus)
		return
	}
	h := make(http.Header, len(resp.Header))
	for k, vs := range resp.Header {
		if !hopByHopHeader(k) && k != "Content-Length" {
			h[k] = vs
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(buf)))
	shared := fillOutcome{kind: fillShared, status: resp.StatusCode, header: h, body: buf}
	if f.serveStale(res, shared, observability.FillReasonUpstreamStatus) {
		return
	}
	f.finish(observability.FillResultDiscarded, observability.FillReasonUpstreamStatus, transientCooldown)
	f.setOutcome(shared)
}

// reportHealth applies the result of the fill's upstream request, begun
// at started, to its host's health gate while stale-if-error is enabled.
func (f *fill) reportHealth(res upstreamResult, started time.Time) {
	if f.c.staleEnabled() {
		f.c.gates.report(f.repo.Host, res, started, f.c.now())
	}
}

// holdsStaleEntry reports whether the fill's key has a tier-1 entry that
// stale service could answer with.
func (f *fill) holdsStaleEntry() bool {
	e := f.c.openStaleEntry(f.key, f.repo, string(f.req.Class))
	if e == nil {
		return false
	}
	e.close()
	return true
}

// releaseOrServeStale answers the fill's subscribers from a stale entry
// when res is eligible and one qualifies, and otherwise releases them to
// the passthrough path.
func (f *fill) releaseOrServeStale(res upstreamResult, reason string) {
	if !f.serveStale(res, fillOutcome{kind: fillReleased}, reason) {
		f.release(reason, transientCooldown)
	}
}

// openSpool reserves disk for the response and writes the sealed header.
// A pack fill reserves the sealed size of the upstream Content-Length, or
// of maxEntrySize when the length is unknown (contentLength -1), plus
// headroom for flushes; a refs fill reserves refsInitialReservation. A
// response whose Content-Length already exceeds maxEntrySize will not be
// stored, so it reserves its sealed size from free budget only, without
// evicting entries; if that cannot be made its subscribers pass through.
func (f *fill) openSpool(contentLength int64, now time.Time) bool {
	oversize := contentLength > f.c.opts.MaxEntrySize
	reserve := int64(refsInitialReservation)
	switch {
	case oversize:
		reserve = sealedSize(contentLength) + reserveStep
	case f.key.Group == GroupPack:
		expected := f.c.opts.MaxEntrySize
		if contentLength >= 0 {
			expected = contentLength
		}
		reserve = sealedSize(expected) + reserveStep
	}
	sp, err := f.c.store.Create(f.key.Path(), reserve, !oversize)
	if err != nil {
		if oversize {
			f.release(observability.FillReasonTooLarge, f.c.opts.Retention)
		} else {
			f.release(storeReason(err), transientCooldown)
		}
		return false
	}
	f.spool = sp
	hdr := entryHeader{
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
	w := &spoolWriter{sp: sp, reserved: reserve, evictBelow: sealedSize(f.c.opts.MaxEntrySize) + reserveStep}
	sw, err := newSealedWriter(w, f.c.keyring, hdr)
	if err != nil {
		sp.Abort()
		f.release(storeReason(err), transientCooldown)
		return false
	}
	f.seal.w = sw
	f.createdAt = now
	return true
}

// streamBody copies the upstream body into the spool through the sealed
// writer and the storability scanner, then commits or discards the spool.
func (f *fill) streamBody(contentLength int64, body io.Reader) {
	defer func() {
		if h := f.c.hooks.afterDecision; h != nil {
			h(f.key)
		}
	}()
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
		f.commit()
	}
}

// commit stores the spool. The body is complete and readable by then, so
// a commit failure is a discard, not an abort. A refs entry committed
// after a push bumped the repository's generation may carry the pre-push
// tips, so it is deleted again, but only once every subscriber attached
// to this fill has opened it: they are still served the bytes upstream
// sent them.
func (f *fill) commit() {
	if h := f.c.hooks.beforeCommit; h != nil {
		h(f.key)
	}
	if err := f.spool.Commit(); err != nil {
		f.logger().Warn("entry could not be committed", "error", err)
		f.finish(observability.FillResultDiscarded, observability.FillReasonStoreError, transientCooldown)
		return
	}
	if f.key.Group == GroupRefs && f.c.gens.current(f.key.RepoHash) != f.gen {
		f.dropEntry = true
		f.finish(observability.FillResultDiscarded, observability.FillReasonGeneration, 0)
		return
	}
	f.stored = true
	f.c.noteCommit()
	f.finish(observability.FillResultStored, "", 0)
	if f.c.remote != nil && f.source == observability.TierUpstream && f.c.uploadsGroup(f.key.Group) {
		f.c.enqueueUpload(uploadJob{key: f.key, repo: f.repo, gen: f.gen, createdAt: f.createdAt})
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

// flushSeal runs on the flush timer and seals whatever is buffered. A
// panic here is recorded as the seal error so the fill aborts on its
// next write instead of the process ending.
func (f *fill) flushSeal() {
	f.seal.mu.Lock()
	defer f.seal.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			f.c.logger.Error("flush panicked", "class", f.req.Class, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			f.seal.err = fmt.Errorf("cache: flush panicked: %v", r)
		}
	}()
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
	f.stopFlushLocked()
	if f.seal.err != nil {
		return f.seal.err
	}
	return f.seal.w.Close()
}

// stopFlushLocked ends sealing so no later flush runs. seal.mu must be
// held.
func (f *fill) stopFlushLocked() {
	f.seal.closed = true
	if f.seal.timer != nil {
		f.seal.timer.Stop()
	}
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
// The result and the mark are recorded first, so a released request that
// passes through already sees both.
func (f *fill) release(reason string, markFor time.Duration) {
	f.finish(observability.FillResultDiscarded, reason, markFor)
	f.setOutcome(fillOutcome{kind: fillReleased})
}

// discard ends a spool that served its subscribers but is not storable:
// readers receive every byte and then EOF. The file is removed by
// releaseSpool once every attached subscriber has opened it.
func (f *fill) discard(reason string, markFor time.Duration) {
	f.spool.Discard()
	f.finish(observability.FillResultDiscarded, reason, markFor)
}

// abort ends a fill that cannot continue: readers of the spool receive err
// and abort their clients' connections, and subscribers that have not yet
// started reading take the passthrough path. A response that outgrew the
// entry size limit marks its key for the retention period; any other
// cause marks it for the transient cooldown.
func (f *fill) abort(err error, reason string) {
	if f.abandoned.Load() {
		f.logger().Debug("fill cancelled after its subscribers left")
	} else {
		f.logger().Warn("fill aborted", "reason", reason, "error", err)
	}
	f.seal.mu.Lock()
	f.stopFlushLocked()
	f.seal.mu.Unlock()
	if f.spool != nil {
		f.spool.Fail(err)
	}
	markFor := transientCooldown
	if errors.Is(err, errOversizeGrowth) {
		markFor = f.c.opts.Retention
	}
	f.release(reason, markFor)
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
	f.c.metrics.RecordResponseCacheFill(ctx, f.repo.Host, string(f.req.Class), f.source, result, reason)
	if f.fetched > 0 {
		f.c.metrics.RecordResponseCacheFillBytes(ctx, f.repo.Host, string(f.req.Class), f.source, f.fetched)
	}
	if markFor > 0 && !f.abandoned.Load() {
		now := f.c.now()
		f.c.marks.mark(f.key, now, now.Add(markFor))
	}
	attrs := []any{"result", result, "bytes", f.fetched, "source", f.source}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	f.logger().Debug("fill finished", attrs...)
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
	f.signalPendingLocked()
	c.mu.Unlock()
	f.cancel()
}

// releaseSpool removes a discarded spool, or deletes the entry of a
// commit that a push superseded, once every subscriber attached before
// the fill ended has opened it or left, or the grace period has passed.
// Readers that already hold the file keep reading it. Stored and failed
// spools need nothing here.
func (f *fill) releaseSpool() {
	if f.spool == nil {
		return
	}
	discarded := f.spool.discarded()
	if !discarded && !f.dropEntry {
		return
	}
	timer := time.NewTimer(lateSubscriberGrace)
	defer timer.Stop()
	select {
	case <-f.noPending:
	case <-timer.C:
		f.logger().Warn("subscribers did not open the spool in time; releasing it")
	}
	if discarded {
		f.spool.Release()
		return
	}
	_ = f.spool.DeleteEntry()
}

// attachLocked adds a subscriber. Cache.mu must be held.
func (f *fill) attachLocked() {
	f.subscribers++
	f.pending++
	if f.idle != nil {
		f.idle.Stop()
		f.idle = nil
	}
}

// readerOpened records that a subscriber has opened the spool, or has
// found it committed and opened the entry instead.
func (f *fill) readerOpened() {
	f.c.mu.Lock()
	f.pending--
	f.signalPendingLocked()
	f.c.mu.Unlock()
}

// detach removes a subscriber and, when none remain, schedules the fill's
// cancellation after the idle grace period. opened reports whether the
// subscriber called readerOpened.
func (f *fill) detach(opened bool) {
	c := f.c
	c.mu.Lock()
	defer c.mu.Unlock()
	f.subscribers--
	if !opened {
		f.pending--
		f.signalPendingLocked()
	}
	if f.subscribers == 0 && !f.ended {
		f.idle = time.AfterFunc(c.idleGrace, f.abandon)
	}
}

// signalPendingLocked closes noPending once the fill has ended and no
// attached subscriber is still to open the spool. Cache.mu must be held.
func (f *fill) signalPendingLocked() {
	if f.ended && f.pending == 0 && !f.pendingClosed {
		f.pendingClosed = true
		close(f.noPending)
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
// ahead of the bytes so that a write never exceeds it. Growth up to
// evictBelow sealed bytes may evict committed entries; beyond it, where
// the response can no longer be stored, only free budget is used.
type spoolWriter struct {
	sp         *spool
	written    int64
	reserved   int64
	evictBelow int64
}

func (w *spoolWriter) Write(p []byte) (int, error) {
	end := w.written + int64(len(p))
	if need := end - w.reserved; need > 0 {
		add := max(need, reserveStep)
		evict := end <= w.evictBelow
		if err := w.sp.Reserve(add, evict); err != nil {
			if !evict && errors.Is(err, errBudget) {
				err = fmt.Errorf("%w: %w", errOversizeGrowth, err)
			}
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
	if class == classAdvertisement {
		return contentTypeAdvertisement
	}
	return contentTypeResult
}

// identityEncoded reports whether a response carries no Content-Encoding
// other than identity. Any other coding cannot be streamed to clients or
// stored, since the fill requests identity and relays no coding header.
func identityEncoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for coding := range strings.SplitSeq(v, ",") {
			if c := strings.ToLower(strings.TrimSpace(coding)); c != "" && c != "identity" {
				return false
			}
		}
	}
	return true
}

// scanMode selects the response grammar for a request.
func scanMode(req Request) pktline.Mode {
	switch req.Class {
	case classAdvertisement:
		return pktline.ModeAdvertisement
	case classLsRefs:
		return pktline.ModeV2Result
	case classFetch:
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

// storeReason labels a spool error: a response that outgrew the entry
// size limit, a budget failure, or any other store error.
func storeReason(err error) string {
	switch {
	case errors.Is(err, errOversizeGrowth):
		return observability.FillReasonTooLarge
	case errors.Is(err, errBudget):
		return observability.FillReasonDiskBudget
	default:
		return observability.FillReasonStoreError
	}
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
