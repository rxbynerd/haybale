package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

const (
	// janitorInterval is how often the disk store sweeps expired entries
	// and orphaned temporary files.
	janitorInterval = time.Minute
	// maxCreatedAtSkew is how far in the future an entry's creation time
	// may lie before the entry is treated as corrupt.
	maxCreatedAtSkew = 5 * time.Minute
	// maxClassifications bounds how many requests are in the pre-stream
	// phase (reading and classifying the body, then looking up or
	// joining a fill) at once; a request that finds no slot passes
	// through unclassified.
	maxClassifications = 128
)

// errClientGone reports that the client stopped accepting the response.
var errClientGone = errors.New("cache: client stopped reading")

// errStaleNeedsHeaderTimeout rejects stale-if-error without a bound on the
// wait for upstream response headers.
var errStaleNeedsHeaderTimeout = errors.New("cache: staleIfErrorFor requires a non-zero responseHeaderTimeout; with no header bound a hung upstream would hold requests indefinitely")

// Options configures a Cache.
type Options struct {
	// Dir is the cache directory; see openDiskStore for its requirements.
	Dir string
	// Keyring holds the key entries are sealed under and addressed by.
	Keyring Keyring
	// MaxDiskSize is the disk budget in bytes.
	MaxDiskSize int64
	// MaxEntrySize is the largest response body stored, in bytes. It must
	// not exceed half of MaxDiskSize, so that a pack fill of unknown
	// length can always reserve its sealed size.
	MaxEntrySize int64
	// MaxConcurrentFills bounds pack fills in flight, each of which may
	// reserve maxEntrySize; a request that finds no free slot bypasses
	// the cache. Refs fills are bounded separately by a fixed cap.
	MaxConcurrentFills int
	// MaxRequestBody bounds the decoded request body classify inspects.
	MaxRequestBody int64
	// Retention is the maximum age of any entry.
	Retention time.Duration
	// RefsMaxAge is the maximum age of a refs entry served as a hit; zero
	// means refs always go upstream and are not coalesced.
	RefsMaxAge time.Duration
	// AccessRecheck is how recently an upstream refs response must have
	// succeeded for a pack hit to be served; zero disables the rule.
	AccessRecheck time.Duration
	// ResponseHeaderTimeout bounds the wait for upstream response headers
	// on a fill; zero means unbounded.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds the gap between upstream body bytes on a fill;
	// zero means unbounded.
	IdleTimeout time.Duration
	// ExposeStatus emits the Cache-Status response header.
	ExposeStatus bool
	// StaleIfErrorFor is the maximum age of an entry served when upstream
	// cannot answer a read; zero disables stale service. It must not
	// exceed Retention, and needs a positive ResponseHeaderTimeout.
	StaleIfErrorFor time.Duration
	// Remote is the optional remote tier, shared by every replica that
	// holds the same key. The implementation bounds the time to first
	// byte of its Stat and Get calls; nil disables the tier.
	Remote BlobStore
	// RemoteHeaderTimeout bounds remote-tier work on the request path that
	// the store does not: reading a remote entry's sealed header before the
	// fill falls through to upstream. Zero bounds that read by IdleTimeout
	// instead, and the deletions after a push, a failed verification or a
	// superseded upload by one minute.
	RemoteHeaderTimeout time.Duration
	// Logger receives operational logs; nil discards them.
	Logger *slog.Logger
	// Metrics receives the response-cache instruments; nil records nothing.
	Metrics *observability.Metrics
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Cache is the response cache engine: it classifies policy-allowed reads,
// serves hits from the disk store, and coalesces misses into fills. It
// is safe for concurrent use.
type Cache struct {
	opts    Options
	store   *diskStore
	keyring Keyring
	logger  *slog.Logger
	metrics *observability.Metrics
	now     func() time.Time

	// ctx is the cache's lifetime; fills and the janitor derive from it
	// and Close cancels it.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// slots are the pack fill slots; refsFills counts refs fills in
	// flight against maxRefsFills and is guarded by mu.
	slots     chan struct{}
	refsFills int
	// classifySlots bounds the requests in Serve's pre-stream phase.
	classifySlots chan struct{}

	idleGrace     time.Duration
	flushInterval time.Duration
	// markerTimeout bounds one read of a repository's purge marker.
	markerTimeout time.Duration

	gens   generations
	access accessRecords
	marks  uncacheableMarks
	purges purgeRecords
	gates  healthGates

	// remote is the remote tier, nil when there is none. Uploads and
	// remote deletions run under remoteCtx, which Close cancels only once
	// they have been flushed or its deadline has passed; remoteWG counts
	// the upload workers and background remote tasks, of which
	// remoteTasks bounds how many run at once.
	remote       BlobStore
	remoteCtx    context.Context
	remoteCancel context.CancelFunc
	remoteWG     sync.WaitGroup
	uploads      chan uploadJob
	remoteTasks  chan struct{}

	// mu orders fill attach, detach, start and teardown, so a request
	// never joins a fill that is ending. remoteClosed, set by Close under
	// mu, stops new uploads and remote tasks.
	mu           sync.Mutex
	fills        map[entryKey]*fill
	closed       bool
	remoteClosed bool
	// commits counts fills that committed an entry, so a request that
	// looked the entry up outside mu can tell whether one landed since.
	commits uint64

	hooks fillHooks
}

// fillHooks are seams for tests; every field is nil in production.
type fillHooks struct {
	// beforeCommit runs between a fill's generation check and its Commit.
	beforeCommit func(key entryKey)
	// afterDecision runs once a fill has committed or discarded its spool
	// and before it ends.
	afterDecision func(key entryKey)
	// beforeOpenReader runs in a subscriber just before it opens the
	// spool of a streaming fill.
	beforeOpenReader func(key entryKey)
	// afterCommittedOpen runs in a subscriber that found the spool
	// committed, once it has told the fill it opened the entry.
	afterCommittedOpen func(key entryKey)
	// markerCheckJoined runs when a refs fill joins another fill's purge
	// marker read, before it waits for the result.
	markerCheckJoined func()
	// afterFetch runs in a fill once its Fetcher has returned a response,
	// before the fill claims the response from its header timers.
	afterFetch func(key entryKey)
	// beforeStaleOutcome runs in a fill that has found a qualifying
	// tier-1 entry, before it tells its subscribers to serve it.
	beforeStaleOutcome func(key entryKey)
	// afterProbeDeadline runs beside a probe once its deadline has passed
	// and the purge state is known, reporting whether its subscribers were
	// answered stale.
	afterProbeDeadline func(key entryKey, answered bool)
}

// New opens the cache directory, indexes its entries, removes entries
// sealed under any key other than the active one, and starts the
// janitor and, with a remote tier, the upload workers. The returned Cache
// runs until Close.
func New(opts Options) (*Cache, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = observability.NewNoopMetrics()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	store, err := openDiskStore(opts.Dir, opts.MaxDiskSize, logger, metrics, now)
	if err != nil {
		return nil, err
	}
	removed, err := store.removeForeignEntries(opts.Keyring.activeID())
	if err != nil {
		logger.Warn("removing cache entries sealed under another key failed", "error", err)
	}
	if removed > 0 {
		logger.Info("removed cache entries sealed under another key", "entries", removed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	remoteCtx, remoteCancel := context.WithCancel(context.Background())
	c := &Cache{
		opts:          opts,
		store:         store,
		keyring:       opts.Keyring,
		logger:        logger,
		metrics:       metrics,
		now:           now,
		ctx:           ctx,
		cancel:        cancel,
		slots:         make(chan struct{}, opts.MaxConcurrentFills),
		classifySlots: make(chan struct{}, maxClassifications),
		idleGrace:     fillIdleGrace,
		flushInterval: sealFlushInterval,
		markerTimeout: purgeMarkerTimeout,
		access:        accessRecords{window: opts.AccessRecheck},
		purges:        purgeRecords{retention: opts.Retention, interval: markerCheckInterval(opts.AccessRecheck)},
		gates:         healthGates{logger: logger, interval: healthProbeInterval},
		remote:        opts.Remote,
		remoteCtx:     remoteCtx,
		remoteCancel:  remoteCancel,
		fills:         make(map[entryKey]*fill),
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		store.runJanitor(ctx, janitorInterval, opts.Retention)
	}()
	if c.remote != nil {
		c.uploads = make(chan uploadJob, uploadQueueSize)
		c.remoteTasks = make(chan struct{}, maxRemoteTasks)
		c.remoteWG.Add(uploadWorkers)
		for range uploadWorkers {
			go c.runUploads()
		}
	}
	return c, nil
}

func validateOptions(opts Options) error {
	switch {
	case opts.Dir == "":
		return errors.New("cache: dir is required")
	case opts.Keyring.activeID() == "":
		return errors.New("cache: keyring has no active key")
	case opts.MaxDiskSize <= 0:
		return fmt.Errorf("cache: max disk size must be positive, got %d", opts.MaxDiskSize)
	case opts.MaxEntrySize <= 0 || opts.MaxEntrySize > opts.MaxDiskSize/2:
		return fmt.Errorf("cache: max entry size %d must be between 1 and half of the disk size %d", opts.MaxEntrySize, opts.MaxDiskSize)
	case opts.MaxConcurrentFills < 1:
		return fmt.Errorf("cache: max concurrent fills must be at least 1, got %d", opts.MaxConcurrentFills)
	case opts.MaxRequestBody <= 0:
		return fmt.Errorf("cache: max request body must be positive, got %d", opts.MaxRequestBody)
	case opts.Retention <= 0:
		return fmt.Errorf("cache: retention must be positive, got %v", opts.Retention)
	case opts.RefsMaxAge < 0 || opts.AccessRecheck < 0 || opts.ResponseHeaderTimeout < 0 || opts.IdleTimeout < 0 || opts.RemoteHeaderTimeout < 0 || opts.StaleIfErrorFor < 0:
		return errors.New("cache: durations must not be negative")
	case opts.StaleIfErrorFor > opts.Retention:
		return fmt.Errorf("cache: stale-if-error age %v must not exceed retention %v", opts.StaleIfErrorFor, opts.Retention)
	case opts.StaleIfErrorFor > 0 && opts.ResponseHeaderTimeout == 0:
		return errStaleNeedsHeaderTimeout
	}
	return nil
}

// Serve handles a read that authentication and policy have already
// allowed for the verified identity, which is recorded on the
// cache_stale_served event when the read is answered stale. It returns
// handled=true when the response has been fully written. handled=false
// means the proxy must run its passthrough path: the request was not
// cacheable, the key is marked uncacheable, no fill slot was free, or the
// fill could not serve this request; r.Body then replays the bytes
// already read, and when the cache exposes its status the Cache-Status
// bypass header is already set on w. A subscriber whose response fails
// after bytes were written aborts the connection with
// panic(http.ErrAbortHandler).
func (c *Cache) Serve(w http.ResponseWriter, r *http.Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, identity string) (out Outcome, handled bool) {
	release, ok := c.takeClassifySlot(r)
	if !ok {
		return c.declined(w, repo.Host, observability.ClassBypass, "body_budget"), false
	}
	// The slot covers the pre-stream phase only. serve releases it early
	// once the request starts streaming a response; this defer releases it
	// on every other exit, including a panic.
	defer release()
	return c.serve(w, r, repo, baseURL, fetch, identity, release)
}

// takeClassifySlot reserves a classification slot for a request with a
// body and returns a function that releases it exactly once. A request
// without a body needs no slot. ok is false when every slot is busy.
func (c *Cache) takeClassifySlot(r *http.Request) (release func(), ok bool) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return func() {}, true
	}
	select {
	case c.classifySlots <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(func() { <-c.classifySlots }) }, true
}

// serve classifies the request and answers it from an entry or a fill.
// release frees the request's classification slot; serve calls it before
// it starts streaming a response, so a long transfer does not hold a slot.
func (c *Cache) serve(w http.ResponseWriter, r *http.Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, identity string, release func()) (Outcome, bool) {
	host := repo.Host
	req, bypass, reason, err := classify(r, repo, c.opts.MaxRequestBody)
	if err != nil {
		c.logger.WarnContext(r.Context(), "request could not be classified", "host", host, "error", err)
		return c.declined(w, host, observability.ClassBypass, "classify_error"), false
	}
	if bypass {
		return c.declined(w, host, observability.ClassBypass, reason), false
	}
	class := string(req.Class)
	key := entryKey{Group: req.Class.Group(), RepoHash: c.keyring.RepoHash(baseURL, repo), KeyHash: c.keyring.pathHash(req.Digest)}
	// A request the health gate holds is answered from its stale entry
	// wherever it would otherwise start or join a fill, and also when its
	// key is marked uncacheable.
	if c.marks.marked(key, c.now()) {
		if out, ok := c.serveHeld(w, r, key, repo, class, identity, release); ok {
			return out, true
		}
		return c.declined(w, host, class, "uncacheable"), false
	}
	if key.Group == GroupRefs && c.opts.RefsMaxAge <= 0 {
		if out, ok := c.serveHeld(w, r, key, repo, class, identity, release); ok {
			return out, true
		}
		f, ok := c.startSingle(key, req, repo, baseURL, fetch)
		if !ok {
			return c.declined(w, host, class, "no_slot"), false
		}
		release()
		return c.subscribe(w, r, f, false, repo, class, identity)
	}

	if e := c.openEntry(key, repo, class, true); e != nil {
		release()
		if out, ok := c.serveOpened(w, e, repo, class, cacheStatus{result: observability.ResultHit}, observability.TierDisk); ok {
			return out, true
		}
	}
	if out, ok := c.serveHeld(w, r, key, repo, class, identity, release); ok {
		return out, true
	}
	// A stored entry that fails verification before any byte is written
	// has been deleted, so the request joins or starts a fill instead; a
	// second failure of a freshly committed entry is declined.
	for range 2 {
		f, e, collapsed, declined := c.joinOrStart(key, req, repo, baseURL, fetch, class)
		if declined != "" {
			return c.declined(w, host, class, declined), false
		}
		release()
		if e != nil {
			if out, ok := c.serveOpened(w, e, repo, class, cacheStatus{result: observability.ResultHit}, observability.TierDisk); ok {
				return out, true
			}
			continue
		}
		return c.subscribe(w, r, f, collapsed, repo, class, identity)
	}
	return c.declined(w, host, class, "verification"), false
}

// declined records a request the cache did not handle and prepares w for
// the passthrough path.
func (c *Cache) declined(w http.ResponseWriter, host, class, reason string) Outcome {
	c.metrics.RecordResponseCacheLookup(context.Background(), host, class, observability.ResultBypass)
	c.setCacheStatus(w.Header(), cacheStatus{result: observability.ResultBypass})
	c.logger.Debug("bypass", "host", host, "class", class, "reason", reason)
	return Outcome{Result: observability.ResultBypass}
}

// openedEntry is a stored entry whose header has been verified and whose
// body is ready to stream.
type openedEntry struct {
	entry *storedEntry
	sr    *sealedReader
}

func (e *openedEntry) close() { _ = e.entry.Close() }

// openEntry opens and verifies the stored entry for key, returning nil
// when there is none to serve. An entry that fails verification is
// deleted, as is an entry older than a purge of its repository recorded in
// a purge marker. With fresh set the freshness rules apply too: a pack entry
// needs a recent upstream refs success, an entry past retention is
// deleted and missed, and a refs entry older than RefsMaxAge is missed.
// Freshness is judged from the authenticated creation time, never from
// the file. The caller closes the result.
func (c *Cache) openEntry(key entryKey, repo gitproto.Repo, class string, fresh bool) *openedEntry {
	now := c.now()
	if fresh && key.Group == GroupPack && !c.access.recent(key.RepoHash, now) {
		return nil
	}
	entry, err := c.store.Open(key.Path())
	if err != nil {
		return nil
	}
	sr, err := newSealedReader(entry, c.keyring)
	if err == nil {
		err = verifyHeader(sr.Header(), key, now)
	}
	if err != nil {
		c.dropCorrupt(entry, repo, class, err)
		_ = entry.Close()
		return nil
	}
	if c.purges.covers(key, sr.Header().CreatedAt) {
		_ = c.store.DeleteEntry(entry)
		_ = entry.Close()
		return nil
	}
	if fresh {
		age := now.Sub(sr.Header().CreatedAt)
		switch {
		case age > c.opts.Retention:
			_ = c.store.DeleteEntry(entry)
			_ = entry.Close()
			return nil
		case key.Group == GroupRefs && age > c.opts.RefsMaxAge:
			_ = entry.Close()
			return nil
		}
	}
	return &openedEntry{entry: entry, sr: sr}
}

// serveOpened streams a verified entry to the client, labelled with the
// status's result and with tier. ok is false when the body failed
// verification before any byte was written; the entry has then been
// deleted and the caller treats the request as a miss. A failure after
// bytes were written also deletes the entry and then aborts the response.
func (c *Cache) serveOpened(w http.ResponseWriter, e *openedEntry, repo gitproto.Repo, class string, st cacheStatus, tier string) (Outcome, bool) {
	defer e.close()
	n, started, err := c.stream(w, e.sr, e.sr.Header().ContentType, st)
	switch {
	case errors.Is(err, errClientGone):
	case err != nil && !started:
		c.dropCorrupt(e.entry, repo, class, err)
		return Outcome{}, false
	case err != nil:
		c.dropCorrupt(e.entry, repo, class, err)
		c.logger.Warn("entry failed mid-stream; aborting the response", "host", repo.Host, "class", class, "error", err)
		panic(http.ErrAbortHandler)
	}
	ctx := context.Background()
	c.metrics.RecordResponseCacheLookup(ctx, repo.Host, class, st.result)
	c.metrics.RecordResponseCacheServedBytes(ctx, repo.Host, class, tier, n)
	return Outcome{Result: st.result, Collapsed: st.collapsed, Status: http.StatusOK, BytesOut: n}, true
}

// verifyHeader checks that a verified header belongs at key and carries a
// plausible creation time.
func verifyHeader(h entryHeader, key entryKey, now time.Time) error {
	if h.Group != key.Group || h.RepoHash != key.RepoHash || h.KeyHash != key.KeyHash {
		return fmt.Errorf("%w: header does not match the entry path", ErrIntegrity)
	}
	if h.CreatedAt.After(now.Add(maxCreatedAtSkew)) {
		return fmt.Errorf("%w: creation time is in the future", ErrIntegrity)
	}
	return nil
}

// dropCorrupt deletes an entry that could not be served, leaving any
// entry committed at the same path since untouched. A verification
// failure is a security event; a plain read error is a store error only.
func (c *Cache) dropCorrupt(entry *storedEntry, repo gitproto.Repo, class string, err error) {
	c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierDisk, observability.OperationOpen)
	if errors.Is(err, ErrIntegrity) {
		security.Log(c.logger, security.EventCacheIntegrityFailed, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "class", class)
		c.logger.Debug("entry failed verification; deleting it", "host", repo.Host, "class", class, "error", err)
	} else {
		c.logger.Warn("entry could not be read; deleting it", "host", repo.Host, "class", class, "error", err)
	}
	_ = c.store.DeleteEntry(entry)
}

// startSingle starts a fill that no other request can join, for a refs
// request while refsMaxAge is zero.
func (c *Cache) startSingle(key entryKey, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher) (*fill, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	f := c.startFillLocked(key, req, repo, baseURL, fetch, false)
	return f, f != nil
}

// joinOrStart attaches the request to the in-flight fill for key, or
// returns a stored entry committed since the caller's lookup, or starts a
// new fill. The entry lookup runs without mu held; a fill is started only
// if no commit landed meanwhile, so a request never duplicates a fill
// that has just committed. A refs fill that began before the latest push
// is not joined, since its response may carry the pre-push tips. declined
// is the bypass reason when the request cannot use the cache: no fill
// slot is free, the cache is closed, or the in-flight refs fill is stale.
func (c *Cache) joinOrStart(key entryKey, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, class string) (f *fill, e *openedEntry, collapsed bool, declined string) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, nil, false, "no_slot"
		}
		if f := c.fills[key]; f != nil && !f.ended {
			if c.staleRefsFill(f) {
				c.mu.Unlock()
				return nil, nil, false, "stale_fill"
			}
			f.attachLocked()
			c.mu.Unlock()
			return f, nil, true, ""
		}
		commits := c.commits
		c.mu.Unlock()

		e := c.openEntry(key, repo, class, true)

		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			if e != nil {
				e.close()
			}
			return nil, nil, false, "no_slot"
		case e != nil:
			c.mu.Unlock()
			return nil, e, false, ""
		}
		if f := c.fills[key]; f != nil && !f.ended {
			if c.staleRefsFill(f) {
				c.mu.Unlock()
				return nil, nil, false, "stale_fill"
			}
			f.attachLocked()
			c.mu.Unlock()
			return f, nil, true, ""
		}
		if c.commits != commits {
			c.mu.Unlock()
			continue
		}
		f = c.startFillLocked(key, req, repo, baseURL, fetch, true)
		c.mu.Unlock()
		if f == nil {
			return nil, nil, false, "no_slot"
		}
		return f, nil, false, ""
	}
}

// staleRefsFill reports whether f is a refs fill that began before the
// repository's latest push. Such a fill is discarded at commit, so a new
// request must not take its response.
func (c *Cache) staleRefsFill(f *fill) bool {
	return f.key.Group == GroupRefs && c.gens.current(f.key.RepoHash) != f.gen
}

// noteCommit records that a fill committed an entry.
func (c *Cache) noteCommit() {
	c.mu.Lock()
	c.commits++
	c.mu.Unlock()
}

// startFillLocked takes a fill slot for the key's group and starts the
// fill goroutine with the caller as its first subscriber. It returns nil
// when no slot is free. Cache.mu must be held.
func (c *Cache) startFillLocked(key entryKey, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, shared bool) *fill {
	if !c.acquireSlotLocked(key.Group) {
		return nil
	}
	f := c.newFill(key, req, repo, baseURL, fetch, shared)
	f.subscribers = 1
	f.pending = 1
	if shared {
		c.fills[key] = f
	}
	c.wg.Add(1)
	go f.run()
	return f
}

// acquireSlotLocked takes a fill slot for group: one of the configured
// pack slots, or one of the fixed refs slots. Cache.mu must be held.
func (c *Cache) acquireSlotLocked(group Group) bool {
	if group == GroupRefs {
		if c.refsFills >= maxRefsFills {
			return false
		}
		c.refsFills++
		return true
	}
	select {
	case c.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseSlot returns the slot acquireSlotLocked took for group.
func (c *Cache) releaseSlot(group Group) {
	if group == GroupRefs {
		c.mu.Lock()
		c.refsFills--
		c.mu.Unlock()
		return
	}
	<-c.slots
}

// subscribe serves the request from fill f. A subscriber that attaches
// after the fill committed is served from the committed entry; one that
// attaches after a discard decision still reads the spool, which the fill
// keeps until every attached subscriber has opened it.
func (c *Cache) subscribe(w http.ResponseWriter, r *http.Request, f *fill, collapsed bool, repo gitproto.Repo, class, identity string) (Outcome, bool) {
	host := repo.Host
	opened := false
	defer func() { f.detach(opened) }()
	ctx := context.Background()
	if collapsed {
		c.metrics.RecordResponseCacheCollapsed(ctx, host)
	}
	select {
	case <-f.headerReady:
	case <-r.Context().Done():
		return Outcome{Result: observability.ResultMiss, Collapsed: collapsed}, true
	}
	out := f.outcome
	switch out.kind {
	case fillReleased:
		return c.declined(w, host, class, "fill_released"), false
	case fillShared:
		return c.writeShared(w, &out, host, class, collapsed), true
	case fillStale:
		if res, ok := c.serveStaleEntry(w, f.key, repo, class, collapsed, identity, out.stale); ok {
			return res, true
		}
		if out.fallback.kind == fillShared {
			return c.writeShared(w, out.fallback, host, class, collapsed), true
		}
		return c.declined(w, host, class, "fill_released"), false
	}

	st := cacheStatus{result: observability.ResultMiss, collapsed: collapsed}
	servedAt := c.now()
	if out.stale != nil {
		st = cacheStatus{result: observability.ResultStale, collapsed: collapsed, fwdStatus: out.stale.fwdStatus}
	}
	if h := c.hooks.beforeOpenReader; h != nil {
		h(f.key)
	}
	rd, err := f.spool.NewReader()
	if errors.Is(err, errSpoolCommitted) {
		// The entry is opened before readerOpened, which lets the fill
		// delete an entry a push superseded.
		e := c.openEntry(f.key, repo, class, false)
		opened = true
		f.readerOpened()
		if h := c.hooks.afterCommittedOpen; h != nil {
			h(f.key)
		}
		if e == nil {
			return c.declined(w, host, class, "fill_ended"), false
		}
		res, ok := c.serveOpened(w, e, repo, class, st, out.tier)
		if !ok {
			return c.declined(w, host, class, "verification"), false
		}
		if out.stale != nil {
			c.logStaleServed(identity, repo, class, out.tier, out.stale, servedAt)
		}
		<-f.done
		res.Stored = f.stored
		return res, true
	}
	if err != nil {
		return c.declined(w, host, class, "fill_failed"), false
	}
	opened = true
	f.readerOpened()
	defer func() { _ = rd.Close() }()
	stop := context.AfterFunc(r.Context(), func() { _ = rd.Close() })
	defer stop()
	sr, err := newSealedReader(rd, c.keyring)
	if err != nil {
		return c.declined(w, host, class, "fill_failed"), false
	}
	n, started, err := c.stream(w, sr, out.contentType, st)
	if err != nil && r.Context().Err() != nil {
		err = errClientGone
	}
	switch {
	case errors.Is(err, errClientGone):
		c.metrics.RecordResponseCacheLookup(ctx, host, class, st.result)
		if out.stale != nil {
			c.logStaleServed(identity, repo, class, out.tier, out.stale, servedAt)
		}
		return Outcome{Result: st.result, Collapsed: collapsed, Status: http.StatusOK, BytesOut: n}, true
	case err != nil && !started:
		return c.declined(w, host, class, "fill_failed"), false
	case err != nil:
		c.logger.Warn("fill failed mid-stream; aborting the response", "host", host, "class", class, "error", err)
		panic(http.ErrAbortHandler)
	}
	c.metrics.RecordResponseCacheLookup(ctx, host, class, st.result)
	c.metrics.RecordResponseCacheServedBytes(ctx, host, class, out.tier, n)
	if out.stale != nil {
		c.logStaleServed(identity, repo, class, out.tier, out.stale, servedAt)
	}
	// The spool reaches EOF only once the fill has committed or discarded
	// it, so the fill is about to finish and its result is known.
	<-f.done
	return Outcome{Result: st.result, Collapsed: collapsed, Stored: f.stored, Status: http.StatusOK, BytesOut: n}, true
}

// writeShared writes a fill's shared non-200 response.
func (c *Cache) writeShared(w http.ResponseWriter, out *fillOutcome, host, class string, collapsed bool) Outcome {
	h := w.Header()
	for k, vs := range out.header {
		h[k] = append([]string(nil), vs...)
	}
	c.setCacheStatus(h, cacheStatus{result: observability.ResultMiss, collapsed: collapsed})
	w.WriteHeader(out.status)
	n, _ := w.Write(out.body)
	c.metrics.RecordResponseCacheLookup(context.Background(), host, class, observability.ResultMiss)
	return Outcome{Result: observability.ResultMiss, Collapsed: collapsed, Status: out.status, BytesOut: int64(n)}
}

// serveHeld answers a request whose host's health gate holds it from the
// key's qualifying tier-1 stale entry, before any fill slot, spool or
// upstream request is taken, and releases the classification slot first.
// With a remote tier the repository's purge state must be known current
// first. ok is false, with nothing written, when stale service is
// disabled, the gate does not hold the host, the purge state is not
// current, or no tier-1 entry qualifies; the request then proceeds as it
// would otherwise.
func (c *Cache) serveHeld(w http.ResponseWriter, r *http.Request, key entryKey, repo gitproto.Repo, class, identity string, release func()) (Outcome, bool) {
	if !c.staleEnabled() || !c.gates.held(repo.Host, c.now()) || !c.purgeCurrent(r.Context(), repo, key.RepoHash) {
		return Outcome{}, false
	}
	e := c.openStaleEntry(key, repo, class)
	if e == nil {
		return Outcome{}, false
	}
	release()
	return c.serveStaleOpened(w, e, repo, class, false, identity, &staleService{reason: staleReasonHealthGate})
}

// serveStaleEntry answers the request from the stale tier-1 entry for
// key and records the cache_stale_served event. ok is false, with nothing
// written, when no entry qualifies any longer.
func (c *Cache) serveStaleEntry(w http.ResponseWriter, key entryKey, repo gitproto.Repo, class string, collapsed bool, identity string, st *staleService) (Outcome, bool) {
	e := c.openStaleEntry(key, repo, class)
	if e == nil {
		return Outcome{}, false
	}
	return c.serveStaleOpened(w, e, repo, class, collapsed, identity, st)
}

// serveStaleOpened streams the opened stale entry e as serveStaleEntry
// does, and closes it.
func (c *Cache) serveStaleOpened(w http.ResponseWriter, e *openedEntry, repo gitproto.Repo, class string, collapsed bool, identity string, st *staleService) (Outcome, bool) {
	served := *st
	served.createdAt = e.sr.Header().CreatedAt
	servedAt := c.now()
	res, ok := c.serveOpened(w, e, repo, class, cacheStatus{result: observability.ResultStale, collapsed: collapsed, fwdStatus: st.fwdStatus}, observability.TierDisk)
	if ok {
		c.logStaleServed(identity, repo, class, observability.TierDisk, &served, servedAt)
	}
	return res, ok
}

// stream copies verified plaintext from src to w, flushing after every
// segment. The response headers are written before the first body byte,
// so a failure before any byte leaves w untouched and started false; a
// failure after that returns the error with started true. errClientGone
// reports that the client stopped accepting bytes.
func (c *Cache) stream(w http.ResponseWriter, src io.Reader, contentType string, st cacheStatus) (n int64, started bool, err error) {
	buf := make([]byte, segmentSize)
	k, rerr := src.Read(buf)
	if k == 0 && rerr != nil && !errors.Is(rerr, io.EOF) {
		return 0, false, rerr
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	c.setCacheStatus(h, st)
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	for {
		if k > 0 {
			wn, werr := w.Write(buf[:k])
			n += int64(wn)
			if werr != nil {
				return n, true, errClientGone
			}
			_ = rc.Flush()
		}
		switch {
		case errors.Is(rerr, io.EOF):
			return n, true, nil
		case rerr != nil:
			return n, true, rerr
		}
		k, rerr = src.Read(buf)
	}
}

// Invalidate records a push to repo: it bumps the repository's generation
// so an in-flight refs fill is discarded at commit and a queued refs
// upload is skipped, records the push time so a remote refs entry
// created before it is not served, and deletes the repository's stored
// refs entries. With a remote tier it then deletes the remote refs
// entries before returning, within remoteBound and best effort: failures
// are logged, never returned.
func (c *Cache) Invalidate(ctx context.Context, repo gitproto.Repo, baseURL *url.URL) {
	repoHash := c.keyring.RepoHash(baseURL, repo)
	c.gens.bump(repoHash, c.now())
	n, err := c.store.DeletePrefix(RepoPrefix(GroupRefs, repoHash))
	if err != nil {
		c.logger.WarnContext(ctx, "invalidating refs entries after a push failed", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "error", err)
	} else {
		c.logger.DebugContext(ctx, "invalidated refs entries after a push", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
	}
	if c.remote != nil {
		c.invalidateRemote(repo, repoHash)
	}
}

// Purge deletes the entries of repo in group, or in both groups when
// group is empty, through PurgeRepository, and returns how many were
// removed from both tiers. With a remote tier the purge marker makes
// other replicas drop their older entries, and this process treats
// entries created before now as purged.
func (c *Cache) Purge(ctx context.Context, repo gitproto.Repo, baseURL *url.URL, group Group) (int, error) {
	groups, err := ParseGroups(string(group))
	if err != nil {
		return 0, err
	}
	now := c.now()
	if c.remote != nil {
		var times purgeTimes
		for _, g := range groups {
			times.set(g, now)
		}
		c.purges.observe(c.keyring.RepoHash(baseURL, repo), times, now)
	}
	res, err := PurgeRepository(ctx, c.keyring, PurgeRequest{
		Repo:        repo,
		BaseURL:     baseURL,
		Groups:      groups,
		Now:         now,
		Remote:      c.remote,
		DeleteLocal: c.store.DeletePrefix,
	})
	return res.Remote + res.Local, err
}

// Close stops the janitor, cancels every fill and waits for them, then
// flushes the upload queue and waits for background remote tasks, all
// until ctx ends; it then cancels any remote request still running and
// closes the store. Serve must not be called afterwards.
func (c *Cache) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.cancel()

	err := waitUntil(ctx, &c.wg, "fills still running")
	c.mu.Lock()
	c.remoteClosed = true
	if c.uploads != nil {
		close(c.uploads)
	}
	c.mu.Unlock()
	if err == nil {
		err = waitUntil(ctx, &c.remoteWG, "uploads still pending")
	}
	c.remoteCancel()
	return errors.Join(err, c.store.Close())
}

// waitUntil waits for wg until ctx ends, reporting what was still running
// when it did.
func waitUntil(ctx context.Context, wg *sync.WaitGroup, what string) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("cache: close: %s: %w", what, ctx.Err())
	}
}
