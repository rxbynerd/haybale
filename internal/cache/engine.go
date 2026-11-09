package cache

import (
	"context"
	"encoding/hex"
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
)

const (
	// janitorInterval is how often the disk store sweeps expired entries
	// and orphaned temporary files.
	janitorInterval = time.Minute
	// maxCreatedAtSkew is how far in the future an entry's creation time
	// may lie before the entry is treated as corrupt.
	maxCreatedAtSkew = 5 * time.Minute
	// storeOperationOpen labels an entry that failed verification when it
	// was opened or read.
	storeOperationOpen = "open"
)

// errClientGone reports that the client stopped accepting the response.
var errClientGone = errors.New("cache: client stopped reading")

// Options configures a Cache.
type Options struct {
	// Dir is the cache directory; see OpenDiskStore for its requirements.
	Dir string
	// Keyring holds the key entries are sealed under and addressed by.
	Keyring Keyring
	// MaxDiskSize is the disk budget in bytes.
	MaxDiskSize int64
	// MaxEntrySize is the largest response body stored, in bytes.
	MaxEntrySize int64
	// MaxConcurrentFills bounds pack fills in flight, each of which may
	// reserve maxEntrySize; a request that finds no free slot bypasses
	// the cache. Refs fills are bounded separately by a fixed cap.
	MaxConcurrentFills int
	// MaxRequestBody bounds the decoded request body Classify inspects.
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
	// Remote is the remote tier. It must be nil in this release.
	Remote BlobStore
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
	store   *DiskStore
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

	idleGrace     time.Duration
	flushInterval time.Duration

	gens   generations
	access accessRecords
	marks  uncacheableMarks

	// mu orders fill attach, detach, start and teardown, so a request
	// never joins a fill that is ending.
	mu     sync.Mutex
	fills  map[Key]*fill
	closed bool
}

// New opens the cache directory, indexes its entries and starts the
// janitor. The returned Cache runs until Close.
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
	store, err := OpenDiskStore(opts.Dir, opts.MaxDiskSize, logger, metrics, now)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
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
		idleGrace:     fillIdleGrace,
		flushInterval: sealFlushInterval,
		access:        accessRecords{window: opts.AccessRecheck},
		fills:         make(map[Key]*fill),
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		store.RunJanitor(ctx, janitorInterval, opts.Retention)
	}()
	return c, nil
}

func validateOptions(opts Options) error {
	switch {
	case opts.Dir == "":
		return errors.New("cache: dir is required")
	case opts.Keyring.ActiveID() == "":
		return errors.New("cache: keyring has no active key")
	case opts.MaxDiskSize <= 0:
		return fmt.Errorf("cache: max disk size must be positive, got %d", opts.MaxDiskSize)
	case opts.MaxEntrySize <= 0 || opts.MaxEntrySize > opts.MaxDiskSize:
		return fmt.Errorf("cache: max entry size must be between 1 and the disk size, got %d", opts.MaxEntrySize)
	case opts.MaxConcurrentFills < 1:
		return fmt.Errorf("cache: max concurrent fills must be at least 1, got %d", opts.MaxConcurrentFills)
	case opts.MaxRequestBody <= 0:
		return fmt.Errorf("cache: max request body must be positive, got %d", opts.MaxRequestBody)
	case opts.Retention <= 0:
		return fmt.Errorf("cache: retention must be positive, got %v", opts.Retention)
	case opts.RefsMaxAge < 0 || opts.AccessRecheck < 0 || opts.ResponseHeaderTimeout < 0 || opts.IdleTimeout < 0:
		return errors.New("cache: durations must not be negative")
	case opts.Remote != nil:
		return errors.New("cache: the remote tier is not supported in this release")
	}
	return nil
}

// Serve handles a read that authentication and policy have already
// allowed. It returns handled=true when the response has been fully
// written. handled=false means the proxy must run its passthrough path:
// the request was not cacheable, the key is marked uncacheable, no fill
// slot was free, or the fill could not serve this request; r.Body then
// replays the bytes already read, and when the cache exposes its status
// the Cache-Status bypass header is already set on w. A subscriber whose
// response fails after bytes were written aborts the connection with
// panic(http.ErrAbortHandler).
func (c *Cache) Serve(w http.ResponseWriter, r *http.Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher) (Outcome, bool) {
	host := repo.Host
	req, bypass, reason, err := Classify(r, repo, c.opts.MaxRequestBody)
	if err != nil {
		c.logger.WarnContext(r.Context(), "cache: request could not be classified", "host", host, "error", err)
		return c.declined(w, host, observability.ResultBypass, "classify_error"), false
	}
	if bypass {
		return c.declined(w, host, observability.ResultBypass, reason), false
	}
	class := string(req.Class)
	key := Key{Group: req.Class.Group(), RepoHash: c.keyring.RepoHash(baseURL, repo), KeyHash: req.KeyHash}
	if c.marks.marked(key, c.now()) {
		return c.declined(w, host, class, "uncacheable"), false
	}

	entry := c.lookupEntry(key)
	// A second pass runs when a stored entry fails verification: the
	// entry has been deleted, so the request joins or starts a fill.
	for range 2 {
		if entry != nil {
			if out, ok := c.serveEntry(w, entry, key, host, class); ok {
				return out, true
			}
			entry = nil
		}
		var f *fill
		var collapsed, ok bool
		if key.Group == GroupRefs && c.opts.RefsMaxAge <= 0 {
			f, ok = c.startSingle(key, req, repo, baseURL, fetch)
		} else {
			f, entry, collapsed, ok = c.joinOrStart(key, req, repo, baseURL, fetch)
		}
		if !ok {
			return c.declined(w, host, class, "no_slot"), false
		}
		if entry != nil {
			continue
		}
		return c.subscribe(w, r, f, collapsed, host, class)
	}
	return c.declined(w, host, class, "verification"), false
}

// declined records a request the cache did not handle and prepares w for
// the passthrough path.
func (c *Cache) declined(w http.ResponseWriter, host, class, reason string) Outcome {
	c.metrics.RecordResponseCacheLookup(context.Background(), host, class, observability.ResultBypass)
	c.setCacheStatus(w.Header(), observability.ResultBypass, false)
	c.logger.Debug("cache: bypass", "host", host, "class", class, "reason", reason)
	return Outcome{Result: observability.ResultBypass}
}

// lookupEntry opens the stored entry for key if it may be served: it
// exists, is within retention, and satisfies the freshness rule of its
// group. An expired entry is deleted. The caller closes the entry.
func (c *Cache) lookupEntry(key Key) *Entry {
	if key.Group == GroupRefs && c.opts.RefsMaxAge <= 0 {
		return nil
	}
	entry, err := c.store.Open(key.Path())
	if err != nil {
		return nil
	}
	now := c.now()
	age := now.Sub(entry.ModTime())
	switch {
	case age > c.opts.Retention:
		_ = entry.Close()
		_ = c.store.Delete(key.Path())
		return nil
	case key.Group == GroupRefs && age > c.opts.RefsMaxAge,
		key.Group == GroupPack && !c.access.recent(key.RepoHash, now):
		_ = entry.Close()
		return nil
	}
	return entry
}

// serveEntry streams a stored entry to the client. ok is false when the
// entry failed verification before any byte was written; it has then been
// deleted and the caller treats the request as a miss.
func (c *Cache) serveEntry(w http.ResponseWriter, entry *Entry, key Key, host, class string) (Outcome, bool) {
	defer func() { _ = entry.Close() }()
	sr, err := NewSealedReader(entry, c.keyring)
	if err == nil && !headerMatches(sr.Header(), key, c.now()) {
		err = fmt.Errorf("%w: header does not match the entry path", ErrIntegrity)
	}
	if err != nil {
		c.dropCorrupt(key, err)
		return Outcome{}, false
	}
	n, started, err := c.stream(w, sr, sr.Header().ContentType, observability.ResultHit, false)
	switch {
	case errors.Is(err, errClientGone):
	case err != nil && !started:
		c.dropCorrupt(key, err)
		return Outcome{}, false
	case err != nil:
		c.logger.Warn("cache: entry failed mid-stream; aborting the response", "host", host, "class", class, "error", err)
		c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierDisk, storeOperationOpen)
		panic(http.ErrAbortHandler)
	}
	ctx := context.Background()
	c.metrics.RecordResponseCacheLookup(ctx, host, class, observability.ResultHit)
	c.metrics.RecordResponseCacheServedBytes(ctx, host, class, observability.TierDisk, n)
	return Outcome{Result: observability.ResultHit, Status: http.StatusOK, BytesOut: n}, true
}

// headerMatches reports whether a verified header belongs at key and
// carries a plausible creation time.
func headerMatches(h Header, key Key, now time.Time) bool {
	return h.Group == key.Group && h.RepoHash == key.RepoHash && h.KeyHash == key.KeyHash &&
		!h.CreatedAt.After(now.Add(maxCreatedAtSkew))
}

// dropCorrupt deletes an entry that failed verification.
func (c *Cache) dropCorrupt(key Key, err error) {
	c.metrics.RecordResponseCacheStoreError(context.Background(), observability.TierDisk, storeOperationOpen)
	c.logger.Warn("cache: entry failed verification; deleting it", "group", key.Group, "error", err)
	_ = c.store.Delete(key.Path())
}

// startSingle starts a fill that no other request can join, for a refs
// request while refsMaxAge is zero.
func (c *Cache) startSingle(key Key, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher) (*fill, bool) {
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
// new fill. ok is false when no fill slot is free or the cache is closed.
func (c *Cache) joinOrStart(key Key, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher) (f *fill, entry *Entry, collapsed, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, false, false
	}
	if f := c.fills[key]; f != nil && !f.ended {
		f.attachLocked()
		return f, nil, true, true
	}
	if entry := c.lookupEntry(key); entry != nil {
		return nil, entry, false, true
	}
	f = c.startFillLocked(key, req, repo, baseURL, fetch, true)
	return f, nil, false, f != nil
}

// startFillLocked takes a fill slot for the key's group and starts the
// fill goroutine with the caller as its first subscriber. It returns nil
// when no slot is free. Cache.mu must be held.
func (c *Cache) startFillLocked(key Key, req Request, repo gitproto.Repo, baseURL *url.URL, fetch Fetcher, shared bool) *fill {
	if !c.acquireSlotLocked(key.Group) {
		return nil
	}
	f := c.newFill(key, req, repo, baseURL, fetch, shared)
	f.subscribers = 1
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

// subscribe serves the request from fill f.
func (c *Cache) subscribe(w http.ResponseWriter, r *http.Request, f *fill, collapsed bool, host, class string) (Outcome, bool) {
	defer f.detach()
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
		h := w.Header()
		for k, vs := range out.header {
			h[k] = vs
		}
		c.setCacheStatus(h, observability.ResultMiss, collapsed)
		w.WriteHeader(out.status)
		n, _ := w.Write(out.body)
		c.metrics.RecordResponseCacheLookup(ctx, host, class, observability.ResultMiss)
		return Outcome{Result: observability.ResultMiss, Collapsed: collapsed, Status: out.status, BytesOut: int64(n)}, true
	}

	rd, err := f.spool.NewReader()
	if err != nil {
		// The fill ended before this subscriber could open the spool.
		return c.declined(w, host, class, "fill_ended"), false
	}
	defer func() { _ = rd.Close() }()
	sr, err := NewSealedReader(rd, c.keyring)
	if err != nil {
		return c.declined(w, host, class, "fill_ended"), false
	}
	n, started, err := c.stream(w, sr, out.contentType, observability.ResultMiss, collapsed)
	switch {
	case errors.Is(err, errClientGone):
		c.metrics.RecordResponseCacheLookup(ctx, host, class, observability.ResultMiss)
		return Outcome{Result: observability.ResultMiss, Collapsed: collapsed, Status: http.StatusOK, BytesOut: n}, true
	case err != nil && !started:
		return c.declined(w, host, class, "fill_failed"), false
	case err != nil:
		c.logger.Warn("cache: fill failed mid-stream; aborting the response", "host", host, "class", class, "error", err)
		panic(http.ErrAbortHandler)
	}
	c.metrics.RecordResponseCacheLookup(ctx, host, class, observability.ResultMiss)
	c.metrics.RecordResponseCacheServedBytes(ctx, host, class, observability.TierUpstream, n)
	// The spool reaches EOF only once the fill has committed or discarded
	// it, so the fill is about to finish and its result is known.
	<-f.done
	return Outcome{Result: observability.ResultMiss, Collapsed: collapsed, Stored: f.stored, Status: http.StatusOK, BytesOut: n}, true
}

// stream copies verified plaintext from src to w, flushing after every
// segment. The response headers are written before the first body byte,
// so a failure before any byte leaves w untouched and started false; a
// failure after that returns the error with started true. errClientGone
// reports that the client stopped accepting bytes.
func (c *Cache) stream(w http.ResponseWriter, src io.Reader, contentType, result string, collapsed bool) (n int64, started bool, err error) {
	buf := make([]byte, SegmentSize)
	k, rerr := src.Read(buf)
	if k == 0 && rerr != nil && !errors.Is(rerr, io.EOF) {
		return 0, false, rerr
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	c.setCacheStatus(h, result, collapsed)
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
// so an in-flight refs fill is discarded at commit, and deletes the
// repository's stored refs entries.
func (c *Cache) Invalidate(ctx context.Context, repo gitproto.Repo, baseURL *url.URL) {
	repoHash := c.keyring.RepoHash(baseURL, repo)
	c.gens.bump(repoHash)
	n, err := c.store.DeletePrefix(repoPrefix(GroupRefs, repoHash))
	if err != nil {
		c.logger.WarnContext(ctx, "cache: invalidating refs entries after a push failed", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "error", err)
		return
	}
	c.logger.DebugContext(ctx, "cache: invalidated refs entries after a push", "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "entries", n)
}

// Purge deletes the stored entries of repo in group, or in both groups
// when group is empty, and returns how many were removed.
func (c *Cache) Purge(_ context.Context, repo gitproto.Repo, baseURL *url.URL, group Group) (int, error) {
	var groups []Group
	switch group {
	case "":
		groups = []Group{GroupRefs, GroupPack}
	case GroupRefs, GroupPack:
		groups = []Group{group}
	default:
		return 0, fmt.Errorf("cache: unknown group %q", group)
	}
	repoHash := c.keyring.RepoHash(baseURL, repo)
	total := 0
	for _, g := range groups {
		n, err := c.store.DeletePrefix(repoPrefix(g, repoHash))
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// repoPrefix is the storage prefix of one repository's entries in group.
func repoPrefix(group Group, repoHash [32]byte) string {
	return "v1/" + string(group) + "/" + hex.EncodeToString(repoHash[:]) + "/"
}

// Close stops the janitor, cancels every fill and waits for them until
// ctx ends, then closes the store. Serve must not be called afterwards.
func (c *Cache) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.cancel()

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		err = fmt.Errorf("cache: close: fills still running: %w", ctx.Err())
	}
	return errors.Join(err, c.store.Close())
}
