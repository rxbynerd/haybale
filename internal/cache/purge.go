package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/observability"
)

const (
	// groupPurge is the header group of a purge marker. It is never the
	// group of a cache entry.
	groupPurge Group = "purge"
	// purgeMarkerContentType is the header Content-Type of a purge marker.
	purgeMarkerContentType = "application/octet-stream"
	// purgeMarkerBodyLen is the marker body: the refs and then the pack
	// purge time, each as big-endian Unix nanoseconds, zero for never.
	purgeMarkerBodyLen = 16
	// maxPurgeMarkerSize bounds how much of a remote marker object is read.
	maxPurgeMarkerSize = 64 << 10
	// purgeMarkerTimeout bounds one read of a repository's purge marker.
	purgeMarkerTimeout = 30 * time.Second
	// purgeCheckBackoff is how long after a failed marker read the
	// repository's marker is not read again, so an unreachable remote tier
	// costs a refs fill its header timeout at most once per interval.
	purgeCheckBackoff = janitorInterval
)

// purgeMarkerPath returns "v1/purge/<repoHash hex>", the remote object that
// records when a repository was last purged.
func purgeMarkerPath(repoHash [32]byte) string {
	return layoutVersionDir + "/" + string(groupPurge) + "/" + hex.EncodeToString(repoHash[:])
}

// purgeTimes holds the last purge time of each group of one repository.
// A zero time means the group was never purged.
type purgeTimes struct {
	refs, pack time.Time
}

func (p purgeTimes) of(g Group) time.Time {
	if g == GroupRefs {
		return p.refs
	}
	return p.pack
}

func (p *purgeTimes) set(g Group, t time.Time) {
	if g == GroupRefs {
		p.refs = t
	} else {
		p.pack = t
	}
}

// covers reports whether an entry of group created at createdAt predates
// the group's last purge.
func (p purgeTimes) covers(g Group, createdAt time.Time) bool {
	t := p.of(g)
	return !t.IsZero() && createdAt.Before(t)
}

// merge returns the later time of each group from p and o, and whether
// any group advanced past p.
func (p purgeTimes) merge(o purgeTimes) (purgeTimes, bool) {
	advanced := false
	for _, g := range []Group{GroupRefs, GroupPack} {
		if o.of(g).After(p.of(g)) {
			p.set(g, o.of(g))
			advanced = true
		}
	}
	return p, advanced
}

// sealPurgeMarker seals a purge marker for repoHash created at at. The
// marker uses the entry format, so a bucket writer without the cache key
// can neither forge one nor move one to another repository.
func sealPurgeMarker(kr Keyring, repoHash [32]byte, repo gitproto.Repo, baseURL *url.URL, at time.Time, times purgeTimes) ([]byte, error) {
	var buf bytes.Buffer
	sw, err := newSealedWriter(&buf, kr, entryHeader{
		Group:       groupPurge,
		RepoHash:    repoHash,
		Repo:        repo.Host + "/" + repo.Owner + "/" + repo.Name,
		BaseURL:     baseURL.String(),
		CreatedAt:   at,
		ContentType: purgeMarkerContentType,
	})
	if err != nil {
		return nil, err
	}
	var body [purgeMarkerBodyLen]byte
	binary.BigEndian.PutUint64(body[:8], unixNanos(times.refs))
	binary.BigEndian.PutUint64(body[8:], unixNanos(times.pack))
	if _, err := sw.Write(body[:]); err != nil {
		return nil, err
	}
	if err := sw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// openPurgeMarker verifies a sealed purge marker for repoHash and returns
// the purge times it records. Anything else is ErrIntegrity.
func openPurgeMarker(data []byte, kr Keyring, repoHash [32]byte, now time.Time) (purgeTimes, error) {
	sr, err := newSealedReader(bytes.NewReader(data), kr)
	if err != nil {
		return purgeTimes{}, err
	}
	h := sr.Header()
	switch {
	case h.Group != groupPurge || h.RepoHash != repoHash || h.KeyHash != [32]byte{}:
		return purgeTimes{}, fmt.Errorf("%w: purge marker does not match its path", ErrIntegrity)
	case h.CreatedAt.After(now.Add(maxCreatedAtSkew)):
		return purgeTimes{}, fmt.Errorf("%w: purge marker creation time is in the future", ErrIntegrity)
	}
	body, err := io.ReadAll(io.LimitReader(sr, purgeMarkerBodyLen+1))
	if err != nil {
		return purgeTimes{}, truncated(err, "purge marker")
	}
	if len(body) != purgeMarkerBodyLen {
		return purgeTimes{}, fmt.Errorf("%w: purge marker body is %d bytes", ErrIntegrity, len(body))
	}
	times := purgeTimes{refs: fromUnixNanos(body[:8]), pack: fromUnixNanos(body[8:])}
	if times.refs.After(h.CreatedAt) || times.pack.After(h.CreatedAt) {
		return purgeTimes{}, fmt.Errorf("%w: purge time is after the marker's creation", ErrIntegrity)
	}
	return times, nil
}

func unixNanos(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UnixNano()) //nolint:gosec // purge times are after 1970
}

func fromUnixNanos(b []byte) time.Time {
	n := binary.BigEndian.Uint64(b)
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(n)).UTC() //nolint:gosec // inverse of unixNanos
}

// readPurgeMarker reads and verifies repoHash's purge marker from store.
// found is false when there is none.
func readPurgeMarker(ctx context.Context, store BlobStore, kr Keyring, repoHash [32]byte, now time.Time) (times purgeTimes, found bool, err error) {
	rc, _, err := store.Get(ctx, purgeMarkerPath(repoHash), 0)
	if errors.Is(err, ErrNotFound) {
		return purgeTimes{}, false, nil
	}
	if err != nil {
		return purgeTimes{}, false, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxPurgeMarkerSize+1))
	if err != nil {
		return purgeTimes{}, false, err
	}
	if len(data) > maxPurgeMarkerSize {
		return purgeTimes{}, false, fmt.Errorf("%w: purge marker exceeds %d bytes", ErrIntegrity, maxPurgeMarkerSize)
	}
	times, err = openPurgeMarker(data, kr, repoHash, now)
	return times, err == nil, err
}

// PurgeStep names one step of PurgeRepository.
type PurgeStep uint8

const (
	// PurgeStepMarker writes the repository's purge marker.
	PurgeStepMarker PurgeStep = iota + 1
	// PurgeStepRemote deletes the repository's remote entries.
	PurgeStepRemote
	// PurgeStepLocal deletes the repository's local entries.
	PurgeStepLocal
)

// PurgeRequest describes the purge of one repository's entries.
type PurgeRequest struct {
	Repo    gitproto.Repo
	BaseURL *url.URL
	// Groups are the groups purged; see ParseGroups.
	Groups []Group
	// Now is the purge time the marker records.
	Now time.Time
	// Remote is the remote tier, nil for a local-only purge.
	Remote BlobStore
	// DeleteLocal deletes the local entries under one repository prefix
	// and returns how many it removed; nil skips the local tier.
	DeleteLocal func(prefix string) (int, error)
	// StepDone, when set, is called as each step succeeds, with the result
	// so far.
	StepDone func(PurgeStep, PurgeResult)
}

// PurgeResult counts what PurgeRepository did.
type PurgeResult struct {
	// MarkerReplaced reports that the repository's existing purge marker
	// failed verification and was replaced.
	MarkerReplaced bool
	// Remote and Local count the entries deleted from each tier.
	Remote, Local int
}

// PurgeError is a failed step of PurgeRepository. Group is the group
// being deleted when a remote or local step failed.
type PurgeError struct {
	Step  PurgeStep
	Group Group
	Err   error
}

func (e *PurgeError) Error() string { return e.Err.Error() }

func (e *PurgeError) Unwrap() error { return e.Err }

// PurgeRepository purges a repository's entries in req.Groups: it writes
// the purge marker and deletes the remote entries when there is a remote
// tier, then deletes the local entries. A marker that cannot be written
// ends the purge before any deletion; a failed remote deletion still lets
// the local step run. Failures are *PurgeError values; reruns are safe.
func PurgeRepository(ctx context.Context, kr Keyring, req PurgeRequest) (PurgeResult, error) {
	var res PurgeResult
	done := func(step PurgeStep) {
		if req.StepDone != nil {
			req.StepDone(step, res)
		}
	}
	repoHash := kr.RepoHash(req.BaseURL, req.Repo)
	var remoteErr, localErr error
	if req.Remote != nil {
		replaced, err := writePurgeMarker(ctx, req.Remote, kr, req.Repo, req.BaseURL, req.Groups, req.Now)
		if err != nil {
			return res, &PurgeError{Step: PurgeStepMarker, Err: err}
		}
		res.MarkerReplaced = replaced
		done(PurgeStepMarker)
		for _, g := range req.Groups {
			n, err := deleteRemotePrefix(ctx, req.Remote, RepoPrefix(g, repoHash))
			res.Remote += n
			if err != nil {
				remoteErr = &PurgeError{Step: PurgeStepRemote, Group: g, Err: err}
				break
			}
		}
		if remoteErr == nil {
			done(PurgeStepRemote)
		}
	}
	if req.DeleteLocal != nil {
		for _, g := range req.Groups {
			n, err := req.DeleteLocal(RepoPrefix(g, repoHash))
			res.Local += n
			if err != nil {
				localErr = &PurgeError{Step: PurgeStepLocal, Group: g, Err: err}
				break
			}
		}
		if localErr == nil {
			done(PurgeStepLocal)
		}
	}
	return res, errors.Join(remoteErr, localErr)
}

// writePurgeMarker records a purge of groups at now in the repository's
// purge marker, keeping the times of groups not purged now. The marker's
// creation time is the latest of now and every kept time, so a kept time
// from a host whose clock ran ahead still verifies. A marker that fails
// verification is replaced, and replaced reports it.
func writePurgeMarker(ctx context.Context, store BlobStore, kr Keyring, repo gitproto.Repo, baseURL *url.URL, groups []Group, now time.Time) (replaced bool, err error) {
	repoHash := kr.RepoHash(baseURL, repo)
	times, _, err := readPurgeMarker(ctx, store, kr, repoHash, now)
	switch {
	case errors.Is(err, ErrIntegrity):
		replaced = true
	case err != nil:
		return false, fmt.Errorf("cache: read purge marker: %w", err)
	}
	createdAt := now
	for _, t := range []time.Time{times.refs, times.pack} {
		if t.After(createdAt) {
			createdAt = t
		}
	}
	for _, g := range groups {
		times.set(g, now)
	}
	marker, err := sealPurgeMarker(kr, repoHash, repo, baseURL, createdAt, times)
	if err != nil {
		return false, err
	}
	if err := store.Put(ctx, purgeMarkerPath(repoHash), bytes.NewReader(marker), int64(len(marker))); err != nil {
		return false, fmt.Errorf("cache: write purge marker: %w", err)
	}
	return replaced, nil
}

// deleteRemotePrefix deletes every entry object under prefix and returns
// how many it deleted. Keys that are not entry paths under prefix are
// left alone. It stops at the first error, which is a *remoteOpError.
func deleteRemotePrefix(ctx context.Context, store BlobStore, prefix string) (int, error) {
	n := 0
	for info, err := range store.List(ctx, prefix) {
		if err != nil {
			return n, &remoteOpError{op: observability.OperationList, err: err}
		}
		if !strings.HasPrefix(info.Key, prefix) || !validEntryPath(info.Key) {
			continue
		}
		if err := store.Delete(ctx, info.Key); err != nil {
			return n, &remoteOpError{op: observability.OperationDelete, err: err}
		}
		n++
	}
	return n, nil
}

// remoteOpError is a remote-tier failure labelled with the operation that
// failed, one of the observability Operation values.
type remoteOpError struct {
	op  string
	err error
}

func (e *remoteOpError) Error() string { return e.err.Error() }

func (e *remoteOpError) Unwrap() error { return e.err }

// markerCheckInterval is how long a successful purge marker check stays
// current: janitorInterval, or accessRecheck when that is shorter, so the
// marker is read at least as often as a pack hit needs the access record
// renewed.
func markerCheckInterval(accessRecheck time.Duration) time.Duration {
	if accessRecheck > 0 && accessRecheck < janitorInterval {
		return accessRecheck
	}
	return janitorInterval
}

// purgeRecords remembers, per repository, the purge times this process
// has seen in purge markers or made itself, when a marker check last
// succeeded or failed, and the check in flight.
type purgeRecords struct {
	retention time.Duration
	// interval is how long a successful check stays current.
	interval time.Duration

	mu       sync.Mutex
	times    map[[32]byte]purgeTimes
	checked  map[[32]byte]time.Time
	failed   map[[32]byte]time.Time
	inflight map[[32]byte]*markerCheck
}

// markerCheck is one purge marker read that concurrent refs fills of a
// repository share. current is valid once done is closed.
type markerCheck struct {
	done    chan struct{}
	current bool
}

// checkStart says what a refs fill does about the repository's marker.
type checkStart uint8

const (
	// checkCurrent: a check succeeded within the interval.
	checkCurrent checkStart = iota + 1
	// checkBackoff: a check failed within purgeCheckBackoff.
	checkBackoff
	// checkJoin: another fill's check is in flight; wait for it.
	checkJoin
	// checkLead: this fill reads the marker and must call finishCheck.
	checkLead
)

// covers reports whether an entry at key created at createdAt predates a
// known purge of its repository and group.
func (p *purgeRecords) covers(key entryKey, createdAt time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.times[key.RepoHash].covers(key.Group, createdAt)
}

// observe merges times into repoHash's record and returns the merged
// times and whether any group advanced.
func (p *purgeRecords) observe(repoHash [32]byte, times purgeTimes, now time.Time) (purgeTimes, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.times == nil {
		p.times = make(map[[32]byte]purgeTimes)
	}
	if len(p.times) >= pruneThreshold {
		for h, t := range p.times {
			if now.Sub(t.refs) > p.retention && now.Sub(t.pack) > p.retention {
				delete(p.times, h)
			}
		}
	}
	merged, advanced := p.times[repoHash].merge(times)
	if advanced {
		p.times[repoHash] = merged
	}
	return merged, advanced
}

// beginCheck decides how a refs fill at now learns whether repoHash's
// purge state is current. For checkJoin and checkLead it returns the
// shared check.
func (p *purgeRecords) beginCheck(repoHash [32]byte, now time.Time) (checkStart, *markerCheck) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.checked[repoHash]; ok && now.Sub(t) < p.interval {
		return checkCurrent, nil
	}
	if t, ok := p.failed[repoHash]; ok {
		if now.Sub(t) < purgeCheckBackoff {
			return checkBackoff, nil
		}
		delete(p.failed, repoHash)
	}
	if mc := p.inflight[repoHash]; mc != nil {
		return checkJoin, mc
	}
	if p.inflight == nil {
		p.inflight = make(map[[32]byte]*markerCheck)
	}
	mc := &markerCheck{done: make(chan struct{})}
	p.inflight[repoHash] = mc
	return checkLead, mc
}

// finishCheck ends the shared check mc for repoHash at now: a current
// result is remembered for the interval, and failed starts the backoff.
// A check that is neither, cut short by the cache closing, records
// nothing.
func (p *purgeRecords) finishCheck(repoHash [32]byte, mc *markerCheck, current, failed bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[repoHash] == mc {
		delete(p.inflight, repoHash)
	}
	switch {
	case current:
		p.checked = remember(p.checked, repoHash, now, p.interval)
	case failed:
		delete(p.checked, repoHash)
		p.failed = remember(p.failed, repoHash, now, purgeCheckBackoff)
	}
	mc.current = current
	close(mc.done)
}

// remember sets m[repoHash] to now, first pruning entries older than keep
// once the map is large. It returns the map, made if nil.
func remember(m map[[32]byte]time.Time, repoHash [32]byte, now time.Time, keep time.Duration) map[[32]byte]time.Time {
	if m == nil {
		m = make(map[[32]byte]time.Time)
	}
	if len(m) >= pruneThreshold {
		for h, t := range m {
			if now.Sub(t) >= keep {
				delete(m, h)
			}
		}
	}
	m[repoHash] = now
	return m
}
