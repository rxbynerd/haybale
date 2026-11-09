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

// PurgeRemote purges repo's entries in groups from the remote tier. It
// first records the purge at now in the repository's purge marker,
// keeping the times of groups not purged now, so that every replica
// sharing the tier treats local entries created before it as misses once
// it next refreshes the repository's access record. It then deletes the
// groups' remote objects and returns how many it deleted. A marker that
// fails verification is replaced.
func PurgeRemote(ctx context.Context, store BlobStore, kr Keyring, repo gitproto.Repo, baseURL *url.URL, groups []Group, now time.Time) (int, error) {
	repoHash := kr.RepoHash(baseURL, repo)
	times, _, err := readPurgeMarker(ctx, store, kr, repoHash, now)
	if err != nil && !errors.Is(err, ErrIntegrity) {
		return 0, fmt.Errorf("cache: read purge marker: %w", err)
	}
	for _, g := range groups {
		times.set(g, now)
	}
	marker, err := sealPurgeMarker(kr, repoHash, repo, baseURL, now, times)
	if err != nil {
		return 0, err
	}
	if err := store.Put(ctx, purgeMarkerPath(repoHash), bytes.NewReader(marker), int64(len(marker))); err != nil {
		return 0, fmt.Errorf("cache: write purge marker: %w", err)
	}
	deleted := 0
	for _, g := range groups {
		n, err := deleteRemotePrefix(ctx, store, RepoPrefix(g, repoHash))
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
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

// purgeRecords remembers, per repository, the purge times this process
// has seen in purge markers or made itself, and when reading a marker
// last failed.
type purgeRecords struct {
	retention time.Duration

	mu     sync.Mutex
	times  map[[32]byte]purgeTimes
	failed map[[32]byte]time.Time
}

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

// shouldCheck reports whether repoHash's marker may be read at now: not
// within purgeCheckBackoff of a failed read.
func (p *purgeRecords) shouldCheck(repoHash [32]byte, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.failed[repoHash]
	if !ok {
		return true
	}
	if now.Sub(t) >= purgeCheckBackoff {
		delete(p.failed, repoHash)
		return true
	}
	return false
}

// checkFailed records a failed marker read for repoHash at now.
func (p *purgeRecords) checkFailed(repoHash [32]byte, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed == nil {
		p.failed = make(map[[32]byte]time.Time)
	}
	if len(p.failed) >= pruneThreshold {
		for h, t := range p.failed {
			if now.Sub(t) >= purgeCheckBackoff {
				delete(p.failed, h)
			}
		}
	}
	p.failed[repoHash] = now
}
