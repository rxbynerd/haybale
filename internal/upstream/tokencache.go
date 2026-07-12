package upstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// earlyRefreshWindow is how long before a minted token's actual expiry
// tokenCache starts treating it as needing refresh. GitHub installation
// tokens are valid for about an hour; refreshing 5 minutes early means an
// in-flight clone or push that grabs a token right before expiry never
// gets handed one that goes stale mid-transfer.
const earlyRefreshWindow = 5 * time.Minute

// mintFunc mints a fresh upstream credential for repo/verb, returning
// the credential and its actual (not early-refresh-adjusted) expiry.
// GitHubAppSource.mint is the only production implementation; tests
// supply fakes.
type mintFunc func(ctx context.Context, repo gitproto.Repo, verb gitproto.Verb) (BasicAuth, time.Time, error)

// repoKey identifies the (host, owner, repo) a cached token was minted
// for. Verb is deliberately not part of this key — tokenCache keeps a
// separate read/write map instead (see cachedToken maps below) so
// write-satisfies-read can check the write entry without also needing to
// know a read entry's key shape matches.
type repoKey struct {
	host, owner, repo string
}

// cachedToken is one minted credential plus the actual upstream expiry
// it was minted with.
type cachedToken struct {
	cred      BasicAuth
	expiresAt time.Time
}

// needsRefresh reports whether t should be treated as stale at now: past
// its actual expiry, or within earlyRefreshWindow of it.
func (t cachedToken) needsRefresh(now time.Time) bool {
	return !now.Before(t.expiresAt.Add(-earlyRefreshWindow))
}

// tokenCache caches minted upstream credentials keyed by (host, owner,
// repo, verb), internal to GitHubAppSource. Callers of CredentialSource
// must never cache the returned BasicAuth themselves (see the
// CredentialSource doc comment) — this is the one place that does.
//
// Semantics:
//   - a cached credential is reused until it needs refresh (see
//     cachedToken.needsRefresh / earlyRefreshWindow above);
//   - write-satisfies-read: a valid cached WRITE credential also
//     satisfies a READ request (checked first, before the read cache),
//     since a write-scoped token is always sufficient for a read. A
//     cached READ credential never satisfies a WRITE request;
//   - concurrent Get calls for the same (host, owner, repo, verb)
//     collapse into a single mint call via singleflight; each waiting
//     caller still honors its own ctx (see get's doc comment) rather than
//     blocking on whichever caller's call actually ends up in flight.
//
// now is an injected clock (defaulting to time.Now in production) so
// tests can exercise expiry and the early-refresh boundary
// deterministically with a fake clock. tokenCache is safe for concurrent
// use.
type tokenCache struct {
	now func() time.Time

	mu    sync.Mutex
	read  map[repoKey]cachedToken
	write map[repoKey]cachedToken

	group singleflight.Group
}

// newTokenCache builds an empty tokenCache using now as its clock.
func newTokenCache(now func() time.Time) *tokenCache {
	return &tokenCache{
		now:   now,
		read:  make(map[repoKey]cachedToken),
		write: make(map[repoKey]cachedToken),
	}
}

// get returns a cached credential for repo/verb if one is present and
// not due for refresh, otherwise it mints a fresh one via mint (a single
// call, shared across any concurrent Get for the same key) and caches
// the result before returning it.
//
// A concurrent caller that arrives while a mint for the same key is
// already in flight ("follower") uses singleflight.Group.DoChan and
// selects on the shared result versus its OWN ctx.Done, so it honors its
// own deadline/cancellation instead of blocking on the in-flight call's
// ctx (Group.Do's follower path has no reference to a follower's ctx at
// all). Giving up does not cancel the in-flight mint itself — it keeps
// running to completion for whoever else is still waiting on it — this
// only fixes "a follower honors its own deadline," which is the
// documented CredentialSource contract.
func (c *tokenCache) get(ctx context.Context, repo gitproto.Repo, verb gitproto.Verb, mint mintFunc) (BasicAuth, error) {
	key := repoKey{host: repo.Host, owner: repo.Owner, repo: repo.Name}
	now := c.now()

	if cred, ok := c.lookup(key, verb, now); ok {
		return cred, nil
	}

	// The singleflight key must include verb: a concurrent read and
	// write for the same repo mint different scopes and must not
	// collapse into each other's result, only requests sharing the exact
	// same (key, verb) do.
	sfKey := fmt.Sprintf("%s/%s/%s/%s", key.host, key.owner, key.repo, verb.String())
	ch := c.group.DoChan(sfKey, func() (any, error) {
		cred, expiresAt, mintErr := mint(ctx, repo, verb)
		if mintErr != nil {
			return BasicAuth{}, mintErr
		}
		c.store(key, verb, cachedToken{cred: cred, expiresAt: expiresAt})
		return cred, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return BasicAuth{}, res.Err
		}
		// The closure above only ever returns (BasicAuth, nil) on its
		// success path, so this type assertion cannot fail for any
		// res.Err == nil result DoChan hands back — including to a
		// follower that shared the leader's call.
		return res.Val.(BasicAuth), nil
	case <-ctx.Done():
		return BasicAuth{}, ctx.Err()
	}
}

// lookup checks for a still-valid cached credential for key/verb,
// write-satisfies-read (see tokenCache's doc comment) applied before
// falling back to the read cache.
func (c *tokenCache) lookup(key repoKey, verb gitproto.Verb, now time.Time) (BasicAuth, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if wt, ok := c.write[key]; ok && !wt.needsRefresh(now) {
		return wt.cred, true
	}
	if verb == gitproto.Write {
		// A write request is never satisfied by a read-scoped token,
		// regardless of what's in the read cache.
		return BasicAuth{}, false
	}
	if rt, ok := c.read[key]; ok && !rt.needsRefresh(now) {
		return rt.cred, true
	}
	return BasicAuth{}, false
}

// store records a freshly minted credential in the read or write map
// according to verb.
func (c *tokenCache) store(key repoKey, verb gitproto.Verb, tok cachedToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if verb == gitproto.Write {
		c.write[key] = tok
	} else {
		c.read[key] = tok
	}
}
