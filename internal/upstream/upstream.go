// Package upstream mints the credential haybale injects into the
// upstream leg of a proxied request: the "real" git-host credential that
// the client itself must never see or hold. internal/proxy's rewrite
// step strips the client's own (haybale) Authorization header and
// injects whatever CredentialSource.Credentials returns in its place —
// see internal/proxy's rewrite and modifyResponse.
//
// CredentialSource is the v0.2/M4 extraction seam: StaticSource (M3)
// always returns the same fixed credential; GitHubAppSource (M4) will
// mint a short-lived GitHub App installation token per (repo, verb) and
// cache it internally (with singleflight, per the plan). Implementations
// own their own caching; callers — internal/proxy in particular — must
// never cache a returned BasicAuth themselves, since only the
// CredentialSource knows when its own value has gone stale.
package upstream

import (
	"context"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// BasicAuth is the HTTP Basic-auth credential a CredentialSource mints
// for the upstream leg of a proxied request. Password is the secret —
// it must never be logged, and it is never the credential the client
// itself presented to haybale (internal/identity already authenticated
// and discarded that one).
type BasicAuth struct {
	Username string
	Password string
}

// CredentialSource mints (or returns a fixed) upstream Basic-auth
// credential for a given repo/verb. Implementations may cache
// internally (e.g. by installation-token expiry); a caller must never
// cache the returned BasicAuth itself, since only the CredentialSource
// knows when its own value has gone stale.
//
// A non-nil error here must map to an HTTP 502 at the proxy layer —
// never a 401 — since the caller (an already-authenticated haybale
// client) has no upstream credential of its own to supply, and
// re-prompting it would only hang the client on a credential it cannot
// produce.
//
// Credentials must be safe to call concurrently from multiple
// goroutines: the proxy invokes it once per in-flight request with no
// external synchronization.
//
// Implementations are responsible for enforcing their own
// timeout/deadline on Credentials. The proxy passes the inbound
// request's context through unmodified and imposes no bound of its own —
// the server intentionally sets no read/write/idle timeout (to permit
// multi-gigabyte pack transfers), so an implementation that blocks
// unboundedly (e.g. a hung upstream API call) will hang the request
// indefinitely.
type CredentialSource interface {
	Credentials(ctx context.Context, repo gitproto.Repo, verb gitproto.Verb) (BasicAuth, error)
}
