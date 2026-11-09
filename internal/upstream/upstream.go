// Package upstream mints the credential haybale injects into the
// upstream leg of a proxied request: the "real" git-host credential that
// the client itself must never see or hold. internal/proxy's rewrite
// step strips the client's own (haybale) Authorization header and
// injects whatever CredentialSource.Credentials returns in its place —
// see internal/proxy's rewrite and modifyResponse.
//
// Implementations own credential caching. Callers must not cache a returned
// BasicAuth because only its CredentialSource knows when it expires.
package upstream

import (
	"context"
	"errors"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// ErrUnavailable is wrapped (with %w) by a CredentialSource only when a
// failure indicates the upstream credential API is unreachable or
// failing: a network or dial error, the source's own request timeout, or
// an HTTP 5xx response. Callers detect it with errors.Is.
//
// It is never wrapped for a response that indicates misconfiguration,
// revocation or rate limiting (401, 403, 404, 422, 429), for an
// unparseable response, or for the caller's own context ending. Those
// errors stay opaque so they are never mistaken for an outage.
var ErrUnavailable = errors.New("upstream: credential source unavailable")

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
// An error that wraps ErrUnavailable additionally tells the caller the
// credential API itself could not answer, as opposed to refusing to mint
// a credential; callers may test for it with errors.Is(err,
// ErrUnavailable). The proxy still maps both cases to 502. An
// implementation wraps ErrUnavailable only as ErrUnavailable's doc
// comment describes.
//
// Credentials must be safe to call concurrently from multiple
// goroutines: the proxy invokes it at most once per in-flight request,
// and not at all when a response is served from the response cache, with
// no external synchronization.
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
