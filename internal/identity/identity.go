// Package identity authenticates inbound git smart-HTTP requests to a
// caller Identity. In haybale's target deployment (Stirrup sandboxes)
// this Identity is the sandbox's per-run token, so a request's Identity
// is what internal/policy authorizes against — never the raw
// credential, which is discarded immediately after it is checked.
//
// This package is a v0.2 extraction seam: the Authenticator interface is
// deliberately narrow (context + request in, Identity out) so a future
// SPIFFE/mTLS or Cedar-backed implementation can replace
// StaticTokenAuthenticator without touching internal/proxy.
package identity

import (
	"context"
	"errors"
	"net/http"
)

// Identity identifies the authenticated caller of a proxied request. In
// Stirrup's deployment this is the sandbox's RunID.
type Identity struct {
	ID string
}

// Authenticator authenticates an inbound HTTP request, returning the
// caller's Identity or an error if the presented credential (however
// this implementation extracts it) is missing, malformed, or does not
// match a configured identity.
//
// Implementations must never log the raw credential they extract from r,
// and must compare it against stored material in constant time so
// response timing cannot leak how close a guessed credential is to a
// valid one.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

// ErrAuthenticationFailed is returned by Authenticate when the presented
// credential is missing, malformed, or does not match any configured
// identity. Callers — the proxy in particular — should map any non-nil
// Authenticate error to a 401 with a WWW-Authenticate challenge, never
// to a 404: authentication failure and authorization denial are
// distinct outcomes with distinct status codes.
var ErrAuthenticationFailed = errors.New("identity: authentication failed")
