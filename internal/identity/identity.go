// Package identity authenticates inbound git smart-HTTP requests to a
// caller Identity. In haybale's target deployment the control plane
// issues each workload a signed JWT identity, and haybale verifies it
// against the control plane's public keys (a JWKS URL) — so a request's
// Identity is derived from the token's verified claims, never from the
// raw credential, which is discarded immediately after it is checked.
//
// This package is a v0.2 extraction seam: the Authenticator interface is
// deliberately narrow (context + request in, Identity out) so a future
// SPIFFE/mTLS or Cedar-backed implementation can replace
// JWTAuthenticator without touching internal/proxy.
package identity

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Identity identifies the authenticated caller of a proxied request. It
// is derived from a verified JWT: ID is rendered from the token's claims
// (see JWTAuthenticator's identityTemplate), and the optional audit/
// authorization fields below carry verified assertions — never secret
// material — for the policy engine and security log.
type Identity struct {
	// ID is the authenticated caller's stable identifier, matched against
	// policy.yaml's identity globs. Rendered from verified claims by the
	// issuer's identityTemplate (e.g. "gha:{repository}" or "{sub}").
	ID string
	// Issuer is the verified `iss` claim of the token this Identity was
	// authenticated from, carried for audit logging. It is a value from
	// the operator's own configured, bounded issuer set (an unverified
	// `iss` never reaches here), so it is safe to log and to use as a
	// low-cardinality span/metric label.
	Issuer string
	// RepoScope, when non-nil, is the list of "{host}/{owner}/{repo}" glob
	// strings a per-issuer repoScopeClaim carried on the verified token.
	// It NARROWS authorization: internal/policy intersects it with the
	// YAML policy (effective = policy ∩ RepoScope), denying any repo the
	// scope does not also cover. A nil RepoScope means the token carried
	// no scope claim, so policy alone decides; a non-nil but empty
	// RepoScope denies every repo (the token asserted an empty scope).
	// A token can only ever narrow access this way, never widen it.
	RepoScope []string
}

// Authenticator authenticates an inbound HTTP request, returning the
// caller's Identity or an error if the presented credential (however
// this implementation extracts it) is missing, malformed, or does not
// verify against a configured identity.
//
// Implementations must never log the raw credential they extract from r.
// The comparison strategy is implementation-defined but must not leak a
// credential's validity through the timing of secret-dependent branches:
// a StaticTokenAuthenticator-style implementation would compare digests
// in constant time, whereas JWTAuthenticator's asymmetric-signature
// verification is not a secret comparison at all (the verifying key is
// public), so no constant-time discipline applies to it.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

// bearerPrefix is the scheme prefix extractCredential recognises on an
// Authorization header when no Basic-auth password is present.
const bearerPrefix = "Bearer "

// extractCredential pulls the presented credential out of r: the
// Basic-auth password if present (git's primary mechanism — the username
// is arbitrary and ignored, so a JWT is presented as the password of any
// username), otherwise the value of an `Authorization: Bearer <token>`
// header. It reports false if neither is present. Shared by every
// Authenticator implementation so they extract the caller's credential
// identically.
func extractCredential(r *http.Request) (string, bool) {
	if _, password, ok := r.BasicAuth(); ok {
		return password, true
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, bearerPrefix) {
		return strings.TrimPrefix(auth, bearerPrefix), true
	}
	return "", false
}

// ErrAuthenticationFailed is returned by Authenticate when the presented
// credential is missing, malformed, or does not match any configured
// identity. Callers — the proxy in particular — should map any non-nil
// Authenticate error to a 401 with a WWW-Authenticate challenge, never
// to a 404: authentication failure and authorization denial are
// distinct outcomes with distinct status codes.
var ErrAuthenticationFailed = errors.New("identity: authentication failed")
