// Package security provides structured security-event logging shared by
// haybale's identity, policy, and proxy layers. Every event name here is
// deliberately generic and carries no request-specific data of its own —
// callers supply the request/identity/repo context as slog attributes.
//
// Callers MUST NEVER pass a raw token, a token digest, or any other
// credential material as one of those attributes: security events are
// exactly the log lines an operator greps across a fleet, so a
// credential leaking into one would be an incident, not a bug report.
package security

import "log/slog"

const (
	// EventAuthnFailed is emitted when an Authenticator rejects a
	// request: a missing, malformed, or non-matching credential.
	EventAuthnFailed = "authn_failed"
	// EventPolicyDenied is emitted when a policy Engine denies a
	// request: either no rule matched (default deny) or the matched
	// rule does not grant the requested verb.
	EventPolicyDenied = "policy_denied"
	// EventUpstreamAuthFailed is emitted whenever a request fails
	// because haybale could not present a working upstream credential:
	// either a CredentialSource.Credentials call itself returned an
	// error (no credential to inject at all), or the upstream rejected
	// the credential haybale did inject (a 401/403 arriving after
	// rewrite() already set it). Both cases map the client-visible
	// response to 502, never 401 — the caller has no upstream
	// credential of its own to supply, so re-prompting it would only
	// hang the client.
	EventUpstreamAuthFailed = "upstream_auth_failed"
	// EventTokenMinted is emitted by a CredentialSource that actively
	// mints a short-lived credential (GitHubAppSource, M4) each time it
	// does so, for an audit trail of "when" without ever including the
	// minted token itself. StaticSource (M3) never mints — it returns a
	// fixed credential — so it never emits this event.
	EventTokenMinted = "token_minted"
)

// Log emits a structured security event on logger. Security events are
// logged at Warn level — they are exactly the log lines worth an
// operator's attention, so Warn (rather than Info) keeps them visible at
// haybale's default log level.
func Log(logger *slog.Logger, event string, args ...any) {
	logger.Warn("security event", append([]any{"event", event}, args...)...)
}
