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
)

// Log emits a structured security event on logger. Security events are
// logged at Warn level — they are exactly the log lines worth an
// operator's attention, so Warn (rather than Info) keeps them visible at
// haybale's default log level.
func Log(logger *slog.Logger, event string, args ...any) {
	logger.Warn("security event", append([]any{"event", event}, args...)...)
}
