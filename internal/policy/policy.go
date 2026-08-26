// Package policy authorizes an already-authenticated identity's request
// against a default-deny set of rules. It never grants access on its
// own: an identity with no matching rule — or one whose matching rule
// does not name the requested Permission — is denied, and the proxy
// maps every denial to the same 404 an unlisted or nonexistent repo
// would produce, so a caller probing repos it lacks access to cannot
// distinguish "exists but denied" from "does not exist" (no existence
// oracle).
package policy

import (
	"fmt"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
)

// Permission is a policy-grantable capability. The zero value is not a
// valid Permission — every Permission a Rule carries is validated
// against permissionRead/permissionWrite at load time.
type Permission string

const (
	// PermissionRead grants gitproto.Read (fetch/clone).
	PermissionRead Permission = "read"
	// PermissionWrite grants gitproto.Write (push), including the
	// info/refs?service=git-receive-pack handshake that precedes it.
	// PermissionWrite does NOT implicitly grant PermissionRead — a rule
	// that should cover both lists both permissions explicitly.
	PermissionWrite Permission = "write"
)

// Rule is one policy.yaml entry: an identity matching any of Identities
// (glob patterns) requesting a repo matching any of Repos (glob
// patterns) is granted every Permission listed, and nothing else. See
// matchesAny for exactly how these glob patterns are matched.
type Rule struct {
	Identities  []string     `yaml:"identities"`
	Repos       []string     `yaml:"repos"`
	Permissions []Permission `yaml:"permissions"`
}

// String renders r for audit logging: a policy_denied security event
// includes the matched rule (or its absence) so an operator can tell
// "no rule matched at all" apart from "a rule matched but didn't grant
// this verb" without ever needing to log request or credential
// material — a Rule is pure configuration, never a secret.
func (r Rule) String() string {
	return fmt.Sprintf("identities=%v repos=%v permissions=%v", r.Identities, r.Repos, r.Permissions)
}

// grants reports whether r's Permissions list includes the permission
// gitproto.Verb v requires.
func (r Rule) grants(v gitproto.Verb) bool {
	want := PermissionRead
	if v == gitproto.Write {
		want = PermissionWrite
	}
	for _, p := range r.Permissions {
		if p == want {
			return true
		}
	}
	return false
}

// Decision is the result of an authorization check. It carries enough
// context for audit logging — in particular the Rule that matched, if
// any — without ever including token or credential material, since a
// Rule is pure configuration.
type Decision struct {
	// Allowed is true only when a rule matched both the identity and
	// the repo and granted the requested verb's permission.
	Allowed bool
	// Rule is the first rule whose identity and repo patterns matched,
	// regardless of whether it granted the requested verb, or nil if no
	// rule's patterns matched at all (default deny). A non-nil Rule
	// with Allowed == false means "a rule matched but didn't grant this
	// verb" — distinct from "no rule matched" for audit purposes.
	Rule *Rule
	// Reason is a short human-readable explanation of the decision,
	// suitable for a security-event log line.
	Reason string
}

// Engine authorizes a (identity, repo, verb) triple against policy.
type Engine interface {
	Authorize(id identity.Identity, repo gitproto.Repo, verb gitproto.Verb) Decision
}
