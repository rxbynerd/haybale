package policy

import (
	"fmt"
	"os"
	"path"

	"gopkg.in/yaml.v3"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
)

// policyFile is the top-level shape of policy.yaml.
type policyFile struct {
	Rules []Rule `yaml:"rules"`
}

// GlobEngine is the default-deny Engine implementation: an ordered list
// of Rules, matched first-match-wins. It is loaded once at startup (from
// LoadGlobEngine) and never mutated afterwards — safe for concurrent use
// without a lock.
type GlobEngine struct {
	rules []Rule
}

// NewGlobEngine builds a GlobEngine from rules, validating that every
// rule has at least one identity pattern, at least one repo pattern, at
// least one well-formed permission, and that every glob pattern is
// well-formed per path.Match — failing fast rather than deferring a
// malformed pattern to the first request that happens to test it. An
// empty rules slice is valid: it is a policy that denies everything,
// which is a legitimate (if unusual) configuration, not a mistake this
// constructor should reject.
func NewGlobEngine(rules []Rule) (*GlobEngine, error) {
	for i, r := range rules {
		if len(r.Identities) == 0 {
			return nil, fmt.Errorf("policy: rules[%d]: at least one identity pattern is required", i)
		}
		if len(r.Repos) == 0 {
			return nil, fmt.Errorf("policy: rules[%d]: at least one repo pattern is required", i)
		}
		if len(r.Permissions) == 0 {
			return nil, fmt.Errorf("policy: rules[%d]: at least one permission is required", i)
		}
		for _, p := range r.Permissions {
			if p != PermissionRead && p != PermissionWrite {
				return nil, fmt.Errorf("policy: rules[%d]: permission %q must be %q or %q", i, p, PermissionRead, PermissionWrite)
			}
		}
		for _, pattern := range r.Identities {
			if err := validatePattern(pattern); err != nil {
				return nil, fmt.Errorf("policy: rules[%d]: identity pattern %q: %w", i, pattern, err)
			}
		}
		for _, pattern := range r.Repos {
			if err := validatePattern(pattern); err != nil {
				return nil, fmt.Errorf("policy: rules[%d]: repo pattern %q: %w", i, pattern, err)
			}
		}
	}
	return &GlobEngine{rules: rules}, nil
}

// LoadGlobEngine reads and parses the policy.yaml file at policyPath,
// then validates it via NewGlobEngine.
func LoadGlobEngine(policyPath string) (*GlobEngine, error) {
	data, err := os.ReadFile(policyPath) //nolint:gosec // policyPath is the operator-supplied policy.yaml location from config, not attacker input
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", policyPath, err)
	}

	var f policyFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", policyPath, err)
	}

	engine, err := NewGlobEngine(f.Rules)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", policyPath, err)
	}
	return engine, nil
}

// Authorize implements Engine. It walks rules in order and returns the
// Decision for the first rule whose Identities and Repos patterns both
// match — Allowed reflecting whether that rule's Permissions grants the
// requested verb — or a default-deny Decision with a nil Rule if no
// rule's patterns matched at all.
func (e *GlobEngine) Authorize(id identity.Identity, repo gitproto.Repo, verb gitproto.Verb) Decision {
	key := repoKey(repo)
	for i := range e.rules {
		rule := &e.rules[i]
		if !matchesAny(rule.Identities, id.ID) {
			continue
		}
		if !matchesAny(rule.Repos, key) {
			continue
		}
		if rule.grants(verb) {
			return Decision{Allowed: true, Rule: rule, Reason: "matched rule grants " + string(permissionFor(verb))}
		}
		return Decision{Allowed: false, Rule: rule, Reason: "matched rule does not grant " + string(permissionFor(verb))}
	}
	return Decision{Allowed: false, Rule: nil, Reason: "no matching rule (default deny)"}
}

// permissionFor returns the Permission a given gitproto.Verb requires.
func permissionFor(v gitproto.Verb) Permission {
	if v == gitproto.Write {
		return PermissionWrite
	}
	return PermissionRead
}

// repoKey joins a gitproto.Repo into the single string glob patterns in
// policy.yaml match against: "{host}/{owner}/{repo}". See matchesAny for
// exactly how a pattern like "github.com/acme/*" matches this string.
func repoKey(repo gitproto.Repo) string {
	return repo.Host + "/" + repo.Owner + "/" + repo.Name
}

// matchesAny reports whether s matches any of patterns, using
// path.Match semantics for each.
//
// path.Match's "*" matches any sequence of non-"/" runes and never
// crosses a "/" boundary; "?" matches exactly one non-"/" rune; "[...]"
// character classes are supported exactly as path.Match defines them.
// Applied to a repo key "{host}/{owner}/{repo}" (three slash-separated
// segments, since gitproto.Repo's Owner and Name are always single path
// segments), this means:
//
//   - "github.com/acme/*" matches every repo under the acme owner on
//     github.com — the "*" matches exactly one segment (the repo name).
//   - "github.com/acme/widgets" matches only that one exact repo.
//   - "*/acme/*" matches the acme owner on any configured host.
//   - "github.com/*/*" matches any owner/repo under github.com.
//   - "*/*/*" or "**" matches every configured host/owner/repo (a "*"
//     and "**" are equivalent under path.Match — it has no special
//     double-star behaviour for crossing "/").
//   - A pattern with the wrong number of "/"-separated segments for
//     what it's compared against never matches: a two-segment pattern
//     like "acme/*" can never match a three-segment repo key, since a
//     bare "*" cannot expand across the segment boundary the missing
//     host component would require. This is a configuration mistake,
//     not a security hole — default-deny means an always-false rule
//     simply never grants anything, exactly as if it were absent.
//     Repo patterns must therefore always specify a host segment.
//
// Identity patterns (matched against a bare identity ID with no "/") are
// unaffected by any of the above — "run-*" matches "run-abc123" exactly
// as it would with simple prefix matching, since there is no "/" for
// "*" to avoid crossing.
//
// A malformed pattern (path.Match returns ErrBadPattern for it) is
// never reachable here: NewGlobEngine validates every pattern in a rule
// at load time, so any pattern reaching matchesAny is already known to
// be well-formed.
func matchesAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, s); err == nil && ok {
			return true
		}
	}
	return false
}

// validatePattern reports an error if pattern is not well-formed
// path.Match syntax — used at load time so a typo'd glob (e.g. an
// unclosed "[" character class) fails config validation instead of
// silently never matching at request time.
func validatePattern(pattern string) error {
	_, err := path.Match(pattern, "")
	return err
}
