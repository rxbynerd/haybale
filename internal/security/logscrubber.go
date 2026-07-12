package security

import "regexp"

// redactedPlaceholder replaces every matched secret span in Scrub.
const redactedPlaceholder = "[REDACTED]"

// namedPattern pairs a regexp with a stable name, mirroring Stirrup's
// harness/internal/security/logscrubber.go shape (name kept for
// documentation/test clarity even though, unlike Stirrup, haybale has no
// SecurityNotifier to report per-pattern redaction stats to).
type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns is the closed set of shapes Scrub redacts. Ported from
// Stirrup's harness/internal/security/logscrubber.go, trimmed to the
// credential shapes relevant to a git smart-HTTP proxy:
//
//   - HTTP auth headers (Basic/Bearer) — exactly the header
//     internal/proxy strips from the inbound request and injects on the
//     outbound one; a bug that ever logged a header value verbatim would
//     otherwise leak either the client's haybale token or the injected
//     upstream credential.
//   - a credential embedded in a URL's userinfo component — git remote
//     URLs commonly carry a token this way
//     (https://x-access-token:ghs_xxx@host/owner/repo.git), and neither
//     the Basic nor Bearer pattern above matches that shape.
//   - GitHub's own token prefixes (ghp_/gho_/ghu_/ghs_/ghr_ and the
//     github_pat_ fine-grained PAT shape) — what a real personal access
//     token, OAuth token, user-to-server token, GitHub App installation
//     token (ghs_, what M4's GitHubAppSource mints), or refresh token
//     looks like, in case one is ever echoed into an error string from a
//     dependency this package doesn't control.
//   - a PEM private key block — M4's github-app credential type carries
//     a privateKeyPath; if that key's contents were ever passed to a log
//     call by mistake, this is the last line of defense.
//
// This list is intentionally small and specific rather than a permissive
// high-entropy-string catch-all: haybale's own logging call sites are
// the primary defense (only repo/owner/host/verb/identity/status are
// ever passed as log attributes — see internal/proxy), and this
// scrubber is defense-in-depth for the case where that discipline slips.
var secretPatterns = []namedPattern{
	// url_userinfo must run before basic_auth_header/bearer_token_header:
	// a raw "https://x-access-token:ghs_xxx@github.com/..." URL contains
	// neither literal "Basic " nor "Bearer ", so only this pattern
	// catches a credential accidentally embedded in a logged URL.
	{"url_userinfo", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@]+@`)},
	{"basic_auth_header", regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/]+=*`)},
	{"bearer_token_header", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`)},
	// Covers every current GitHub token-prefix shape (classic PAT ghp_,
	// OAuth gho_, user-to-server ghu_, App installation ghs_, refresh
	// ghr_) plus the github_pat_ fine-grained PAT shape, which doesn't
	// share the ghX_ prefix pattern at all.
	{"github_token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]+\b|github_pat_[A-Za-z0-9_]+`)},
	{"pem_private_key", regexp.MustCompile(`-----BEGIN[\s\w]+KEY-----`)},
}

// Scrub replaces every known secret pattern in value with "[REDACTED]".
// It is safe to call on a value that contains no secret material at all
// (the common case) — it simply returns value unchanged.
func Scrub(value string) string {
	for _, p := range secretPatterns {
		value = p.re.ReplaceAllString(value, redactedPlaceholder)
	}
	return value
}
