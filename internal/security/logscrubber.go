package security

import "regexp"

// redactedPlaceholder replaces every matched secret span in Scrub.
const redactedPlaceholder = "[REDACTED]"

// namedPattern pairs a regexp with a stable name for tests and diagnostics.
type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns is the closed set of credential shapes Scrub redacts:
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
//   - a compact JWT (eyJ-prefixed, three dot-joined base64url segments).
//   - GitHub's own token prefixes (ghp_/gho_/ghu_/ghs_/ghr_ and the
//     github_pat_ fine-grained PAT shape) — what a real personal access
//     token, OAuth token, user-to-server token, GitHub App installation
//     token (ghs_), or refresh token looks like.
//   - a PEM private key block.
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
	// A compact JWT — three base64url segments joined by dots, with the
	// leading segment always starting "eyJ" (the base64url of `{"`, the
	// start of every JOSE header). It follows the auth-header patterns so
	// they redact a wrapped JWT first, while this catches a bare token.
	{"jwt_compact", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
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
