package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// maxTokenBytes caps the size of a presented credential before it is ever
// handed to the JWT parser. A compact JWT that clears verification is a
// few hundred bytes to a couple of kilobytes; 64 KiB is far above any
// legitimate token yet small enough that an attacker cannot make haybale
// spend unbounded work parsing (or splitting into segments — the class of
// issue golang-jwt CVE-2025-30204 covered) a giant, never-valid blob. A
// credential larger than this is rejected as an authentication failure
// without the parser being invoked at all.
const maxTokenBytes = 64 * 1024

// IssuerConfig is one trusted issuer's fully-resolved verification
// parameters, as internal/config hands them to NewJWTAuthenticator. It is
// this package's own type (not the YAML struct) so internal/identity
// stays free of any dependency on internal/config — config maps its
// validated YAML onto this shape.
type IssuerConfig struct {
	// Issuer is the exact string a token's `iss` claim must equal. It both
	// selects this issuer's trust material (via the token's unverified
	// `iss`) and is re-checked against the verified claims.
	Issuer string
	// JWKSURL and JWKSFile are the two mutually-exclusive JWKS sources;
	// exactly one is non-empty (config.Validate guarantees this). JWKSURL
	// is fetched and refreshed in the background; JWKSFile is read once at
	// startup.
	JWKSURL  string
	JWKSFile string
	// Algorithms is the signing-algorithm allowlist (e.g. ["RS256",
	// "ES256"]). Only asymmetric algorithms are ever configured here; a
	// token whose `alg` header is outside this list — including `none` and
	// every HMAC variant — is rejected before its signature is checked,
	// which is what defeats algorithm-confusion attacks (D2).
	Algorithms []string
	// Audiences is the set of acceptable `aud` values; a token must carry
	// at least one of them. A token with no `aud`, or an `aud` disjoint
	// from this set, is rejected.
	Audiences []string
	// Leeway is the clock-skew tolerance applied to exp/nbf/iat checks.
	Leeway time.Duration
	// Typ, when non-empty, is the JOSE `typ` header the token must carry
	// (compared case-insensitively, per RFC 8725 §3.11). Empty disables
	// the check.
	Typ string
	// ClaimBindings maps a claim name to the set of glob patterns its
	// string value must match at least one of. Every binding must pass or
	// authentication fails — this is what pins an otherwise-permissive
	// issuer (e.g. GitHub Actions, where any workflow can mint a token) to
	// the specific callers an operator intends to trust.
	ClaimBindings map[string][]string
	// IdentityTemplate renders Identity.ID from verified claims, e.g.
	// "gha:{repository}" or "{sub}". Referenced claims must be present and
	// string-typed or authentication fails.
	IdentityTemplate string
	// RepoScopeClaim, when non-empty, names a claim carrying a list of
	// "{host}/{owner}/{repo}" glob strings that NARROW authorization (see
	// Identity.RepoScope). Absent on a token means no narrowing.
	RepoScopeClaim string
}

// issuerVerifier is the compiled, per-request-reusable form of one
// IssuerConfig: its key source, a prebuilt parser carrying the issuer's
// algorithm allowlist / audience / issuer / expiry rules, and the
// compiled claim-binding, identity-template, and repo-scope logic.
type issuerVerifier struct {
	issuer         string
	keys           keySource
	parser         *jwt.Parser
	typ            string
	claimBindings  map[string][]string
	identity       []templateSegment
	repoScopeClaim string
}

// JWTAuthenticator authenticates requests bearing a control-plane-issued
// JWT. It holds one issuerVerifier per configured issuer, keyed by the
// exact `iss` string, and never tries a token against any issuer other
// than the one its unverified `iss` names — so trust material, the
// algorithm allowlist, and the audience expectation are all bound to a
// single issuer, and a token signed by issuer B's key while claiming
// issuer A's `iss` fails against A's key set (D2).
//
// It is immutable after New returns (its maps and verifiers are only
// read, never written, once serving) and so is safe for concurrent use.
type JWTAuthenticator struct {
	byIssuer map[string]*issuerVerifier
	logger   *slog.Logger
}

// NewJWTAuthenticator compiles issuers into a JWTAuthenticator, building
// each issuer's key source: a URL-backed source (with a background
// refresh goroutine bound to ctx) for an issuer with a JWKSURL, or a
// file-backed source for one with a JWKSFile. The initial JWKS fetch is
// synchronous and fail-fast (see newURLKeySource), so an unreachable or
// empty JWKS at startup returns an error here rather than a deferred
// per-request failure. logger receives background-refresh warnings and
// debug-level authentication traces; a nil logger falls back to
// slog.Default().
//
// ctx governs the lifetime of every URL-backed issuer's refresh
// goroutine: cancelling it (on server shutdown) stops them. It must
// therefore be a long-lived context (the server's), not a per-request
// one.
func NewJWTAuthenticator(ctx context.Context, issuers []IssuerConfig, logger *slog.Logger) (*JWTAuthenticator, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(issuers) == 0 {
		return nil, fmt.Errorf("identity: jwt authenticator requires at least one issuer")
	}
	byIssuer := make(map[string]*issuerVerifier, len(issuers))
	for _, ic := range issuers {
		if ic.Issuer == "" {
			return nil, fmt.Errorf("identity: issuer string must not be empty")
		}
		if _, dup := byIssuer[ic.Issuer]; dup {
			return nil, fmt.Errorf("identity: duplicate issuer %q", ic.Issuer)
		}
		// Reject an empty algorithm allowlist at construction, not just in
		// config: golang-jwt's WithValidMethods only enforces the allowlist
		// when the slice is NON-NIL (parser.go: `if p.validMethods != nil`),
		// so a nil Algorithms would silently disable algorithm checking
		// entirely — admitting alg:none and every HMAC variant, the exact
		// algorithm-confusion attack this verifier exists to defeat. The
		// production config path always defaults Algorithms to
		// [RS256, ES256] before reaching here, but this constructor is
		// public and must not leave that landmine for a direct caller.
		if len(ic.Algorithms) == 0 {
			return nil, fmt.Errorf("identity: issuer %q: at least one signing algorithm is required", ic.Issuer)
		}

		var keys keySource
		var err error
		switch {
		case ic.JWKSURL != "":
			keys, err = newURLKeySource(ctx, ic.JWKSURL, logger)
		case ic.JWKSFile != "":
			keys, err = newFileKeySource(ic.JWKSFile)
		default:
			err = errNoKeySource
		}
		if err != nil {
			return nil, fmt.Errorf("identity: issuer %q: %w", ic.Issuer, err)
		}

		segments, err := parseTemplate(ic.IdentityTemplate)
		if err != nil {
			return nil, fmt.Errorf("identity: issuer %q: identityTemplate: %w", ic.Issuer, err)
		}

		// WithValidMethods enforces the algorithm allowlist before the
		// signature (and so before the keyfunc) is ever consulted;
		// WithExpirationRequired rejects a token with no exp; WithIssuer
		// re-checks the verified `iss` equals the one that selected this
		// verifier; WithAudience requires at least one configured audience
		// to be present; WithIssuedAt rejects an iat in the future.
		parser := jwt.NewParser(
			jwt.WithValidMethods(ic.Algorithms),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(ic.Leeway),
			jwt.WithIssuer(ic.Issuer),
			jwt.WithAudience(ic.Audiences...),
			jwt.WithIssuedAt(),
		)

		byIssuer[ic.Issuer] = &issuerVerifier{
			issuer:         ic.Issuer,
			keys:           keys,
			parser:         parser,
			typ:            ic.Typ,
			claimBindings:  ic.ClaimBindings,
			identity:       segments,
			repoScopeClaim: ic.RepoScopeClaim,
		}
	}
	return &JWTAuthenticator{byIssuer: byIssuer, logger: logger}, nil
}

// Authenticate implements Authenticator. It extracts the presented JWT
// (Basic-auth password or Bearer header), routes it to the verifier its
// unverified `iss` names, runs full RFC 8725 verification against only
// that issuer's trust material, evaluates the issuer's claim bindings,
// renders the identity, and extracts any repo-scope claim.
//
// Every failure — a missing credential, an oversized blob, an unknown
// issuer, a bad signature, an expired token, a claim-binding miss, a
// template referencing an absent claim — returns the same
// ErrAuthenticationFailed with no claim-specific detail, so a caller
// cannot use the error to distinguish why a token was rejected. The
// specific reason is logged server-side at Debug level (never the raw
// token, and only fixed reason strings, never attacker-controlled claim
// values) for operator troubleshooting.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	raw, ok := extractCredential(r)
	if !ok || raw == "" {
		return a.fail("no credential presented")
	}
	if len(raw) > maxTokenBytes {
		return a.fail("credential exceeds maximum token size")
	}

	// Read the unverified `iss` (and `typ` header) purely to SELECT the
	// verifier. Nothing here is trusted: the token is not verified until
	// the full parse below runs against the selected issuer's keys.
	unverifiedClaims := jwt.MapClaims{}
	unverifiedTok, _, err := jwt.NewParser().ParseUnverified(raw, unverifiedClaims)
	if err != nil {
		return a.fail("malformed token")
	}
	iss, err := unverifiedClaims.GetIssuer()
	if err != nil || iss == "" {
		return a.fail("missing iss claim")
	}
	iv, ok := a.byIssuer[iss]
	if !ok {
		return a.fail("unknown issuer")
	}

	// Optional explicit typing (RFC 8725 §3.11): a per-issuer contract may
	// require a specific `typ` (e.g. "at+jwt"). Compared case-insensitively
	// since `typ` is a media type.
	if iv.typ != "" {
		gotTyp, _ := unverifiedTok.Header["typ"].(string)
		if !strings.EqualFold(gotTyp, iv.typ) {
			return a.fail("unexpected typ header")
		}
	}

	// Full verification against ONLY this issuer's key set: signature,
	// algorithm allowlist, exp/nbf/iat (with leeway), iss, and aud.
	claims := jwt.MapClaims{}
	if _, err := iv.parser.ParseWithClaims(raw, claims, iv.keys.KeyfuncCtx(ctx)); err != nil {
		return a.fail("verification failed")
	}

	// Claim bindings: every configured binding must match, or the token is
	// rejected. This is the gate that keeps an open issuer (any GitHub
	// Actions workflow can mint a validly-signed token for the right
	// audience) pinned to the callers the operator actually trusts.
	for claim, patterns := range iv.claimBindings {
		val, ok := claims[claim].(string)
		if !ok || !matchesAnyGlob(patterns, val) {
			return a.fail("claim binding not satisfied")
		}
	}

	// Render the identity from verified claims. A referenced claim that is
	// absent or non-string fails authentication rather than rendering a
	// blank or partial identity that policy might match unexpectedly.
	id, err := renderIdentity(iv.identity, claims)
	if err != nil {
		return a.fail("identity template: " + err.Error())
	}

	scope, err := extractRepoScope(iv.repoScopeClaim, claims)
	if err != nil {
		return a.fail("repo scope claim: " + err.Error())
	}

	// Verified assertions only — never the compact token. Debug level so a
	// default (info) deployment isn't flooded with a line per request; the
	// proxy's own per-request Info log carries identity + issuer for
	// baseline audit, and this adds jti/exp correlation when an operator
	// turns Debug on.
	a.logger.DebugContext(ctx, "jwt authenticated",
		"issuer", iss, "identity", id, "jti", stringClaim(claims, "jti"), "exp", stringClaim(claims, "exp"))

	return &Identity{ID: id, Issuer: iss, RepoScope: scope}, nil
}

// fail logs reason at Debug (server-side troubleshooting only) and
// returns the single, detail-free ErrAuthenticationFailed every failure
// path shares. reason is always a fixed string, never interpolated with
// token or claim material.
func (a *JWTAuthenticator) fail(reason string) (*Identity, error) {
	a.logger.Debug("jwt authentication failed", "reason", reason)
	return nil, ErrAuthenticationFailed
}

// templateSegment is one piece of a parsed identityTemplate: exactly one
// of literal (a fixed run of text) or claim (a {claim} placeholder to
// resolve against verified claims) is set.
type templateSegment struct {
	literal string
	claim   string
}

// parseTemplate compiles an identityTemplate string into segments. It
// rejects an empty template (a rendered identity must be non-empty), an
// unclosed "{", a "}" with no matching "{", and an empty "{}" placeholder
// — all config-time errors so a malformed template fails startup rather
// than every request.
func parseTemplate(tmpl string) ([]templateSegment, error) {
	if tmpl == "" {
		return nil, fmt.Errorf("must not be empty")
	}
	var segments []templateSegment
	rest := tmpl
	for len(rest) > 0 {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			if strings.IndexByte(rest, '}') >= 0 {
				return nil, fmt.Errorf("unmatched '}'")
			}
			segments = append(segments, templateSegment{literal: rest})
			break
		}
		if lit := rest[:open]; lit != "" {
			if strings.IndexByte(lit, '}') >= 0 {
				return nil, fmt.Errorf("unmatched '}'")
			}
			segments = append(segments, templateSegment{literal: lit})
		}
		rest = rest[open+1:]
		close := strings.IndexByte(rest, '}')
		if close < 0 {
			return nil, fmt.Errorf("unclosed '{'")
		}
		claim := rest[:close]
		if claim == "" {
			return nil, fmt.Errorf("empty '{}' placeholder")
		}
		if strings.IndexByte(claim, '{') >= 0 {
			return nil, fmt.Errorf("nested '{' in placeholder")
		}
		segments = append(segments, templateSegment{claim: claim})
		rest = rest[close+1:]
	}
	return segments, nil
}

// ValidateIdentityTemplate reports whether tmpl is a well-formed
// identityTemplate (non-empty, balanced braces, no empty placeholder) —
// the config-time counterpart of parseTemplate, so a malformed template
// fails startup validation with a clear message instead of every request.
func ValidateIdentityTemplate(tmpl string) error {
	_, err := parseTemplate(tmpl)
	return err
}

// ValidateGlob reports whether pattern is a well-formed path.Match glob,
// so a claim-binding pattern with (say) an unclosed character class fails
// config validation rather than silently never matching at request time.
func ValidateGlob(pattern string) error {
	_, err := path.Match(pattern, "")
	return err
}

// renderIdentity resolves segments against claims into the final identity
// string. Every {claim} placeholder must resolve to a present, string
// -typed, NON-EMPTY claim; a claim that is missing, not a string, or the
// empty string is an error (the caller maps it to an authentication
// failure), as is a template that renders to an empty identity overall —
// an empty or partial identity must never reach the policy engine, where
// it could match a rule the operator did not intend.
func renderIdentity(segments []templateSegment, claims jwt.MapClaims) (string, error) {
	var b strings.Builder
	for _, s := range segments {
		if s.claim == "" {
			b.WriteString(s.literal)
			continue
		}
		val, ok := claims[s.claim].(string)
		if !ok {
			return "", fmt.Errorf("claim %q is absent or not a string", s.claim)
		}
		if val == "" {
			return "", fmt.Errorf("claim %q is empty", s.claim)
		}
		b.WriteString(val)
	}
	out := b.String()
	if out == "" {
		return "", fmt.Errorf("rendered identity is empty")
	}
	return out, nil
}

// extractRepoScope reads the repo-scope claim named by claimName from
// claims. An empty claimName (the issuer configured no scope claim)
// yields a nil scope — policy alone decides. A claim that is absent also
// yields a nil scope (the token asserts no narrowing). A claim that is
// present but is not a JSON array of strings is an error. A present empty
// array yields a non-nil empty slice, which internal/policy treats as
// "deny every repo".
func extractRepoScope(claimName string, claims jwt.MapClaims) ([]string, error) {
	if claimName == "" {
		return nil, nil
	}
	raw, present := claims[claimName]
	if !present {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("claim %q is not an array", claimName)
	}
	// Non-nil even when empty: a token that carries an explicit empty
	// scope array is asserting "no repos", which must deny everything, not
	// be indistinguishable from an absent claim (which permits policy to
	// decide alone).
	scope := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("claim %q contains a non-string element", claimName)
		}
		scope = append(scope, s)
	}
	return scope, nil
}

// matchesAnyGlob reports whether s matches any of patterns under
// path.Match semantics — the same glob dialect internal/policy uses for
// identity/repo patterns, so a claim binding like {repository:
// "rxbynerd/*"} matches with exactly the behaviour an operator already
// understands from policy.yaml. A malformed pattern (path.Match returns
// ErrBadPattern) simply never matches, so a typo fails closed rather than
// throwing.
func matchesAnyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, s); err == nil && ok {
			return true
		}
	}
	return false
}

// stringClaim renders a claim as a string for a debug log line, tolerating
// the non-string types (numbers, in particular exp) that MapClaims decodes
// JSON into. Used only for audit logging of verified claims, never for a
// security decision. A float64 (how encoding/json decodes every JSON
// number, including a Unix-timestamp exp) that holds an integral value is
// rendered as a plain integer rather than left to default %v formatting,
// which would print a timestamp like 1750000000 as "1.75e+09".
func stringClaim(claims jwt.MapClaims, name string) string {
	switch v := claims[name].(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}
