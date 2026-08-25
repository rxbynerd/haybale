package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"golang.org/x/time/rate"
)

// keySource is one issuer's JWKS trust material: it yields the
// golang-jwt jwt.Keyfunc that maps a token's `kid` header to the public
// key that must have signed it. Each issuer has its own keySource, so a
// token is only ever verified against the keys of the issuer its
// (unverified) `iss` claim selected — never "try every issuer's keys" —
// preventing cross-issuer key confusion.
//
// keyfunc.Keyfunc (both the URL- and file-backed implementations) already
// satisfies exactly what JWTAuthenticator needs, so keySource is a thin
// alias of that interface rather than a bespoke wrapper — it exists to
// name the role in this package's own vocabulary and to give the two
// constructors below a shared return type.
type keySource = keyfunc.Keyfunc

// jwksHTTPTimeout bounds a single JWKS fetch. Unlike the proxy data path
// (which deliberately sets no transfer timeout, since pack transfers run
// to gigabytes), a JWKS document is a small, bounded JSON object fetched
// from a control-plane endpoint: a fetch that hangs must never be allowed
// to stall startup (the initial fail-fast fetch) or pin a refresh
// goroutine indefinitely, so it gets a short, fixed timeout.
const jwksHTTPTimeout = 10 * time.Second

// defaultJWKSRefreshInterval is how often a URL-backed keySource
// re-fetches its JWKS in the background when the endpoint sends no
// Cache-Control max-age of its own. Chosen to comfortably track standard
// overlap key rotation (publish-new-alongside-old, then retire-old) while
// keeping steady-state egress to the JWKS endpoint negligible.
const defaultJWKSRefreshInterval = time.Hour

// unknownKIDRefetchEvery rate-limits the "refetch the JWKS on a token
// whose kid we've never seen" behaviour: a burst of tokens bearing an
// unknown (or attacker-chosen) kid must not translate into a burst of
// outbound JWKS fetches. One refetch per this interval is enough to pick
// up a freshly-rotated key promptly without turning unknown-kid tokens
// into an egress amplification vector.
const unknownKIDRefetchEvery = 5 * time.Minute

// newURLKeySource builds a URL-backed keySource for jwksURL. It launches
// a background refresh goroutine bound to ctx (so it stops when the
// server's context is cancelled on shutdown) that keeps the key set
// current, honouring the endpoint's Cache-Control and refetching — behind
// unknownKIDRefetchEvery — when a token presents an unseen kid.
//
// The initial fetch is synchronous and fail-fast: newURLKeySource returns
// an error if the JWKS cannot be fetched and parsed into at least one key
// at startup, so a misconfigured or unreachable JWKS URL refuses to serve
// traffic rather than failing unpredictably on the first request — the
// same fail-fast-at-startup philosophy identities/policy/TLS loading
// already follow. refreshErr surfaces a background refresh failure to
// logger (never silently swallowed) so a JWKS endpoint that later goes
// bad is visible in the operator's logs.
func newURLKeySource(ctx context.Context, jwksURL string, logger *slog.Logger) (keySource, error) {
	if logger == nil {
		logger = slog.Default()
	}
	// NoErrorReturnFirstHTTPReq=false makes the constructor's initial
	// fetch synchronous and fail-fast: a first fetch that fails returns an
	// error here rather than being deferred to the background goroutine.
	failFast := false
	ks, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
		Client:                    &http.Client{Timeout: jwksHTTPTimeout},
		HTTPTimeout:               jwksHTTPTimeout,
		NoErrorReturnFirstHTTPReq: &failFast,
		RefreshInterval:           defaultJWKSRefreshInterval,
		RefreshUnknownKID:         rate.NewLimiter(rate.Every(unknownKIDRefetchEvery), 1),
		RefreshErrorHandlerFunc: func(u string) func(ctx context.Context, err error) {
			return func(ctx context.Context, err error) {
				// A refresh failure is not fatal — the last successfully
				// fetched key set keeps serving — but it must be visible:
				// an operator needs to know their trust material has gone
				// stale before an unnoticed rotation locks every caller out.
				logger.WarnContext(ctx, "jwks background refresh failed", "jwksURL", u, "error", err)
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("identity: fetch jwks from %q: %w", jwksURL, err)
	}
	// Belt-and-suspenders over NoErrorReturnFirstHTTPReq: require the
	// initial fetch to have yielded at least one usable key, so an
	// endpoint that returns 200 with an empty or unparseable key set fails
	// startup here with a clear message rather than passing config
	// validation and then rejecting every token at request time.
	keys, err := ks.VerificationKeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity: read jwks from %q: %w", jwksURL, err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("identity: jwks at %q contained no keys", jwksURL)
	}
	return ks, nil
}

// newFileKeySource builds a file-backed keySource from a static JWKS
// document on disk (the per-issuer jwksFile option). No network fetch and
// no refresh goroutine: the file is read once, at startup, and its keys
// are fixed for the process lifetime — the airgapped/e2e counterpart to
// newURLKeySource, and how a test stands up a real verifier against an
// in-process signing key without an httptest JWKS server. Rotating a
// file-backed issuer's keys means editing the file and restarting, which
// is exactly the explicit, greppable behaviour an operator who chose a
// static file over a URL is asking for.
func newFileKeySource(jwksFile string) (keySource, error) {
	raw, err := os.ReadFile(jwksFile) //nolint:gosec // jwksFile is an operator-supplied config path, not attacker input
	if err != nil {
		return nil, fmt.Errorf("identity: read jwksFile %q: %w", jwksFile, err)
	}
	ks, err := keyfunc.NewJWKSetJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("identity: parse jwksFile %q: %w", jwksFile, err)
	}
	keys, err := ks.VerificationKeySet(context.Background())
	if err != nil {
		return nil, fmt.Errorf("identity: read jwksFile %q: %w", jwksFile, err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("identity: jwksFile %q contained no keys", jwksFile)
	}
	return ks, nil
}

// errNoKeySource is a programmer-error guard: a fully validated issuer
// always has exactly one of jwksURL/jwksFile, so reaching key-source
// construction with neither indicates a config-validation bug, not an
// operator mistake.
var errNoKeySource = errors.New("identity: issuer has neither jwksURL nor jwksFile")
