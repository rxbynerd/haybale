// Package proxy implements haybale's streaming passthrough reverse
// proxy for git smart-HTTP traffic.
//
// Every request that gitproto.ParseRequest accepts and that resolves to
// a configured upstream is authenticated (internal/identity) and
// authorized (internal/policy) before it is forwarded. Once authorized,
// a per-upstream upstream.CredentialSource mints (or returns a fixed)
// upstream credential that rewrite injects in place of the client's own
// Authorization header — the client's haybale token never reaches the
// upstream, and the upstream credential never reaches the client (see
// modifyResponse). Pack data can run to gigabytes, so nothing here may
// buffer or parse a body — only httputil.ReverseProxy's plumbing (and a
// byte-counting wrapper for the request log) touches it.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/security"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// wwwAuthenticateChallenge is the WWW-Authenticate header value sent
// alongside a 401: it names the Basic scheme so a git client re-prompts
// for (or retries with) credentials rather than giving up outright.
const wwwAuthenticateChallenge = `Basic realm="haybale"`

// Proxy is an http.Handler that validates inbound smart-HTTP requests,
// authenticates and authorizes the caller, and streams the request
// through to the configured upstream.
type Proxy struct {
	// upstreams maps a host-in-path key (e.g. "github.com") to that
	// upstream's base URL. Treated as immutable after New returns — safe
	// for concurrent reads without a lock since nothing ever mutates it.
	upstreams map[string]*url.URL
	// credentialSources maps the same host-in-path key to the
	// upstream.CredentialSource that mints (or returns a fixed) the
	// credential injected into that upstream's requests. Also treated as
	// immutable after New returns.
	credentialSources map[string]upstream.CredentialSource
	rp                *httputil.ReverseProxy
	logger            *slog.Logger
	authenticator     identity.Authenticator
	policyEngine      policy.Engine
}

// routeKey is the context key ServeHTTP uses to hand the resolved
// upstream base URL to rewrite.
type routeKey struct{}

// credentialContextKey is the context key ServeHTTP uses to hand the
// resolved upstream credential — plus the repo/verb the credential was
// minted for, needed again by modifyResponse to log a
// security.EventUpstreamAuthFailed — to rewrite and modifyResponse.
type credentialContextKey struct{}

// credentialContext is the value stored under credentialContextKey.
type credentialContext struct {
	credential upstream.BasicAuth
	repo       gitproto.Repo
	verb       gitproto.Verb
}

// New builds a Proxy that routes by the host-in-path segment: upstreams
// maps that key to the upstream's base URL, and credentialSources maps
// the same key to the upstream.CredentialSource that mints the
// credential injected into that upstream's requests. Both maps are the
// injectable seam a caller (production config, or the e2e harness) uses
// to point a host key at an arbitrary base URL/credential, such as an
// httptest server and a StaticSource. authenticator and policyEngine
// gate every non-healthz request: a request that fails Authenticate gets
// a 401, and one that Authorize denies gets a 404 indistinguishable from
// an unknown or malformed one. A nil authenticator or policyEngine is
// rejected here, at construction time, rather than left to panic on the
// first non-/healthz request — every production call path already has
// both by the time it reaches New (config.Validate() populates them
// before serve.go calls New), so a nil value here indicates a caller bug
// this constructor should catch immediately, matching the
// fail-fast-at-startup philosophy internal/config already uses.
//
// A nil logger falls back to slog.Default().
func New(upstreams map[string]*url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger) (*Proxy, error) {
	if authenticator == nil {
		return nil, fmt.Errorf("proxy: authenticator is required")
	}
	if policyEngine == nil {
		return nil, fmt.Errorf("proxy: policyEngine is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	p := &Proxy{
		upstreams:         upstreams,
		credentialSources: credentialSources,
		authenticator:     authenticator,
		policyEngine:      policyEngine,
		logger:            logger,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		// -1 disables periodic batching and flushes on every write
		// instead, so git's sideband progress output (clone/push
		// percentages) streams live through the proxy rather than
		// arriving in bursts.
		FlushInterval: -1,
		Transport: &http.Transport{
			// Never let the transport request/decode its own gzip
			// encoding — Content-Encoding and Accept-Encoding must pass
			// through exactly as the client sent them, since this is a
			// byte-for-byte passthrough, not a decoding proxy.
			DisableCompression: true,
			// ForceAttemptHTTP2 already defaults to false on a
			// manually-constructed http.Transport (it is only true on
			// http.DefaultTransport); set explicitly so the HTTP/1.1
			// requirement is visible here rather than relying on that
			// default.
			ForceAttemptHTTP2: false,
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		// ModifyResponse maps a post-injection upstream 401/403 to a 502
		// and strips WWW-Authenticate — see modifyResponse's doc comment
		// for the security invariant this enforces.
		ModifyResponse: p.modifyResponse,
	}
	return p, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}

	repo, verb, err := gitproto.ParseRequest(r)
	if err != nil {
		// Malformed, dumb-protocol, and path-traversal requests all
		// collapse to the same 404 a policy-denied or genuinely
		// nonexistent repo would return — no existence oracle. Logged
		// at the fixed, static reason gitproto.invalid() already
		// produces (err.Error() here is always one of those constant
		// strings, never the raw request path/query) so a deployment
		// under active probing has signal without an information leak
		// or unbounded log-line size from attacker-controlled input.
		p.logger.Warn("rejected request", "reason", err.Error())
		http.NotFound(w, r)
		return
	}

	base, ok := p.upstreams[repo.Host]
	if !ok {
		p.logger.Warn("rejected request", "reason", "unknown upstream host", "host", repo.Host)
		http.NotFound(w, r)
		return
	}

	id, err := p.authenticator.Authenticate(r.Context(), r)
	if err != nil {
		// The credential itself is never logged — only that
		// authentication failed and for which repo/verb it was
		// attempted, which is the audit-relevant context.
		security.Log(p.logger, security.EventAuthnFailed,
			"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String())
		w.Header().Set("WWW-Authenticate", wwwAuthenticateChallenge)
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}

	decision := p.policyEngine.Authorize(*id, repo, verb)
	if !decision.Allowed {
		// matchedRule is "none" when no rule's identity/repo patterns
		// matched at all (default deny), or the matched rule's own
		// String() when a rule matched but didn't grant this verb —
		// distinguishing the two for audit purposes without ever
		// logging anything from the request itself beyond repo/verb.
		matchedRule := "none"
		if decision.Rule != nil {
			matchedRule = decision.Rule.String()
		}
		// Policy-denied and unknown/malformed requests must be
		// byte-identical to the client: no existence oracle. This is
		// exactly the same http.NotFound(w, r) call the two branches
		// above use, with nothing written to w beforehand — do not add
		// a header or a body here.
		security.Log(p.logger, security.EventPolicyDenied,
			"identity", id.ID, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
			"reason", decision.Reason, "matchedRule", matchedRule)
		http.NotFound(w, r)
		return
	}

	source, ok := p.credentialSources[repo.Host]
	if !ok || source == nil {
		// Every upstream host in production config.Validate() output has
		// a matching credential source built alongside it (config.go's
		// Upstream.Credential is required, just like BaseURL) — this
		// branch is a defensive backstop against a caller-assembled
		// upstreams/credentialSources pair that got out of sync, not a
		// path production traffic should ever reach. It is handled
		// identically to a Credentials() error below: 502, never 401,
		// since the client still has no upstream credential to supply.
		security.Log(p.logger, security.EventUpstreamAuthFailed,
			"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
			"reason", "no credential source configured for this upstream")
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	cred, err := source.Credentials(r.Context(), repo, verb)
	if err != nil {
		// A credential-source failure (M4's mint failure; a misconfigured
		// static token) must never surface as a 401: the client has no
		// upstream credential of its own to supply, so a 401 would just
		// make git hang on (or fail) a credential prompt it can't answer.
		// The error itself is never logged — only that it happened —
		// since an implementation's error could in principle wrap
		// response bytes from an upstream token-minting call.
		security.Log(p.logger, security.EventUpstreamAuthFailed,
			"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
			"reason", "credential source error")
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}

	ctx := context.WithValue(r.Context(), routeKey{}, base)
	ctx = context.WithValue(ctx, credentialContextKey{}, credentialContext{credential: cred, repo: repo, verb: verb})

	var bytesIn atomic.Int64
	r.Body = &countingReadCloser{ReadCloser: r.Body, n: &bytesIn}

	var bytesOut atomic.Int64
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK, bytesOut: &bytesOut}

	start := time.Now()
	p.rp.ServeHTTP(rec, r.WithContext(ctx))
	duration := time.Since(start)

	// Logged after ServeHTTP returns (rather than before, as a prior
	// version of this line did at Debug level) so the log carries the
	// actual response status, byte counts, and duration — outcome
	// information a caller can't know in advance. Info rather than Debug
	// so a default-configured deployment (LogLevel: "info") gets baseline
	// per-request observability instead of logging nothing. bytesIn and
	// bytesOut are counted by wrapping the request body reader and
	// response writer, never by buffering: pack data can run to
	// gigabytes, so nothing here reads the body itself, only how many
	// bytes passed through it.
	p.logger.Info("proxied request",
		"identity", id.ID, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(), "status", rec.status,
		"bytesIn", bytesIn.Load(), "bytesOut", bytesOut.Load(), "durationMs", duration.Milliseconds())
}

// countingReadCloser wraps an io.ReadCloser and atomically tallies every
// byte Read returns into n, without buffering or otherwise altering the
// stream — used to count inbound request-body bytes for the
// byte-counting request log.
type countingReadCloser struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// statusRecorder wraps an http.ResponseWriter to capture the status code
// written and tally response bytes, so ServeHTTP can log both after
// httputil.ReverseProxy has finished writing the response. It implements
// http.Flusher (delegating to the underlying ResponseWriter when
// available) so it doesn't disable the live-flushing behaviour New's
// FlushInterval: -1 configures — the ReverseProxy internals silently
// drop flushing for a ResponseWriter that doesn't implement
// http.Flusher.
type statusRecorder struct {
	http.ResponseWriter
	status   int
	bytesOut *atomic.Int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Write tallies every byte written to the client before delegating to
// the underlying ResponseWriter — response bodies stream through
// unbuffered exactly as before; only the running count is new.
func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytesOut.Add(int64(n))
	return n, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// rewrite implements httputil.ReverseProxy.Rewrite. It points the
// outbound request at the upstream base URL ServeHTTP resolved, with the
// path rewritten to strip only the leading /{host} segment — the
// /{owner}/{repo}[.git]/<endpoint> suffix and query string, along with
// every header (Git-Protocol, Content-Type, Content-Encoding, Accept,
// Accept-Encoding included) that pr.Out already carries as a clone of
// the inbound request, pass through unchanged — except Authorization,
// which is explicitly deleted and replaced (see below).
//
// Deliberately absent: a call to pr.SetXForwarded(). ReverseProxy only
// strips inbound Forwarded/X-Forwarded-* headers and reintroduces its
// own X-Forwarded-For/Host/Proto when SetXForwarded is called — leaving
// it uncalled is the mechanism by which those headers are suppressed
// rather than forwarded, per this proxy's security design (never inject
// client IP/host/proto upstream). Do not "fix" this by adding
// SetXForwarded(); TestClientXForwardedHeadersAreSuppressed guards
// against exactly that regression.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	base, _ := pr.In.Context().Value(routeKey{}).(*url.URL)

	// SetURL sets scheme/host and joins base.Path with the (still
	// host-prefixed) inbound path; that joined path is overwritten
	// below with the host-segment-stripped version, but SetURL is still
	// what establishes scheme/host and merges any query string carried
	// on base itself.
	pr.SetURL(base)
	pr.Out.URL.Path = base.Path + stripHostSegment(pr.In.URL.Path)
	pr.Out.URL.RawPath = ""

	// httputil.ReverseProxy only strips the small RFC hop-by-hop header
	// set (Connection, Keep-Alive, Proxy-Authenticate,
	// Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade) by
	// default — Authorization is end-to-end, not hop-by-hop, so it would
	// otherwise clone straight through to pr.Out. The client's
	// Authorization here is the haybale auth token Authenticate just
	// checked (Basic password or Bearer), never a credential the
	// upstream git host understands; forwarding it verbatim would leak
	// that token to anything with visibility into the upstream leg.
	pr.Out.Header.Del("Authorization")

	// Order matters: the delete above must run before this SetBasicAuth
	// call, never after — the inbound client credential must be replaced
	// by the injected upstream one, never appended alongside it (which
	// SetBasicAuth's own Header.Set semantics already guarantee even if
	// the order were reversed, but the delete keeps that guarantee
	// explicit rather than incidental). credentialContext is always
	// present here: ServeHTTP sets it in the same context value it uses
	// for routeKey, immediately before invoking p.rp.ServeHTTP, and
	// rewrite only ever runs as part of that same call.
	if cc, ok := pr.In.Context().Value(credentialContextKey{}).(credentialContext); ok {
		pr.Out.SetBasicAuth(cc.credential.Username, cc.credential.Password)
	}
}

// modifyResponse implements httputil.ReverseProxy.ModifyResponse. Its
// only job is the second half of M3's core security invariant: the
// upstream credential rewrite injected must never reach the client. A
// 401 or 403 arriving here happened strictly after rewrite already set
// Authorization to that injected credential — httputil.ReverseProxy
// calls Rewrite before every RoundTrip, with no path that sends a
// request without it — so any 401/403 response means the upstream
// rejected haybale's own credential, not something the client did.
// Treating it as an ordinary passthrough 401 would make git re-prompt
// the client for a credential it has no way to supply (the sandbox has
// no real git credentials — that's the entire premise of haybale
// existing); this maps it to 502 instead and strips WWW-Authenticate so
// git never even considers re-prompting.
//
// Every other status (success or any other error) is streamed through
// completely unmodified — this function must never rewrite a genuine
// upstream success response.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	cc, _ := resp.Request.Context().Value(credentialContextKey{}).(credentialContext)
	security.Log(p.logger, security.EventUpstreamAuthFailed,
		"host", cc.repo.Host, "owner", cc.repo.Owner, "repo", cc.repo.Name, "verb", cc.verb.String(),
		"upstreamStatus", resp.StatusCode, "reason", "upstream rejected injected credential")

	// The original body is discarded (and its reader closed here, since
	// ReverseProxy only closes whatever Body is set on resp when this
	// function returns, not one that was replaced and abandoned) — an
	// upstream error page for a 401/403 is not something haybale can
	// vouch for the contents of, and there is no reason to give the
	// client anything more than a fixed, safe message.
	_ = resp.Body.Close()
	body := []byte(http.StatusText(http.StatusBadGateway) + "\n")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	// The one header this entire function exists to strip: without this,
	// a git client sees WWW-Authenticate on what looks like a 401 and
	// re-prompts for credentials the sandbox cannot supply.
	resp.Header.Del("WWW-Authenticate")
	resp.StatusCode = http.StatusBadGateway
	resp.Status = fmt.Sprintf("%d %s", http.StatusBadGateway, http.StatusText(http.StatusBadGateway))
	return nil
}

// stripHostSegment removes the leading /{host} segment from an
// already-validated request path, leaving /{owner}/{repo}[.git]/<endpoint>.
func stripHostSegment(p string) string {
	rest := strings.TrimPrefix(p, "/")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return ""
	}
	return rest[i:]
}
