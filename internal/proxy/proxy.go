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

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
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
	metrics           *observability.Metrics
	authenticator     identity.Authenticator
	policyEngine      policy.Engine

	// draining is set by BeginDrain, called from cmd/haybale/cmd/serve.go
	// on SIGTERM/SIGINT before http.Server.Shutdown is invoked. Once true,
	// /healthz starts returning 503 instead of 200, telling a load
	// balancer to stop routing new traffic to this instance while
	// Shutdown lets in-flight requests — a large git clone/push in
	// particular — finish streaming to completion. An atomic.Bool since
	// BeginDrain runs concurrently with in-flight ServeHTTP calls, with no
	// other synchronization between them.
	draining atomic.Bool
}

// BeginDrain marks p as draining: every subsequent /healthz request
// returns 503 instead of 200. It does not itself stop accepting new
// connections or wait for in-flight requests — that is
// http.Server.Shutdown's job (see cmd/haybale/cmd/serve.go) — it only
// flips the health-check signal a load balancer polls, so a caller
// should invoke this immediately before calling Shutdown. Idempotent and
// safe to call concurrently with ServeHTTP.
func (p *Proxy) BeginDrain() {
	p.draining.Store(true)
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
// A nil logger falls back to slog.Default(); a nil metrics falls back to
// observability.NewNoopMetrics() so every record call site is
// unconditional and no path has to nil-check.
func New(upstreams map[string]*url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger, metrics *observability.Metrics) (*Proxy, error) {
	if authenticator == nil {
		return nil, fmt.Errorf("proxy: authenticator is required")
	}
	if policyEngine == nil {
		return nil, fmt.Errorf("proxy: policyEngine is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if metrics == nil {
		metrics = observability.NewNoopMetrics()
	}
	p := &Proxy{
		upstreams:         upstreams,
		credentialSources: credentialSources,
		authenticator:     authenticator,
		policyEngine:      policyEngine,
		logger:            logger,
		metrics:           metrics,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		// -1 disables periodic batching and flushes on every write
		// instead, so git's sideband progress output (clone/push
		// percentages) streams live through the proxy rather than
		// arriving in bursts.
		FlushInterval: -1,
		// otelhttp.NewTransport wraps the upstream leg so each forwarded
		// request produces a client span (parented to the inbound server
		// span) and an http.client.* metric. It is given an EMPTY
		// propagator deliberately: haybale must not inject its own
		// traceparent/tracestate/baggage into the request it sends
		// upstream, preserving the byte-for-byte passthrough invariant
		// (the upstream leg carries only the headers the client sent plus
		// the Authorization rewrite injects — see rewrite). Inbound trace
		// continuation still works: the server handler uses the global W3C
		// propagator to extract a caller-supplied traceparent. When telemetry
		// is disabled the global tracer is a no-op.
		Transport: otelhttp.NewTransport(
			&http.Transport{
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
			otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator()),
		),
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		// ModifyResponse maps a post-injection upstream 401/403 to a 502
		// and resets the response headers to a minimal known-safe set
		// (so WWW-Authenticate and anything else upstream-controlled
		// never reaches the client) — see modifyResponse's doc comment
		// for the security invariant this enforces.
		ModifyResponse: p.modifyResponse,
	}
	return p, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		if p.draining.Load() {
			// Deliberately still a "successful" HTTP exchange, just a
			// non-2xx status: a load balancer's health check should read
			// this as "stop routing new traffic here", not as haybale
			// itself being unreachable.
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// The server span otelhttp opened (in serve.go) lives on r.Context();
	// enrich it as the request resolves so a trace carries haybale's own
	// view (verb, host, outcome) alongside otelhttp's protocol attributes.
	span := trace.SpanFromContext(r.Context())

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
		span.SetAttributes(attribute.String("haybale.outcome", observability.OutcomeRejected))
		p.metrics.RecordRejected(r.Context())
		p.logger.Warn("rejected request", "reason", err.Error())
		http.NotFound(w, r)
		return
	}

	base, ok := p.upstreams[repo.Host]
	if !ok {
		// Deliberately no host label on the metric here: repo.Host is
		// attacker-controlled for an unknown upstream (see
		// Metrics.RecordRejected). The span, which tolerates the
		// cardinality, still gets the verb for debugging.
		span.SetAttributes(
			attribute.String("haybale.verb", verb.String()),
			attribute.String("haybale.outcome", observability.OutcomeRejected),
		)
		p.metrics.RecordRejected(r.Context())
		p.logger.Warn("rejected request", "reason", "unknown upstream host", "host", repo.Host)
		http.NotFound(w, r)
		return
	}

	// From here host is a configured upstream (a bounded label) and verb
	// is known — safe to put both on the span and on metric labels.
	span.SetAttributes(
		attribute.String("haybale.host", repo.Host),
		attribute.String("haybale.verb", verb.String()),
		attribute.String("haybale.repo.owner", repo.Owner),
		attribute.String("haybale.repo.name", repo.Name),
	)

	id, err := p.authenticator.Authenticate(r.Context(), r)
	if err != nil {
		// The credential itself is never logged — only that
		// authentication failed and for which repo/verb it was
		// attempted, which is the audit-relevant context.
		span.SetAttributes(attribute.String("haybale.outcome", observability.OutcomeAuthnFailed))
		p.metrics.RecordFailure(r.Context(), repo.Host, verb.String(), observability.OutcomeAuthnFailed)
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
		span.SetAttributes(
			attribute.String("haybale.identity", id.ID),
			attribute.String("haybale.outcome", observability.OutcomePolicyDenied),
		)
		p.metrics.RecordFailure(r.Context(), repo.Host, verb.String(), observability.OutcomePolicyDenied)
		security.Log(p.logger, security.EventPolicyDenied,
			"identity", id.ID, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
			"reason", decision.Reason, "matchedRule", matchedRule)
		http.NotFound(w, r)
		return
	}
	span.SetAttributes(attribute.String("haybale.identity", id.ID))
	if id.Issuer != "" {
		// The VERIFIED issuer (post-authentication) is drawn from the
		// operator's own bounded, configured issuer set — never the
		// attacker-controlled unverified `iss` — so it is safe as a
		// low-cardinality span attribute for audit correlation.
		span.SetAttributes(attribute.String("haybale.issuer", id.Issuer))
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
		span.SetAttributes(attribute.String("haybale.outcome", observability.OutcomeUpstreamAuthFailed))
		p.metrics.RecordFailure(r.Context(), repo.Host, verb.String(), observability.OutcomeUpstreamAuthFailed)
		security.Log(p.logger, security.EventUpstreamAuthFailed,
			"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
			"reason", "no credential source configured for this upstream")
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	cred, err := source.Credentials(r.Context(), repo, verb)
	if err != nil {
		// A credential-source failure must never surface as a 401: the client
		// has no upstream credential of its own to supply, so a 401 would just
		// make git hang on (or fail) a credential prompt it can't answer.
		// The error itself is never logged — only that it happened —
		// since an implementation's error could in principle wrap
		// response bytes from an upstream token-minting call.
		span.SetAttributes(attribute.String("haybale.outcome", observability.OutcomeUpstreamAuthFailed))
		p.metrics.RecordFailure(r.Context(), repo.Host, verb.String(), observability.OutcomeUpstreamAuthFailed)
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

	// In-flight gauge brackets exactly the forwarded transfer: incremented
	// immediately before the (possibly multi-gigabyte, arbitrarily long)
	// upstream stream begins and decremented via defer when it returns, so
	// a stuck or saturating upstream shows up as a rising gauge. Uses
	// r.Context() so the observation carries the request's trace context.
	p.metrics.InFlightAdd(r.Context(), repo.Host, verb.String(), 1)
	defer p.metrics.InFlightAdd(r.Context(), repo.Host, verb.String(), -1)

	start := time.Now()
	p.rp.ServeHTTP(rec, r.WithContext(ctx))
	duration := time.Since(start)

	span.SetAttributes(
		attribute.String("haybale.outcome", observability.OutcomeProxied),
		attribute.Int("http.response.status_code", rec.status),
	)
	p.metrics.RecordProxied(r.Context(), repo.Host, verb.String(), rec.status, duration, bytesIn.Load(), bytesOut.Load())

	// Log after proxying so the record includes response status, byte counts,
	// and duration. The counters wrap the request body and response writer;
	// they never buffer pack data.
	//
	// InfoContext (not Info) so the record carries r.Context(): when
	// telemetry is on, the SpanContextHandler stamps this line with the
	// same trace_id/span_id as the request span and the otelslog bridge
	// ships it correlated. With telemetry off there is no active span and
	// the context is simply ignored.
	p.logger.InfoContext(r.Context(), "proxied request",
		"identity", id.ID, "issuer", id.Issuer, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(), "status", rec.status,
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

// modifyResponse implements httputil.ReverseProxy.ModifyResponse. It prevents
// upstream authentication responses from exposing credential challenges or
// other upstream-controlled error data to the client. A
// 401 or 403 arriving here happened strictly after rewrite already set
// Authorization to that injected credential — httputil.ReverseProxy
// calls Rewrite before every RoundTrip, with no path that sends a
// request without it — so any 401/403 response means the upstream
// rejected haybale's own credential, not something the client did.
// Treating it as an ordinary passthrough 401 would make git re-prompt
// the client for a credential it has no way to supply (the sandbox has
// no real git credentials — that's the entire premise of haybale
// existing); this maps it to 502 instead and resets the response headers
// to a minimal known-safe set so git never even considers re-prompting
// and no upstream-controlled header (WWW-Authenticate, Set-Cookie, or
// anything else) reaches the client. The discarded upstream body is
// drained to EOF before its reader is closed, so the connection this
// response arrived on can be reused for the next request to the same
// upstream — a bad credential is a sustained failure mode, so every
// subsequent request hits this same path until it's fixed.
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

	// The original body is drained to EOF before being closed (not merely
	// closed) so the Transport can return the underlying connection to
	// its keep-alive pool instead of being forced to discard it — a
	// closed-but-unread body makes net/http treat the connection as
	// unreusable. A bad or expired credential is a sustained failure
	// mode: every subsequent request to this upstream hits this same
	// path, so without draining, an incident becomes "redial upstream on
	// every single request" at the worst possible time. The drained bytes
	// are discarded, never inspected: an upstream error page for a
	// 401/403 is not something haybale can vouch for the contents of, and
	// there is no reason to give the client anything more than a fixed,
	// safe message.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	body := []byte(http.StatusText(http.StatusBadGateway) + "\n")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	// The client-visible headers are replaced wholesale with a minimal,
	// known-safe set, rather than merely deleting WWW-Authenticate —
	// this is what actually stops Set-Cookie, a bespoke challenge header,
	// or anything else a compromised, misconfigured, or lookalike
	// upstream's 401/403 page happens to set from streaming through on
	// this synthetic 502. WWW-Authenticate in particular must never
	// survive: without stripping it, a git client sees it on what looks
	// like a 401 and re-prompts for credentials the sandbox cannot
	// supply — the wholesale reset below covers that case too, so no
	// separate Header.Del("WWW-Authenticate") call is needed.
	resp.Header = http.Header{}
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
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
