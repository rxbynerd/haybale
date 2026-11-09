// Package proxy implements haybale's streaming passthrough reverse
// proxy for git smart-HTTP traffic.
//
// Every request that gitproto.ParseRequest accepts and that resolves to
// a configured upstream is authenticated (internal/identity) and
// authorized (internal/policy) before it is forwarded. Once authorized,
// a per-upstream upstream.CredentialSource mints (or returns a fixed)
// upstream credential that is injected in place of the client's own
// Authorization header — the client's haybale token never reaches the
// upstream, and the upstream credential never reaches the client (see
// sanitizeUpstreamResponse). Pack data can run to gigabytes, so the
// passthrough path never buffers or parses a body — only
// httputil.ReverseProxy's plumbing (and a byte-counting wrapper for the
// request log) touches it. When a response cache is configured
// (WithCache), a policy-allowed read is offered to it first; the cache
// reads that request's body, bounded by its own limit, to classify it,
// and streams the response through a disk spool (see internal/cache).
// Writes and reads the cache declines take the passthrough path.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

	"github.com/rxbynerd/haybale/internal/cache"
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

// upstreamConnectTimeout bounds dialing and the TLS handshake of an
// upstream connection. Transfers themselves stay unbounded.
const upstreamConnectTimeout = 30 * time.Second

// cacheUserAgent is the User-Agent of every request the response cache
// sends upstream. It begins with "git/" because git hosts gate
// smart-HTTP behaviour on that prefix.
const cacheUserAgent = "git/2.0 (haybale)"

// errNoCredentialSource reports an upstream host with no credential
// source, a caller-assembled configuration error.
var errNoCredentialSource = errors.New("proxy: no credential source configured for this upstream")

// ResponseCache is the consumer-side interface of the response cache;
// *cache.Cache satisfies it. Serve is offered every policy-allowed read
// with the verified identity's ID and reports whether it wrote the
// response; Invalidate is called after every git-receive-pack POST.
type ResponseCache interface {
	Serve(w http.ResponseWriter, r *http.Request, repo gitproto.Repo, baseURL *url.URL, fetch cache.Fetcher, identity string) (cache.Outcome, bool)
	Invalidate(ctx context.Context, repo gitproto.Repo, baseURL *url.URL)
}

// Option configures a Proxy at construction.
type Option func(*Proxy)

// WithCache serves policy-allowed reads through c. A nil c leaves the
// proxy a pure passthrough.
func WithCache(c ResponseCache) Option {
	return func(p *Proxy) { p.cache = c }
}

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
	// transport is the one upstream transport; the passthrough reverse
	// proxy and the cache's fetcher share it so both legs carry the same
	// timeouts, compression posture and instrumentation.
	transport     http.RoundTripper
	rp            *httputil.ReverseProxy
	cache         ResponseCache
	logger        *slog.Logger
	metrics       *observability.Metrics
	authenticator identity.Authenticator
	policyEngine  policy.Engine

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
// unconditional and no path has to nil-check. opts apply optional
// features such as WithCache; without them the proxy is a pure
// passthrough.
func New(upstreams map[string]*url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, logger *slog.Logger, metrics *observability.Metrics, opts ...Option) (*Proxy, error) {
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
	for _, opt := range opts {
		opt(p)
	}
	// otelhttp.NewTransport wraps the upstream leg, shared by the
	// passthrough reverse proxy and the cache fetcher, so each upstream
	// request produces a client span (parented to the inbound server span)
	// and an http.client.* metric. It is given an EMPTY propagator
	// deliberately: haybale must not inject its own
	// traceparent/tracestate/baggage upstream, so the passthrough carries
	// only the client's headers plus the injected Authorization (see
	// rewrite) and the fetcher only its fixed header set. Inbound trace
	// continuation still works: the server handler uses the global W3C
	// propagator to extract a caller-supplied traceparent. When telemetry
	// is disabled the global tracer is a no-op.
	p.transport = otelhttp.NewTransport(
		&http.Transport{
			// Dial and TLS handshake are the only bounded phases of an
			// upstream connection; a transfer may take as long as it
			// needs.
			DialContext:         (&net.Dialer{Timeout: upstreamConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: upstreamConnectTimeout,
			// The transport never adds or decodes gzip itself, so the
			// passthrough forwards Accept-Encoding and Content-Encoding
			// exactly as sent, and the cache fetcher's explicit
			// Accept-Encoding: identity is what reaches upstream.
			DisableCompression: true,
			// ForceAttemptHTTP2 already defaults to false on a
			// manually-constructed http.Transport (it is only true on
			// http.DefaultTransport); set explicitly so the HTTP/1.1
			// requirement is visible here rather than relying on that
			// default.
			ForceAttemptHTTP2: false,
		},
		otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator()),
	)
	p.rp = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		// -1 disables periodic batching and flushes on every write
		// instead, so git's sideband progress output (clone/push
		// percentages) streams live through the proxy rather than
		// arriving in bursts.
		FlushInterval: -1,
		Transport:     p.transport,
		ErrorLog:      slog.NewLogLogger(logger.Handler(), slog.LevelError),
		// ModifyResponse maps a post-injection upstream 401/403 to a 502
		// and resets the response headers to a minimal known-safe set
		// (so WWW-Authenticate and anything else upstream-controlled
		// never reaches the client) — see sanitizeUpstreamResponse's doc
		// comment for the security invariant this enforces.
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

	// The byte counters wrap the request body and response writer before
	// anything reads or writes them, on both the cache and passthrough
	// paths; they never buffer pack data.
	var bytesIn atomic.Int64
	r.Body = &countingReadCloser{ReadCloser: r.Body, n: &bytesIn}
	var bytesOut atomic.Int64
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK, bytesOut: &bytesOut}

	// In-flight gauge brackets exactly the transfer: incremented
	// immediately before the (possibly multi-gigabyte, arbitrarily long)
	// stream begins and decremented via defer when it returns, so a stuck
	// or saturating upstream shows up as a rising gauge. Uses r.Context()
	// so the observation carries the request's trace context.
	p.metrics.InFlightAdd(r.Context(), repo.Host, verb.String(), 1)
	defer p.metrics.InFlightAdd(r.Context(), repo.Host, verb.String(), -1)
	start := time.Now()

	// The cache is offered only a read, and only after policy allowed it:
	// it is the first thing that may read the body. A declined read
	// continues down the passthrough path with its body restored.
	var cacheAttrs []any
	if verb == gitproto.Read && p.cache != nil {
		outcome, handled := p.cache.Serve(rec, r, repo, base, &cacheFetcher{proxy: p, base: base, repo: repo}, id.ID)
		cacheAttrs = cacheLogAttrs(outcome)
		span.SetAttributes(cacheSpanAttrs(outcome)...)
		if handled {
			// The cache reports what it actually wrote; a zero status
			// means the client left before any header went out.
			p.finishProxied(r, span, id, repo, verb, outcome.Status, time.Since(start), bytesIn.Load(), outcome.BytesOut, cacheAttrs)
			return
		}
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

	// A push changes the repository's refs whatever its status (a rejected
	// push still returns 200), so the cached refs entries go either way.
	// It runs as soon as the response has been copied and, via defer, when
	// ReverseProxy panics with http.ErrAbortHandler because the client
	// disconnected mid-response. The request context may already be
	// cancelled then, so the call does not use it.
	invalidate := func() {}
	if p.cache != nil && verb == gitproto.Write && r.Method == http.MethodPost {
		invalidated := false
		invalidate = func() {
			if !invalidated {
				invalidated = true
				p.cache.Invalidate(context.WithoutCancel(r.Context()), repo, base)
			}
		}
	}

	defer invalidate()

	p.rp.ServeHTTP(rec, r.WithContext(ctx))
	invalidate()
	p.finishProxied(r, span, id, repo, verb, rec.status, time.Since(start), bytesIn.Load(), bytesOut.Load(), cacheAttrs)
}

// finishProxied records the outcome of a request answered on the client's
// behalf, from the cache or from upstream: the span attributes, the
// proxied-request metrics and the request log line. extra holds the cache
// log fields, when a cache is configured and the request was a read.
//
// A status of zero means the client left before any response header was
// written; there is no status to report, so the status attribute, the
// proxied-request metrics and the log status field are omitted.
//
// The log record uses InfoContext (not Info) so it carries r.Context():
// when telemetry is on, the SpanContextHandler stamps the line with the
// same trace_id/span_id as the request span and the otelslog bridge ships
// it correlated. With telemetry off there is no active span and the
// context is simply ignored.
func (p *Proxy) finishProxied(r *http.Request, span trace.Span, id *identity.Identity, repo gitproto.Repo, verb gitproto.Verb, status int, duration time.Duration, bytesIn, bytesOut int64, extra []any) {
	span.SetAttributes(attribute.String("haybale.outcome", observability.OutcomeProxied))
	attrs := []any{
		"identity", id.ID, "issuer", id.Issuer, "host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
	}
	if status != 0 {
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		p.metrics.RecordProxied(r.Context(), repo.Host, verb.String(), status, duration, bytesIn, bytesOut)
		attrs = append(attrs, "status", status)
	}
	attrs = append(attrs, "bytesIn", bytesIn, "bytesOut", bytesOut, "durationMs", duration.Milliseconds())
	p.logger.InfoContext(r.Context(), "proxied request", append(attrs, extra...)...)
}

// cacheLogAttrs renders a cache outcome as request-log fields: cache
// always, and the collapsed and stored flags for a miss.
func cacheLogAttrs(o cache.Outcome) []any {
	attrs := []any{"cache", o.Result}
	if o.Result == observability.ResultMiss {
		attrs = append(attrs, "cacheCollapsed", o.Collapsed, "cacheStored", o.Stored)
	}
	return attrs
}

// cacheSpanAttrs renders a cache outcome as span attributes.
func cacheSpanAttrs(o cache.Outcome) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("haybale.cache.result", o.Result)}
	if o.Result == observability.ResultMiss {
		attrs = append(attrs,
			attribute.Bool("haybale.cache.collapsed", o.Collapsed),
			attribute.Bool("haybale.cache.stored", o.Stored),
		)
	}
	return attrs
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

// prepareUpstreamRequest applies the credential boundary to an outbound
// request on either path: the client's Authorization header is removed
// and the upstream credential injected in its place. The client's
// Authorization is the haybale token Authenticate just checked, never a
// credential the upstream understands; forwarding it would leak that
// token to anything with visibility into the upstream leg. Nothing here
// adds Forwarded or X-Forwarded-* headers: haybale never tells the
// upstream the client's address, host or scheme.
func prepareUpstreamRequest(out *http.Request, cred upstream.BasicAuth) {
	out.Header.Del("Authorization")
	out.SetBasicAuth(cred.Username, cred.Password)
}

// sanitizeUpstreamResponse enforces the response side of the credential
// boundary on either path. A 401 or 403 from upstream arrives strictly
// after prepareUpstreamRequest injected haybale's own credential, so it
// means the upstream rejected that credential, not something the client
// did. Treating it as an ordinary 401 would make git re-prompt the client
// for a credential it has no way to supply (the sandbox has no real git
// credentials — that's the entire premise of haybale existing); the
// response becomes a 502 whose headers are replaced wholesale with a
// minimal known-safe set, so WWW-Authenticate, Set-Cookie or anything
// else upstream-controlled never reaches the client. The discarded body
// is drained to EOF before its reader is closed, so the connection it
// arrived on can be reused: a bad credential is a sustained failure mode
// and every subsequent request hits this same path until it is fixed.
//
// It returns the upstream status and whether the response was rewritten;
// every other status is left completely unmodified.
func sanitizeUpstreamResponse(resp *http.Response) (upstreamStatus int, sanitized bool) {
	upstreamStatus = resp.StatusCode
	if upstreamStatus != http.StatusUnauthorized && upstreamStatus != http.StatusForbidden {
		return upstreamStatus, false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	body := []byte(http.StatusText(http.StatusBadGateway) + "\n")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header = http.Header{}
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.StatusCode = http.StatusBadGateway
	resp.Status = fmt.Sprintf("%d %s", http.StatusBadGateway, http.StatusText(http.StatusBadGateway))
	return upstreamStatus, true
}

// rewrite implements httputil.ReverseProxy.Rewrite. It points the
// outbound request at the upstream base URL ServeHTTP resolved, with the
// path rewritten to strip only the leading /{host} segment — the
// /{owner}/{repo}[.git]/<endpoint> suffix and query string, along with
// every header (Git-Protocol, Content-Type, Content-Encoding, Accept,
// Accept-Encoding included) that pr.Out already carries as a clone of
// the inbound request, pass through unchanged — except Authorization,
// which prepareUpstreamRequest replaces.
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

	// credentialContext is always present here: ServeHTTP sets it in the
	// same context value it uses for routeKey, immediately before
	// invoking p.rp.ServeHTTP, and rewrite only ever runs as part of that
	// same call.
	if cc, ok := pr.In.Context().Value(credentialContextKey{}).(credentialContext); ok {
		prepareUpstreamRequest(pr.Out, cc.credential)
	}
}

// modifyResponse implements httputil.ReverseProxy.ModifyResponse by
// removing any upstream copy of cache.UpstreamStatusHeader, applying
// sanitizeUpstreamResponse and logging the security event when the
// upstream rejected the injected credential.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	resp.Header.Del(cache.UpstreamStatusHeader)
	upstreamStatus, sanitized := sanitizeUpstreamResponse(resp)
	if !sanitized {
		return nil
	}
	cc, _ := resp.Request.Context().Value(credentialContextKey{}).(credentialContext)
	p.logUpstreamRejected(cc.repo, cc.verb, upstreamStatus)
	return nil
}

func (p *Proxy) logUpstreamRejected(repo gitproto.Repo, verb gitproto.Verb, upstreamStatus int) {
	security.Log(p.logger, security.EventUpstreamAuthFailed,
		"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
		"upstreamStatus", upstreamStatus, "reason", "upstream rejected injected credential")
}

// cacheFetcher is the cache.Fetcher for one request: it synthesises the
// upstream request from the canonical cache.Request, mints the credential
// only when a fetch is needed, and sends it through the proxy's shared
// transport with the same request and response boundaries as the
// passthrough path.
type cacheFetcher struct {
	proxy *Proxy
	base  *url.URL
	repo  gitproto.Repo
}

// Fetch sends req upstream. Only the allowlisted headers are set:
// Content-Type (POST), Accept, Git-Protocol when present,
// Accept-Encoding: identity so the stored body is never encoded, a fixed
// User-Agent, and the injected Authorization. Nothing from the client's
// own request is carried. A credential mint failure is returned as an
// error; the cache then answers the request stale or releases it to the
// passthrough path, which answers 502 and logs upstream_auth_failed. An
// upstream 401 or 403 is returned as the sanitised 502 carrying
// cache.UpstreamStatusHeader with the status upstream sent; an upstream
// copy of that header is removed from every response.
func (f *cacheFetcher) Fetch(ctx context.Context, req cache.Request) (*http.Response, error) {
	source, ok := f.proxy.credentialSources[f.repo.Host]
	if !ok || source == nil {
		return nil, errNoCredentialSource
	}
	cred, err := source.Credentials(ctx, f.repo, gitproto.Read)
	if err != nil {
		return nil, fmt.Errorf("proxy: credential source: %w", err)
	}

	endpoint, query, _ := strings.Cut(req.Endpoint, "?")
	target := *f.base
	target.Path = f.base.Path + "/" + f.repo.Owner + "/" + f.repo.Name + ".git/" + endpoint
	target.RawPath = ""
	switch {
	case f.base.RawQuery == "":
		target.RawQuery = query
	case query != "":
		target.RawQuery = f.base.RawQuery + "&" + query
	}
	var body io.Reader
	if req.Method == http.MethodPost {
		body = bytes.NewReader(req.Body)
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("proxy: build upstream request: %w", err)
	}
	if req.ContentType != "" {
		out.Header.Set("Content-Type", req.ContentType)
	}
	out.Header.Set("Accept", req.Accept)
	if req.Protocol != "" {
		out.Header.Set("Git-Protocol", req.Protocol)
	}
	out.Header.Set("Accept-Encoding", "identity")
	out.Header.Set("User-Agent", cacheUserAgent)
	prepareUpstreamRequest(out, cred)

	resp, err := f.proxy.transport.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	resp.Header.Del(cache.UpstreamStatusHeader)
	if upstreamStatus, sanitized := sanitizeUpstreamResponse(resp); sanitized {
		f.proxy.logUpstreamRejected(f.repo, gitproto.Read, upstreamStatus)
		resp.Header.Set(cache.UpstreamStatusHeader, strconv.Itoa(upstreamStatus))
	}
	return resp, nil
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
