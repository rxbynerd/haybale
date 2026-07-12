// Package proxy implements haybale's streaming passthrough reverse
// proxy for git smart-HTTP traffic.
//
// For M1 this is pure passthrough: every request that gitproto.ParseRequest
// accepts is forwarded to the upstream configured for its host-in-path
// segment, with request and response bodies streamed through unmodified.
// Pack data can run to gigabytes, so nothing here may buffer or parse a
// body — only httputil.ReverseProxy's plumbing touches it. Identity,
// policy, and credential injection land in M2/M3 as additional stages
// around this same Rewrite hook.
package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// Proxy is an http.Handler that validates inbound smart-HTTP requests
// and streams them through to the configured upstream.
type Proxy struct {
	// upstreams maps a host-in-path key (e.g. "github.com") to that
	// upstream's base URL. Treated as immutable after New returns — safe
	// for concurrent reads without a lock since nothing ever mutates it.
	upstreams map[string]*url.URL
	rp        *httputil.ReverseProxy
	logger    *slog.Logger
}

// routeKey is the context key ServeHTTP uses to hand the resolved
// upstream base URL to rewrite.
type routeKey struct{}

// New builds a Proxy that routes by the host-in-path segment: upstreams
// maps that key to the upstream's base URL. This map is the injectable
// seam a caller (production config, or the e2e harness) uses to point a
// host key at an arbitrary base URL, such as an httptest server.
//
// A nil logger falls back to slog.Default().
func New(upstreams map[string]*url.URL, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	p := &Proxy{upstreams: upstreams, logger: logger}
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
	}
	return p
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

	ctx := context.WithValue(r.Context(), routeKey{}, base)
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	p.rp.ServeHTTP(rec, r.WithContext(ctx))

	// Logged after ServeHTTP returns (rather than before, as a prior
	// version of this line did at Debug level) so the log carries the
	// actual response status — the one piece of per-request outcome
	// information a caller can't know in advance. Info rather than
	// Debug so a default-configured deployment (LogLevel: "info") gets
	// baseline per-request observability instead of logging nothing.
	p.logger.Info("proxied request",
		"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(), "status", rec.status)
}

// statusRecorder wraps an http.ResponseWriter to capture the status code
// written, so ServeHTTP can log it after httputil.ReverseProxy has
// finished writing the response. It implements http.Flusher (delegating
// to the underlying ResponseWriter when available) so it doesn't disable
// the live-flushing behaviour New's FlushInterval: -1 configures — the
// ReverseProxy internals silently drop flushing for a ResponseWriter that
// doesn't implement http.Flusher.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
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
// the inbound request, pass through unchanged.
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
