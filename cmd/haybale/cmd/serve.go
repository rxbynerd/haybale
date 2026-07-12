package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/rxbynerd/haybale/internal/config"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/proxy"
	"github.com/rxbynerd/haybale/internal/security"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// readHeaderTimeout bounds how long the server waits to read request
// headers. Deliberately the only timeout the server sets: pack transfers
// can run to gigabytes and take arbitrarily long, so there are no
// read/write/idle timeouts beyond this — only the initial header read is
// bounded, guarding against a client that opens a connection and never
// sends a request line.
const readHeaderTimeout = 10 * time.Second

// telemetryShutdownTimeout bounds how long process exit waits for the OTel
// pipelines to flush and shut down. Unlike the proxy's data path (which
// deliberately sets no transfer timeout), a telemetry collector that has
// gone away must never hold the process open: this is a short, fixed
// backstop, applied after in-flight requests have already drained, so the
// last batch of spans/metrics/logs gets a fair chance to flush without
// letting a dead collector stall shutdown indefinitely.
const telemetryShutdownTimeout = 5 * time.Second

var (
	configPath       string
	tlsCertPathFlag  string
	tlsKeyPathFlag   string
	drainTimeoutFlag string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the haybale proxy",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runServe(cmd, configPath)
	},
}

func init() {
	serveCmd.Flags().StringVar(&configPath, "config", "haybale.yaml", "path to haybale's YAML config file")
	serveCmd.Flags().StringVar(&tlsCertPathFlag, "tls-cert-path", "", "path to a PEM certificate; overrides tls.certPath in the config file")
	serveCmd.Flags().StringVar(&tlsKeyPathFlag, "tls-key-path", "", "path to the PEM private key matching --tls-cert-path; overrides tls.keyPath in the config file")
	serveCmd.Flags().StringVar(&drainTimeoutFlag, "drain-timeout", "", `bounds how long graceful shutdown waits for in-flight requests to finish, e.g. "2m" ("0s", the default, waits indefinitely); overrides drainTimeout in the config file`)
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, path string) error {
	cfg, err := config.Load(path, config.WithTLSOverride(tlsCertPathFlag, tlsKeyPathFlag), config.WithDrainTimeoutOverride(drainTimeoutFlag))
	if err != nil {
		return err
	}

	// Telemetry is set up before the logger so the OTLP log handler (when
	// enabled) can be composed into it below. A disabled telemetry block
	// (no endpoint) yields a no-op Providers: noop-backed metrics, a nil
	// LogHandler, and a Shutdown that does nothing — so the wiring below is
	// unconditional and haybale behaves exactly as it did pre-telemetry.
	providers, err := observability.Setup(cmd.Context(), telemetryConfig(cfg))
	if err != nil {
		return fmt.Errorf("setup telemetry: %w", err)
	}

	// ScrubHandler wraps the leaf handler so any token or credential
	// material that reaches a log call anywhere in haybale — a bug, since
	// every call site should already pass only
	// repo/owner/host/verb/identity — is redacted before it ever leaves
	// the process, rather than relying solely on every call site getting
	// that right. When telemetry is enabled, the leaf fans out to both
	// stderr and the OTLP bridge, and the ScrubHandler sits ABOVE that
	// fan-out so both sinks receive already-scrubbed records — no log value
	// leaves the process unscrubbed regardless of sink. The outermost
	// SpanContextHandler stamps trace_id/span_id onto records emitted
	// inside a request span (a no-op otherwise).
	var leaf slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	})
	if providers.LogHandler != nil {
		leaf = observability.NewFanoutHandler(leaf, providers.LogHandler)
	}
	logger := slog.New(observability.NewSpanContextHandler(security.NewScrubHandler(leaf)))

	// Shut the telemetry pipelines down on the way out — after
	// serveWithGracefulDrain has returned (all in-flight requests drained),
	// so the final spans, metrics, and logs of the run are flushed. Bounded
	// so a collector that has gone away cannot make process exit hang. A
	// no-op on a disabled Providers.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
		defer cancel()
		if shutdownErr := providers.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Warn("telemetry shutdown did not complete cleanly", "error", shutdownErr)
		}
	}()

	upstreams, err := buildUpstreams(cfg)
	if err != nil {
		// Validate() already confirmed every BaseURL parses; a failure
		// here indicates a bug in that invariant rather than a bad
		// config, so it is surfaced rather than silently ignored.
		return fmt.Errorf("build upstreams: %w", err)
	}
	credentialSources, err := buildCredentialSources(cfg)
	if err != nil {
		// Validate() already confirmed every upstream's credential block
		// built successfully; a failure here indicates a bug in that
		// invariant rather than a bad config, so it is surfaced rather
		// than silently ignored.
		return fmt.Errorf("build credential sources: %w", err)
	}
	// Every *upstream.GitHubAppSource in credentialSources was built
	// inside config.Validate(), before this logger existed, so it is
	// still logging (if it ever needs to — see SetLogger's doc comment)
	// through its own slog.Default() fallback. Installing the real
	// logger here, before the proxy starts serving traffic, means its
	// security.EventTokenMinted events go through the same
	// ScrubHandler-wrapped logger as every other security event.
	// StaticSource needs no such wiring — it never logs anything.
	wireCredentialSourceLoggers(credentialSources, logger)
	// Install the metric instruments into every GitHubAppSource the same
	// way, and for the same reason, the logger is installed: the sources
	// were built inside config.Validate(), before the telemetry pipeline
	// existed. Must run once, at startup, before the proxy serves traffic.
	wireCredentialSourceMetrics(credentialSources, providers.Metrics)

	// Build the JWT authenticator now, at startup: this performs each
	// issuer's initial JWKS fetch (fail-fast — an unreachable or empty
	// JWKS refuses to serve traffic rather than failing per-request) and
	// launches the background refresh goroutines, bound to cmd.Context()
	// so they stop when the server shuts down. Deliberately not done in
	// config.Validate() (see IdentityConfig.BuildAuthenticator): that path
	// also runs for the offline `haybale policy check`, which must never
	// reach out to a JWKS endpoint. The policy engine, by contrast, is
	// pure file loading and stays in Validate() — Engine() below reuses
	// exactly what Validate() built.
	authenticator, err := cfg.Identity.BuildAuthenticator(cmd.Context(), logger)
	if err != nil {
		return fmt.Errorf("build authenticator: %w", err)
	}
	// proxy.New rejects a nil authenticator/policyEngine at construction,
	// so a caller bug (Validate() didn't run, leaving Engine() nil)
	// surfaces here as an error rather than a panic on the first request.
	p, err := proxy.New(upstreams, credentialSources, authenticator, cfg.Policy.Engine(), logger, providers.Metrics)
	if err != nil {
		return fmt.Errorf("build proxy: %w", err)
	}
	srv, listenAndServe, scheme, err := newServer(cfg, instrumentedHandler(cfg, p))
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	logger.Info("starting haybale", "listen", cfg.Listen, "scheme", scheme, "upstreams", len(upstreams), "drainTimeout", cfg.ParsedDrainTimeout())
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "haybale listening on %s://%s\n", scheme, cfg.Listen); err != nil {
		return err
	}

	// signal.NotifyContext, not signal.Notify: ctx.Done() fires exactly
	// once, on the first SIGTERM or SIGINT, which is all
	// serveWithGracefulDrain needs — a second signal during an already
	// -in-progress drain is not handled specially (it does not, for
	// instance, force an immediate hard shutdown); an operator who needs
	// that has srv.Close()/a process kill -9 available to them regardless
	// of anything this handler does.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serveWithGracefulDrain(ctx, srv, p, cfg.ParsedDrainTimeout(), listenAndServe, logger)
}

// newServer builds the *http.Server cfg's Listen/TLS blocks describe,
// alongside the listenAndServe function runServe should call to start it
// and the scheme ("http" or "https") it's serving, for logging. When
// cfg.TLS is disabled, listenAndServe is exactly srv.ListenAndServe and
// srv.TLSConfig is left nil; when enabled, srv.TLSConfig carries the
// certificate config.Validate() already loaded and parsed once (the same
// fail-fast-at-startup, reuse-not-reparse pattern
// upstream.CredentialSource/identity.Authenticator/policy.Engine already
// establish — Certificates, not GetCertificate, since there is nothing
// left for ListenAndServeTLS's own certFile/keyFile arguments to do), and
// listenAndServe calls srv.ListenAndServeTLS("", "") to use it.
// MinVersion is set explicitly (rather than left at Go's default, itself
// already TLS 1.2) so that floor is visible here as a deliberate choice.
//
// Deliberately absent in both cases: ReadTimeout/WriteTimeout/
// IdleTimeout — TLS must not introduce a bound on how long a
// multi-gigabyte pack transfer is allowed to take; only
// ReadHeaderTimeout bounds anything, for TLS exactly as for plain HTTP.
//
// Returns an error, rather than panicking, if cfg.TLS.Enabled() is true
// but cfg.TLS.Certificate() is nil — TLSConfig.Certificate's own doc
// comment says this happens when Validate() hasn't run yet, which is
// unreachable via runServe (config.Load always calls Validate) but is
// exactly the caller-bug case buildUpstreams/buildCredentialSources
// already guard against for their own inputs; newServer's TLS branch
// should fail the same clean way rather than nil-pointer-panicking on
// *cfg.TLS.Certificate().
//
// Extracted from runServe so TLS wiring is testable without a real
// listener — see TestNewServerTLSEnabled/TestNewServerPlainHTTP.
func newServer(cfg *config.Config, handler http.Handler) (srv *http.Server, listenAndServe func() error, scheme string, err error) {
	srv = &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	if !cfg.TLS.Enabled() {
		return srv, srv.ListenAndServe, "http", nil
	}

	cert := cfg.TLS.Certificate()
	if cert == nil {
		return nil, nil, "", fmt.Errorf("newServer: tls is enabled but no certificate was loaded (config.Validate() must run before newServer)")
	}

	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	return srv, func() error { return srv.ListenAndServeTLS("", "") }, "https", nil
}

// ErrDrainTimeoutExceeded is returned by serveWithGracefulDrain (and so
// propagates through runServe to Execute in root.go) when an operator
// -configured, finite drainTimeout expires before every in-flight
// request finished draining on its own. This is a deliberate, expected
// consequence of that configuration choice — not a crash — so Execute
// special-cases it: a distinct exit code and no "Error:" prefix, rather
// than the generic startup/runtime-error path, so on-call tooling keyed
// off either signal doesn't misread a configured cutoff as a failure.
// The full detail (that the timeout fired, and its configured value) is
// already logged as a Warn at the point serveWithGracefulDrain detects
// it, since Execute has no logger of its own.
//
// Unreachable when drainTimeout is <= 0 (the default — see
// defaultDrainTimeout in internal/config): srv.Shutdown is only ever
// given a context.WithTimeout, and so can only return
// context.DeadlineExceeded, when a finite drainTimeout was explicitly
// configured.
var ErrDrainTimeoutExceeded = errors.New("drain timeout exceeded before all in-flight requests finished")

// serveWithGracefulDrain runs listenAndServe (srv.ListenAndServe or the
// srv.ListenAndServeTLS closure runServe built, already bound to srv)
// until either it returns on its own or ctx is done — a SIGTERM/SIGINT
// runServe's signal.NotifyContext caught. On ctx.Done() it marks p as
// draining (see proxy.Proxy.BeginDrain: /healthz starts returning 503,
// telling a load balancer to stop routing new traffic here), then calls
// srv.Shutdown to stop accepting new connections while letting in-flight
// requests — a large git clone/push in particular — finish streaming to
// completion rather than being cut off mid-transfer.
//
// drainTimeout bounds how long Shutdown waits for that. <= 0 (the
// default) means wait indefinitely, for however long the slowest
// in-flight transfer takes to finish on its own — matching the rest of
// the server's own no-read/write/idle-timeout design, since a finite
// default here would silently reintroduce exactly the transfer-duration
// cap that design otherwise avoids. When an operator has explicitly
// configured a finite drainTimeout instead, and it is reached before
// every in-flight request finished, that is treated as a deliberate,
// operator-chosen cutoff: srv.Shutdown does not itself force-close the
// connections still active at that point (it never has — see its own
// doc comment), but this function does not wait any further either; it
// logs a clear warning and returns ErrDrainTimeoutExceeded so the
// process exits now, through Execute's own dedicated path for this
// error, rather than looking like a crash. Any other, unexpected
// Shutdown error (not a reached deadline) is still surfaced as a
// generic error, since that is not a condition this function has a
// deliberate story for.
//
// Extracted from runServe specifically so this logic is testable without
// a real OS signal or a real TLS listener — see
// TestServeWithGracefulDrainWaitsForInFlightRequest/
// TestServeWithGracefulDrainExceedsFiniteTimeout.
func serveWithGracefulDrain(ctx context.Context, srv *http.Server, p *proxy.Proxy, drainTimeout time.Duration, listenAndServe func() error, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() { errCh <- listenAndServe() }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining in-flight requests before exiting")
		p.BeginDrain()

		shutdownCtx := context.Background()
		if drainTimeout > 0 {
			var cancel context.CancelFunc
			shutdownCtx, cancel = context.WithTimeout(shutdownCtx, drainTimeout)
			defer cancel()
		}
		// Timed so drain duration is observable — one of the internal
		// operations issue #1 calls out. How long a fleet takes to drain on
		// deploy/rollout is a real operational signal (a rising drain time
		// means longer-running transfers in flight), and previously the
		// clean-drain path logged nothing at all, so an operator couldn't
		// tell a fast drain from a slow one or confirm it completed.
		drainStart := time.Now()
		shutdownErr := srv.Shutdown(shutdownCtx)
		drainDuration := time.Since(drainStart)
		switch {
		case shutdownErr == nil:
			// Fully drained: every in-flight request finished on its own
			// before drainTimeout (if any) elapsed.
			logger.Info("drain complete, all in-flight requests finished", "drainDurationMs", drainDuration.Milliseconds())
		case drainTimeout > 0 && errors.Is(shutdownErr, context.DeadlineExceeded):
			logger.Warn("drainTimeout exceeded before every in-flight request finished; exiting now as a deliberate, operator-configured cutoff rather than waiting further — any connection still active will be terminated when the process exits", "drainTimeout", drainTimeout, "drainDurationMs", drainDuration.Milliseconds())
			shutdownErr = ErrDrainTimeoutExceeded
		default:
			logger.Warn("graceful shutdown did not complete cleanly", "error", shutdownErr, "drainDurationMs", drainDuration.Milliseconds())
		}

		// Shutdown only signals listenAndServe to stop; it doesn't itself
		// return listenAndServe's own error. Waiting for errCh here means
		// this function (and so runServe, and so main()) doesn't report
		// back to the caller while Serve is still unwinding in-flight
		// connections in the background.
		if serveErr := <-errCh; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && shutdownErr == nil {
			return serveErr
		}
		return shutdownErr
	}
}

// buildUpstreams converts config.Upstreams (already validated) into the
// host->baseURL map internal/proxy.New expects, reusing the exact
// *url.URL Validate() already parsed from each BaseURL rather than
// parsing the string a second time — this closes the gap where the URL
// Validate() checked and the URL the proxy actually dials could diverge.
func buildUpstreams(cfg *config.Config) (map[string]*url.URL, error) {
	upstreams := make(map[string]*url.URL, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		parsed := u.ParsedBaseURL()
		if parsed == nil {
			return nil, fmt.Errorf("upstream %q: baseURL was not validated (call Validate() before buildUpstreams)", u.Host)
		}
		upstreams[u.Host] = parsed
	}
	return upstreams, nil
}

// buildCredentialSources converts config.Upstreams (already validated)
// into the host->CredentialSource map internal/proxy.New expects,
// reusing the exact upstream.CredentialSource Validate() already built
// for each Upstream rather than rebuilding it a second time — the same
// reuse-not-reparse pattern buildUpstreams already establishes for
// BaseURL.
func buildCredentialSources(cfg *config.Config) (map[string]upstream.CredentialSource, error) {
	sources := make(map[string]upstream.CredentialSource, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		src := u.CredentialSource()
		if src == nil {
			return nil, fmt.Errorf("upstream %q: credential source was not validated (call Validate() before buildCredentialSources)", u.Host)
		}
		sources[u.Host] = src
	}
	return sources, nil
}

// wireCredentialSourceLoggers installs logger into every
// *upstream.GitHubAppSource found in sources, via SetLogger. Every
// GitHubAppSource in sources was constructed inside config.Validate()
// (called from config.Load, before logger exists — see
// GitHubAppSource.SetLogger's doc comment for why), so without this call
// its security.EventTokenMinted events would go through slog.Default()
// instead of the ScrubHandler-wrapped logger everything else in this
// process logs through. Must run once, at startup, before the proxy
// starts serving traffic — SetLogger is not meant to be called
// concurrently with an in-flight Credentials() call.
func wireCredentialSourceLoggers(sources map[string]upstream.CredentialSource, logger *slog.Logger) {
	for _, src := range sources {
		if gh, ok := src.(*upstream.GitHubAppSource); ok {
			gh.SetLogger(logger)
		}
	}
}

// wireCredentialSourceMetrics installs metrics into every
// *upstream.GitHubAppSource in sources, via SetMetrics — the metrics
// counterpart of wireCredentialSourceLoggers, run for the same reason: the
// sources were built inside config.Validate(), before the telemetry
// pipeline existed. metrics is always non-nil (a disabled Providers still
// carries noop-backed instruments), so a source that gets it simply records
// into no-ops when telemetry is off. StaticSource needs no wiring — it
// never mints and never touches a cache. Must run once, at startup, before
// the proxy serves traffic.
func wireCredentialSourceMetrics(sources map[string]upstream.CredentialSource, metrics *observability.Metrics) {
	for _, src := range sources {
		if gh, ok := src.(*upstream.GitHubAppSource); ok {
			gh.SetMetrics(metrics)
		}
	}
}

// telemetryConfig translates the operator-facing config.TelemetryConfig
// (kept free of any OpenTelemetry-SDK dependency) into the
// observability.Config that Setup consumes. This is the single seam where
// the two representations meet, so config never imports internal/observability
// and internal/observability never parses the YAML file. The OTLP header
// secret is resolved here, from the environment variable named by
// HeadersEnv — never from the YAML — matching how a credential's tokenEnv
// is read, so a bearer token can't end up committed to a config file.
func telemetryConfig(cfg *config.Config) observability.Config {
	var headers map[string]string
	if cfg.Telemetry.HeadersEnv != "" {
		headers = observability.ParseOTLPHeaders(os.Getenv(cfg.Telemetry.HeadersEnv))
	}
	return observability.Config{
		Endpoint: cfg.Telemetry.Endpoint,
		Protocol: cfg.Telemetry.Protocol,
		Headers:  headers,
		Resource: observability.ResourceOptions{
			Environment:      cfg.Telemetry.Environment,
			ServiceNamespace: cfg.Telemetry.ServiceNamespace,
			Version:          version,
		},
	}
}

// instrumentedHandler wraps handler with otelhttp's HTTP-server
// instrumentation (a server span and http.server.* metrics per request)
// when telemetry is enabled, and returns handler unchanged when it is not —
// so a disabled deployment carries none of otelhttp's per-request wrapping
// overhead at all. /healthz is filtered out so load-balancer probes don't
// flood the trace/metric backends with noise. The span name is kept
// low-cardinality (method only; the host-in-path URL carries owner/repo,
// which must not become part of a span name) — the proxy enriches the span
// with haybale.host/verb/outcome attributes from inside ServeHTTP.
func instrumentedHandler(cfg *config.Config, handler http.Handler) http.Handler {
	if !cfg.Telemetry.Enabled() {
		return handler
	}
	return otelhttp.NewHandler(
		handler,
		"haybale.request",
		otelhttp.WithFilter(func(r *http.Request) bool {
			// Trace everything except the load-balancer health probe.
			isHealthz := r.Method == http.MethodGet && r.URL.Path == "/healthz"
			return !isHealthz
		}),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return "haybale.request " + r.Method
		}),
	)
}

// parseLogLevel maps a validated config log level string to a
// slog.Level, defaulting to Info for any value Validate() didn't already
// reject (which should be unreachable in practice). Validate() accepts
// logLevel case-insensitively without normalising the stored value, so
// this lowercases before matching.
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
