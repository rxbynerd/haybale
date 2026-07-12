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

	"github.com/rxbynerd/haybale/internal/config"
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
	serveCmd.Flags().StringVar(&drainTimeoutFlag, "drain-timeout", "", `bounds how long graceful shutdown waits for in-flight requests to finish, e.g. "2m" ("0s" for unbounded); overrides drainTimeout in the config file`)
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, path string) error {
	cfg, err := config.Load(path, config.WithTLSOverride(tlsCertPathFlag, tlsKeyPathFlag), config.WithDrainTimeoutOverride(drainTimeoutFlag))
	if err != nil {
		return err
	}

	// ScrubHandler wraps the leaf text handler so any token or credential
	// material that reaches a log call anywhere in haybale — a bug, since
	// every call site should already pass only
	// repo/owner/host/verb/identity — is redacted before it ever leaves
	// the process, rather than relying solely on every call site getting
	// that right.
	logger := slog.New(security.NewScrubHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	})))

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

	// Load already ran Validate(), which populates these from the
	// identity/policy blocks — nil here would indicate a caller bug
	// (Validate() didn't run), not a runtime condition. proxy.New itself
	// rejects a nil authenticator/policyEngine at construction, so that
	// caller bug now surfaces here as an error rather than a panic on
	// the first request.
	p, err := proxy.New(upstreams, credentialSources, cfg.Identity.Authenticator(), cfg.Policy.Engine(), logger)
	if err != nil {
		return fmt.Errorf("build proxy: %w", err)
	}
	srv, listenAndServe, scheme, err := newServer(cfg, p)
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

// serveWithGracefulDrain runs listenAndServe (srv.ListenAndServe or the
// srv.ListenAndServeTLS closure runServe built, already bound to srv)
// until either it returns on its own or ctx is done — a SIGTERM/SIGINT
// runServe's signal.NotifyContext caught. On ctx.Done() it marks p as
// draining (see proxy.Proxy.BeginDrain: /healthz starts returning 503,
// telling a load balancer to stop routing new traffic here), then calls
// srv.Shutdown to stop accepting new connections while letting in-flight
// requests — a large git clone/push in particular — finish streaming to
// completion rather than being cut off mid-transfer. drainTimeout bounds
// how long Shutdown waits for that; <= 0 means wait indefinitely, for
// however long the slowest in-flight transfer takes to finish on its
// own.
//
// Extracted from runServe specifically so this logic is testable without
// a real OS signal or a real TLS listener — see
// TestServeWithGracefulDrainWaitsForInFlightRequest.
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
		shutdownErr := srv.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			logger.Warn("graceful shutdown did not complete cleanly", "error", shutdownErr)
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
