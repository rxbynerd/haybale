package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
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

var configPath string

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
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, path string) error {
	cfg, err := config.Load(path)
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
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	logger.Info("starting haybale", "listen", cfg.Listen, "upstreams", len(upstreams))
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "haybale listening on %s\n", cfg.Listen); err != nil {
		return err
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
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
