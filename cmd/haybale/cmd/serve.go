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

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))

	upstreams, err := buildUpstreams(cfg)
	if err != nil {
		// Validate() already confirmed every BaseURL parses; a failure
		// here indicates a bug in that invariant rather than a bad
		// config, so it is surfaced rather than silently ignored.
		return fmt.Errorf("build upstreams: %w", err)
	}

	p := proxy.New(upstreams, logger)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	logger.Info("starting haybale", "listen", cfg.Listen, "upstreams", len(upstreams))
	fmt.Fprintf(cmd.OutOrStdout(), "haybale listening on %s\n", cfg.Listen)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// buildUpstreams converts config.Upstreams (already validated) into the
// host->baseURL map internal/proxy.New expects.
func buildUpstreams(cfg *config.Config) (map[string]*url.URL, error) {
	upstreams := make(map[string]*url.URL, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		parsed, err := url.Parse(u.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", u.Host, err)
		}
		upstreams[u.Host] = parsed
	}
	return upstreams, nil
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
