// Package config loads and validates haybale's YAML configuration file
// (haybale serve --config haybale.yaml).
//
// Validate() is fail-fast: it is called once at startup (Load does this
// automatically) so a misconfigured deployment refuses to serve traffic
// rather than failing unpredictably on the first request. The shape here
// covers only what M1 needs (listen address, log level, upstreams); M2
// and M3 add identity and policy blocks alongside Upstream without
// restructuring what's here.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultListen is used when Listen is left empty in the YAML.
const defaultListen = ":8466"

// defaultLogLevel is used when LogLevel is left empty in the YAML.
const defaultLogLevel = "info"

// validLogLevels is the closed set of log/slog levels haybale accepts.
var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

// Config is haybale's top-level configuration.
type Config struct {
	// Listen is the address the proxy's HTTP server binds to, e.g.
	// ":8466". Defaults to ":8466" when empty.
	Listen string `yaml:"listen"`
	// LogLevel is one of debug|info|warn|error. Defaults to "info" when
	// empty.
	LogLevel string `yaml:"logLevel"`
	// Upstreams lists the git hosts haybale proxies to, keyed by the
	// first path segment of the host-in-path URL scheme
	// (/{host}/{owner}/{repo}.git/<endpoint>).
	Upstreams []Upstream `yaml:"upstreams"`
}

// Upstream is one upstream git host haybale can proxy requests to.
type Upstream struct {
	// Host is the path-segment key clients use to select this upstream,
	// e.g. "github.com". Need not match BaseURL's hostname — this is
	// what makes BaseURL an injectable seam (the e2e harness points it
	// at an httptest server under an arbitrary Host key).
	Host string `yaml:"host"`
	// BaseURL is the upstream's base URL that requests are rewritten
	// against, e.g. "https://github.com".
	BaseURL string `yaml:"baseURL"`

	// parsedBaseURL caches the *url.URL Validate() parsed from BaseURL
	// while checking well-formedness, so callers building the map
	// internal/proxy.New consumes (buildUpstreams in
	// cmd/haybale/cmd/serve.go) reuse that exact parse via ParsedBaseURL
	// instead of independently re-parsing BaseURL — one parse, one
	// source of truth for what "the upstream's URL" means.
	parsedBaseURL *url.URL
}

// ParsedBaseURL returns the *url.URL a prior successful call to
// Validate() parsed from BaseURL, or nil if Validate() has not yet run
// (or did not return nil) for this Upstream. Every production config
// flows through Load (which always calls Validate) before this is read,
// so a nil result at that point indicates a caller bug, not a runtime
// condition.
func (u Upstream) ParsedBaseURL() *url.URL {
	return u.parsedBaseURL
}

// Load reads and parses the YAML file at path, applies defaults, and
// validates the result. It returns an error immediately if the config is
// invalid — callers should treat any error here as fatal at startup.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &cfg, nil
}

// applyDefaults fills in Listen and LogLevel when left empty.
func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
}

// Validate fail-fasts on anything that would make Config unusable at
// startup: an unrecognised log level, no upstreams at all, an upstream
// with a missing host or an unparseable/relative BaseURL, or two
// upstreams sharing the same Host key (which would make routing
// ambiguous).
func (c *Config) Validate() error {
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("logLevel %q is not one of debug, info, warn, error", c.LogLevel)
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("upstreams: at least one upstream is required")
	}

	seen := make(map[string]bool, len(c.Upstreams))
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Host == "" {
			return fmt.Errorf("upstreams[%d]: host is required", i)
		}
		if seen[u.Host] {
			return fmt.Errorf("upstreams[%d]: duplicate host %q", i, u.Host)
		}
		seen[u.Host] = true

		if u.BaseURL == "" {
			return fmt.Errorf("upstreams[%d] (host %q): baseURL is required", i, u.Host)
		}
		parsed, err := url.Parse(u.BaseURL)
		if err != nil {
			return fmt.Errorf("upstreams[%d] (host %q): baseURL %q is not a valid URL: %w", i, u.Host, u.BaseURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("upstreams[%d] (host %q): baseURL %q must be an absolute URL with scheme and host", i, u.Host, u.BaseURL)
		}
		u.parsedBaseURL = parsed
	}

	return nil
}
