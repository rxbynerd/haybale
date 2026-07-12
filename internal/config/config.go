// Package config loads and validates haybale's YAML configuration file
// (haybale serve --config haybale.yaml).
//
// Validate() is fail-fast: it is called once at startup (Load does this
// automatically) so a misconfigured deployment refuses to serve traffic
// rather than failing unpredictably on the first request. This includes
// the identity and policy blocks: Validate() doesn't just check their
// paths are non-empty, it loads and parses the files at those paths (via
// internal/identity and internal/policy), so a malformed identities.yaml
// or policy.yaml fails startup exactly like a bad upstream baseURL does.
// Each Upstream also carries a credential block (Upstream.Credential),
// validated and built into an upstream.CredentialSource the same way —
// see buildCredentialSource.
package config

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/upstream"
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
	// Identity configures how haybale authenticates inbound requests.
	Identity IdentityConfig `yaml:"identity"`
	// Policy configures how haybale authorizes an authenticated
	// request.
	Policy PolicyConfig `yaml:"policy"`
	// Upstreams lists the git hosts haybale proxies to, keyed by the
	// first path segment of the host-in-path URL scheme
	// (/{host}/{owner}/{repo}.git/<endpoint>).
	Upstreams []Upstream `yaml:"upstreams"`
}

// identityTypeStaticTokenFile is the only Identity.Type value v0.1
// supports: a static, file-backed set of identity -> token-digest
// mappings (internal/identity.StaticTokenAuthenticator).
const identityTypeStaticTokenFile = "static-token-file"

// IdentityConfig selects and configures haybale's identity.Authenticator.
type IdentityConfig struct {
	// Type is a discriminator selecting which Authenticator
	// implementation to build; the only supported value in v0.1 is
	// "static-token-file".
	Type string `yaml:"type"`
	// Path is the identities.yaml file Validate() loads the
	// Authenticator from, when Type is "static-token-file".
	Path string `yaml:"path"`

	// authenticator caches the identity.Authenticator Validate() built
	// from Path, so callers (cmd/haybale/cmd/serve.go in particular)
	// reuse that exact value instead of re-parsing Path — the same
	// pattern Upstream.parsedBaseURL/ParsedBaseURL already establishes.
	authenticator identity.Authenticator
}

// Authenticator returns the identity.Authenticator a prior successful
// call to Validate() built from Path, or nil if Validate() has not yet
// run (or did not return nil) for this IdentityConfig.
func (c IdentityConfig) Authenticator() identity.Authenticator {
	return c.authenticator
}

// PolicyConfig configures haybale's policy.Engine.
type PolicyConfig struct {
	// Path is the policy.yaml file Validate() loads the Engine from.
	Path string `yaml:"path"`

	// engine caches the policy.Engine Validate() built from Path, for
	// the same reuse-not-reparse reason IdentityConfig.authenticator
	// does.
	engine policy.Engine
}

// Engine returns the policy.Engine a prior successful call to
// Validate() built from Path, or nil if Validate() has not yet run (or
// did not return nil) for this PolicyConfig.
func (c PolicyConfig) Engine() policy.Engine {
	return c.engine
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
	// Credential configures the upstream.CredentialSource this
	// upstream's requests are authenticated with.
	Credential CredentialConfig `yaml:"credential"`

	// parsedBaseURL caches the *url.URL Validate() parsed from BaseURL
	// while checking well-formedness, so callers building the map
	// internal/proxy.New consumes (buildUpstreams in
	// cmd/haybale/cmd/serve.go) reuse that exact parse via ParsedBaseURL
	// instead of independently re-parsing BaseURL — one parse, one
	// source of truth for what "the upstream's URL" means.
	parsedBaseURL *url.URL

	// credentialSource caches the upstream.CredentialSource Validate()
	// built from Credential, for the same reuse-not-rebuild reason
	// parsedBaseURL exists.
	credentialSource upstream.CredentialSource
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

// CredentialSource returns the upstream.CredentialSource a prior
// successful call to Validate() built from Credential, or nil if
// Validate() has not yet run (or did not return nil) for this Upstream.
// Every production config flows through Load (which always calls
// Validate) before this is read, so a nil result at that point indicates
// a caller bug, not a runtime condition.
func (u Upstream) CredentialSource() upstream.CredentialSource {
	return u.credentialSource
}

// credentialTypeStatic selects a fixed, operator-configured upstream
// credential (upstream.StaticSource): CredentialConfig.Username and the
// secret named by CredentialConfig.TokenEnv.
const credentialTypeStatic = "static"

// credentialTypeGitHubApp selects a GitHub App installation-token
// credential. The config shape (AppID, PrivateKeyPath, APIBaseURL) is
// validated structurally here in M3 so operators can write a
// forward-compatible haybale.yaml now, but no upstream.CredentialSource
// actually mints installation tokens yet — that's M4's GitHubAppSource.
// Until M4 lands, a "github-app" upstream's CredentialSource is a stub
// that always errors (mapped to 502 by internal/proxy, same as any other
// credential-source failure), rather than this package half-building
// GitHubAppSource's mint/cache logic ahead of that milestone.
const credentialTypeGitHubApp = "github-app" //nolint:gosec // G101: this is a config-type discriminator string, not a credential value

// defaultStaticUsername is the Basic-auth username a "static" credential
// uses when Username is left empty in the YAML. x-access-token is
// GitHub's own convention for presenting a token as a Basic-auth
// password (see credentialTypeGitHubApp) and works equally well against
// any upstream that, like git-http-backend, ignores the username
// entirely and checks only the password.
const defaultStaticUsername = "x-access-token"

// CredentialConfig selects and configures the upstream.CredentialSource
// an Upstream's requests are authenticated with.
type CredentialConfig struct {
	// Type is a discriminator selecting which CredentialSource
	// implementation to build: "static" or "github-app".
	Type string `yaml:"type"`
	// Username is the Basic-auth username a "static" credential
	// presents. Defaults to "x-access-token" when empty.
	Username string `yaml:"username"`
	// TokenEnv names the environment variable Validate() reads a
	// "static" credential's secret from. The secret is never written
	// inline in YAML — see Token below.
	TokenEnv string `yaml:"tokenEnv"`
	// Token must never be set: it exists only so Validate() can detect
	// and reject an inline token in YAML with a clear error, rather than
	// silently ignoring an unrecognised field. A credential's secret
	// must always come from the environment variable named by TokenEnv,
	// never committed to a config file.
	Token string `yaml:"token"`
	// AppID is the GitHub App ID a "github-app" credential authenticates
	// as. Structurally validated in M3; not yet used to mint anything.
	AppID int64 `yaml:"appID"`
	// PrivateKeyPath is the path to the GitHub App's PEM private key.
	// Structurally validated in M3; not yet used to mint anything.
	PrivateKeyPath string `yaml:"privateKeyPath"`
	// APIBaseURL overrides the GitHub API base URL for GHES deployments,
	// e.g. "https://ghe.example.com/api/v3". Defaults to
	// "https://api.github.com" when empty. Structurally validated in M3;
	// not yet used to mint anything.
	APIBaseURL string `yaml:"apiBaseURL"`
}

// Load reads and parses the YAML file at path, applies defaults, and
// validates the result. It returns an error immediately if the config is
// invalid — callers should treat any error here as fatal at startup.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is the operator-supplied --config flag value, not attacker input
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
// with a missing host or an unparseable/relative BaseURL, two upstreams
// sharing the same Host key (which would make routing ambiguous), an
// unsupported or unconfigured Identity, or an Identity/Policy file that
// is missing, malformed, or otherwise fails its own package's
// validation.
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

		if err := buildCredentialSource(i, u); err != nil {
			return err
		}
	}

	switch c.Identity.Type {
	case identityTypeStaticTokenFile:
		if c.Identity.Path == "" {
			return fmt.Errorf("identity: path is required for type %q", identityTypeStaticTokenFile)
		}
		auth, err := identity.LoadStaticTokenAuthenticator(c.Identity.Path)
		if err != nil {
			// LoadStaticTokenAuthenticator's own errors are already
			// prefixed "identity: ...", so returning err directly (not
			// wrapping it again) avoids a doubled prefix.
			return err
		}
		c.Identity.authenticator = auth
	default:
		return fmt.Errorf("identity: type %q is not supported (must be %q)", c.Identity.Type, identityTypeStaticTokenFile)
	}

	if c.Policy.Path == "" {
		return fmt.Errorf("policy: path is required")
	}
	engine, err := policy.LoadGlobEngine(c.Policy.Path)
	if err != nil {
		// LoadGlobEngine's own errors are already prefixed "policy:
		// ...", so returning err directly (not wrapping it again)
		// avoids a doubled prefix.
		return err
	}
	c.Policy.engine = engine

	return nil
}

// buildCredentialSource validates u.Credential and, on success, builds
// the upstream.CredentialSource it describes into u.credentialSource.
// i is the upstream's index, used only to prefix error messages the same
// way the rest of Validate() does.
func buildCredentialSource(i int, u *Upstream) error {
	prefix := fmt.Sprintf("upstreams[%d] (host %q): credential", i, u.Host)

	if u.Credential.Token != "" {
		// An inline token is rejected outright, not merely ignored: a
		// config file is far more likely to end up in version control,
		// a support bundle, or an operator's shell history than the
		// environment variable TokenEnv points at, so silently accepting
		// (and ignoring) an inline token would leave an operator
		// believing a config-committed secret is "the intended way" to
		// set one.
		return fmt.Errorf("%s: inline token is not supported; set tokenEnv to an environment variable name instead", prefix)
	}

	switch u.Credential.Type {
	case credentialTypeStatic:
		if u.Credential.TokenEnv == "" {
			return fmt.Errorf("%s: tokenEnv is required for type %q", prefix, credentialTypeStatic)
		}
		token := os.Getenv(u.Credential.TokenEnv)
		if token == "" {
			return fmt.Errorf("%s: environment variable %q (tokenEnv) is unset or empty", prefix, u.Credential.TokenEnv)
		}
		username := u.Credential.Username
		if username == "" {
			username = defaultStaticUsername
		}
		src, err := upstream.NewStaticSource(username, token)
		if err != nil {
			// NewStaticSource's own errors are already prefixed
			// "upstream: ...", so wrap rather than replace them.
			return fmt.Errorf("%s: %w", prefix, err)
		}
		u.credentialSource = src

	case credentialTypeGitHubApp:
		if u.Credential.AppID == 0 {
			return fmt.Errorf("%s: appID is required for type %q", prefix, credentialTypeGitHubApp)
		}
		if u.Credential.PrivateKeyPath == "" {
			return fmt.Errorf("%s: privateKeyPath is required for type %q", prefix, credentialTypeGitHubApp)
		}
		// The shape is validated; the behaviour is not implemented until
		// M4 (GitHubAppSource: ghinstallation JWT + scoped mint +
		// tokenCache). A stub CredentialSource keeps this upstream usable
		// by config.Validate() and internal/proxy's construction-time
		// contracts without half-building that milestone's mint/cache
		// logic here — any attempt to actually use it at request time
		// fails the same way any other credential-source error does: 502,
		// never 401 (see internal/proxy.ServeHTTP).
		u.credentialSource = notImplementedCredentialSource{}

	default:
		return fmt.Errorf("%s: type %q is not supported (must be %q or %q)", prefix, u.Credential.Type, credentialTypeStatic, credentialTypeGitHubApp)
	}

	return nil
}

// notImplementedCredentialSource is the credentialTypeGitHubApp stub:
// every call fails with a fixed, non-sensitive error until M4 replaces
// it with a real GitHubAppSource.
type notImplementedCredentialSource struct{}

func (notImplementedCredentialSource) Credentials(context.Context, gitproto.Repo, gitproto.Verb) (upstream.BasicAuth, error) {
	return upstream.BasicAuth{}, errGitHubAppNotImplemented
}

// errGitHubAppNotImplemented is returned by notImplementedCredentialSource.
var errGitHubAppNotImplemented = errors.New("config: credential type \"github-app\" is not yet implemented")
