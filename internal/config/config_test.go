package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// fakeTokenDigest is a structurally valid "sha256:<hex>" tokenDigest
// value good enough for exercising config-level validation, which only
// cares that identities.yaml parses and decodes — it never needs to
// correspond to any real token.
const fakeTokenDigest = "sha256:" + "11" + "22" + "33" + "44" + "55" + "66" + "77" + "88" +
	"99" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "00" +
	"11" + "22" + "33" + "44" + "55" + "66" + "77" + "88" +
	"99" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "00"

// testTokenEnv is the environment variable name every config_test.go
// fixture's "static" credential block points tokenEnv at. Every test
// that needs Validate() (or Load()) to succeed sets it via t.Setenv, so
// buildCredentialSource's "environment variable is unset or empty" check
// passes without needing a real upstream credential.
const testTokenEnv = "HAYBALE_CONFIG_TEST_TOKEN" //nolint:gosec // G101: this is an environment-variable name, not a credential value

// testTokenEnvValue is the value testTokenEnv is set to wherever a valid
// static credential is needed; its exact contents are never asserted on.
const testTokenEnvValue = "test-token-value"

// validCredential is a "static" CredentialConfig that Validate()
// succeeds on as long as the test also does t.Setenv(testTokenEnv,
// testTokenEnvValue).
var validCredential = CredentialConfig{Type: credentialTypeStatic, TokenEnv: testTokenEnv}

// writeValidIdentityAndPolicyFiles writes a minimal valid identities.yaml
// and policy.yaml under t.TempDir(), returning their paths. Every
// TestValidate case that isn't itself exercising identity/policy
// validation uses these so the rest of Validate() can be tested in
// isolation.
func writeValidIdentityAndPolicyFiles(t *testing.T) (identityPath, policyPath string) {
	t.Helper()
	dir := t.TempDir()

	identityPath = filepath.Join(dir, "identities.yaml")
	identityContent := "identities:\n  - id: run-1\n    tokenDigest: " + fakeTokenDigest + "\n"
	if err := os.WriteFile(identityPath, []byte(identityContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile(identities.yaml): %v", err)
	}

	policyPath = filepath.Join(dir, "policy.yaml")
	policyContent := "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [read, write]\n"
	if err := os.WriteFile(policyPath, []byte(policyContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile(policy.yaml): %v", err)
	}

	return identityPath, policyPath
}

// writeTestRSAKeyFile generates a throwaway RSA private key (never
// committed anywhere — generated fresh every test run) and writes it PEM
// -encoded to a file under t.TempDir(), returning its path. Good enough
// to exercise "github-app" credential validation, which only cares that
// the file exists and parses as an RSA key.
func writeTestRSAKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("os.WriteFile(app.pem): %v", err)
	}
	return path
}

// newFakeGitHubAppServer stands up a minimal httptest stand-in for the
// two GitHub REST endpoints upstream.GitHubAppSource calls: installation
// lookup and scoped-token mint. It always resolves to installationID and
// always mints token, regardless of the requested repo/permissions —
// good enough to prove Validate() wires a github-app credential block
// into a CredentialSource that actually mints, not to re-test
// GitHubAppSource's own least-privilege scoping (internal/upstream's own
// tests already cover that in depth).
func newFakeGitHubAppServer(t *testing.T, installationID int64, token string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id": %d}`, installationID)
	})
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token": %q, "expires_at": %q}`, token, time.Now().Add(time.Hour).Format(time.RFC3339))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestValidate(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	validUpstream := Upstream{Host: "github.com", BaseURL: "https://github.com", Credential: validCredential}

	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr string // substring expected in the error; "" means no error
	}{
		{
			name: "valid minimal config",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
		},
		{
			name: "log level is case-insensitive",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "DEBUG",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
		},
		{
			name: "unknown log level",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "verbose",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "logLevel",
		},
		{
			name: "no upstreams",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
				}
			},
			wantErr: "at least one upstream",
		},
		{
			name: "upstream missing host",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{{BaseURL: "https://github.com"}},
				}
			},
			wantErr: "host is required",
		},
		{
			name: "upstream missing baseURL",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{{Host: "github.com"}},
				}
			},
			wantErr: "baseURL is required",
		},
		{
			name: "upstream baseURL missing scheme",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{{Host: "github.com", BaseURL: "github.com"}},
				}
			},
			wantErr: "must be an absolute URL",
		},
		{
			name: "upstream baseURL is unparseable",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					// An unterminated IPv6 literal: url.Parse rejects this
					// outright (not merely "no scheme"), exercising the
					// url.Parse error branch Validate()'s doc comment
					// promises to reject but which had no test coverage.
					Upstreams: []Upstream{{Host: "github.com", BaseURL: "http://[::1"}},
				}
			},
			wantErr: "not a valid URL",
		},
		{
			name: "duplicate upstream host",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: validCredential},
						{Host: "github.com", BaseURL: "https://github.example.com", Credential: validCredential},
					},
				}
			},
			wantErr: "duplicate host",
		},
		{
			name: "credential type empty",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{{Host: "github.com", BaseURL: "https://github.com"}},
				}
			},
			wantErr: "credential: type",
		},
		{
			name: "credential type unsupported",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{Type: "ldap"}},
					},
				}
			},
			wantErr: "credential: type",
		},
		{
			name: "credential inline token rejected",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeStatic, TokenEnv: testTokenEnv, Token: "inline-secret-value",
						}},
					},
				}
			},
			wantErr: "inline token is not supported",
		},
		{
			name: "credential static missing tokenEnv",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{Type: credentialTypeStatic}},
					},
				}
			},
			wantErr: "tokenEnv is required",
		},
		{
			name: "credential static tokenEnv unset",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{ //nolint:gosec // G101: TokenEnv below is an environment-variable name (deliberately never set), not a credential value
							Type: credentialTypeStatic, TokenEnv: "HAYBALE_CONFIG_TEST_DEFINITELY_UNSET",
						}},
					},
				}
			},
			wantErr: "is unset or empty",
		},
		{
			name: "credential github-app missing appID",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeGitHubApp, PrivateKeyPath: "/tmp/app.pem",
						}},
					},
				}
			},
			wantErr: "appID is required",
		},
		{
			name: "credential github-app missing privateKeyPath",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeGitHubApp, AppID: 12345,
						}},
					},
				}
			},
			wantErr: "privateKeyPath is required",
		},
		{
			name: "credential github-app privateKeyPath does not exist",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeGitHubApp, AppID: 12345, PrivateKeyPath: "/tmp/haybale-config-test-does-not-exist.pem",
						}},
					},
				}
			},
			wantErr: "read privateKeyPath",
		},
		{
			name: "credential github-app privateKeyPath is not a valid RSA key",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				badKeyPath := filepath.Join(t.TempDir(), "not-a-key.pem")
				if err := os.WriteFile(badKeyPath, []byte("this is not a PEM-encoded key"), 0o600); err != nil {
					t.Fatalf("os.WriteFile: %v", err)
				}
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeGitHubApp, AppID: 12345, PrivateKeyPath: badKeyPath,
						}},
					},
				}
			},
			wantErr: "parse private key",
		},
		{
			name: "credential github-app valid shape",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:   ":8466",
					LogLevel: "info",
					Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:   PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{
						{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
							Type: credentialTypeGitHubApp, AppID: 12345, PrivateKeyPath: writeTestRSAKeyFile(t),
						}},
					},
				}
			},
			// A real (throwaway, in-test-generated) RSA key: Validate()
			// both reads the file and builds a working GitHubAppSource
			// from it — see TestValidatePopulatesGitHubAppCredentialSource
			// below for the fuller "it actually mints" assertion.
		},
		{
			name: "identity type empty",
			cfg: func(t *testing.T) Config {
				_, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "identity: type",
		},
		{
			name: "identity type unsupported",
			cfg: func(t *testing.T) Config {
				identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: "ldap", Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "identity: type",
		},
		{
			name: "identity path empty",
			cfg: func(t *testing.T) Config {
				_, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "identity: path is required",
		},
		{
			name: "identity path does not exist",
			cfg: func(t *testing.T) Config {
				_, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: filepath.Join(t.TempDir(), "nope.yaml")},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "identity:",
		},
		{
			name: "identity file fails its own validation",
			cfg: func(t *testing.T) Config {
				dir := t.TempDir()
				identityPath := filepath.Join(dir, "identities.yaml")
				if err := os.WriteFile(identityPath, []byte("identities: []\n"), 0o600); err != nil {
					t.Fatalf("os.WriteFile: %v", err)
				}
				_, policyPath := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "at least one identity",
		},
		{
			name: "policy path empty",
			cfg: func(t *testing.T) Config {
				identityPath, _ := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "policy: path is required",
		},
		{
			name: "policy path does not exist",
			cfg: func(t *testing.T) Config {
				identityPath, _ := writeValidIdentityAndPolicyFiles(t)
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: filepath.Join(t.TempDir(), "nope.yaml")},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: "policy:",
		},
		{
			name: "policy file fails its own validation",
			cfg: func(t *testing.T) Config {
				identityPath, _ := writeValidIdentityAndPolicyFiles(t)
				dir := t.TempDir()
				policyPath := filepath.Join(dir, "policy.yaml")
				badPolicy := "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [admin]\n"
				if err := os.WriteFile(policyPath, []byte(badPolicy), 0o600); err != nil {
					t.Fatalf("os.WriteFile: %v", err)
				}
				return Config{
					Listen:    ":8466",
					LogLevel:  "info",
					Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
					Policy:    PolicyConfig{Path: policyPath},
					Upstreams: []Upstream{validUpstream},
				}
			},
			wantErr: `must be "read" or "write"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg(t)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil error, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidatePopulatesParsedBaseURL(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	cfg := Config{
		Listen:   ":8466",
		LogLevel: "info",
		Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
		Policy:   PolicyConfig{Path: policyPath},
		Upstreams: []Upstream{
			{Host: "github.com", BaseURL: "https://github.com:8443", Credential: validCredential},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	parsed := cfg.Upstreams[0].ParsedBaseURL()
	if parsed == nil {
		t.Fatal("ParsedBaseURL() = nil after successful Validate()")
	}
	if got := parsed.String(); got != "https://github.com:8443" {
		t.Errorf("ParsedBaseURL().String() = %q, want %q", got, "https://github.com:8443")
	}
}

func TestValidatePopulatesAuthenticatorAndEngine(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	cfg := Config{
		Listen:    ":8466",
		LogLevel:  "info",
		Identity:  IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
		Policy:    PolicyConfig{Path: policyPath},
		Upstreams: []Upstream{{Host: "github.com", BaseURL: "https://github.com", Credential: validCredential}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	if cfg.Identity.Authenticator() == nil {
		t.Error("Identity.Authenticator() = nil after successful Validate()")
	}
	if cfg.Policy.Engine() == nil {
		t.Error("Policy.Engine() = nil after successful Validate()")
	}
}

// TestValidatePopulatesCredentialSource asserts Validate() builds a
// working upstream.CredentialSource for a "static" credential block,
// including the defaultStaticUsername fallback when Username is left
// empty.
func TestValidatePopulatesCredentialSource(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	cfg := Config{
		Listen:   ":8466",
		LogLevel: "info",
		Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
		Policy:   PolicyConfig{Path: policyPath},
		Upstreams: []Upstream{
			{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
				Type: credentialTypeStatic, TokenEnv: testTokenEnv,
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	src := cfg.Upstreams[0].CredentialSource()
	if src == nil {
		t.Fatal("CredentialSource() = nil after successful Validate()")
	}
	cred, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	if err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if cred.Username != defaultStaticUsername {
		t.Errorf("Credentials().Username = %q, want default %q", cred.Username, defaultStaticUsername)
	}
	if cred.Password != testTokenEnvValue {
		t.Errorf("Credentials().Password = %q, want the tokenEnv value %q", cred.Password, testTokenEnvValue)
	}
}

// TestValidatePopulatesGitHubAppCredentialSource mirrors
// TestValidatePopulatesCredentialSource for the "github-app" discriminator:
// Validate() must build a genuine upstream.GitHubAppSource that mints a
// real (fake-upstream-backed) installation token, not merely accept the
// config shape structurally. APIBaseURL points at a local httptest fake
// standing in for the GitHub REST API — internal/upstream's own tests
// cover GitHubAppSource's least-privilege scoping and cache behavior in
// depth; this test only proves config.Validate() wires everything
// together correctly.
func TestValidatePopulatesGitHubAppCredentialSource(t *testing.T) {
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	fakeURL := newFakeGitHubAppServer(t, 999, "fake-minted-installation-token")
	cfg := Config{
		Listen:   ":8466",
		LogLevel: "info",
		Identity: IdentityConfig{Type: identityTypeStaticTokenFile, Path: identityPath},
		Policy:   PolicyConfig{Path: policyPath},
		Upstreams: []Upstream{
			{Host: "github.com", BaseURL: "https://github.com", Credential: CredentialConfig{
				Type: credentialTypeGitHubApp, AppID: 12345, PrivateKeyPath: writeTestRSAKeyFile(t), APIBaseURL: fakeURL,
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	src := cfg.Upstreams[0].CredentialSource()
	if src == nil {
		t.Fatal("CredentialSource() = nil after successful Validate()")
	}
	if _, ok := src.(*upstream.GitHubAppSource); !ok {
		t.Fatalf("CredentialSource() = %T, want *upstream.GitHubAppSource", src)
	}
	cred, err := src.Credentials(context.Background(), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
	if err != nil {
		t.Fatalf("Credentials() unexpected error: %v", err)
	}
	if cred.Username != "x-access-token" {
		t.Errorf("Credentials().Username = %q, want %q", cred.Username, "x-access-token")
	}
	if cred.Password != "fake-minted-installation-token" {
		t.Errorf("Credentials().Password = %q, want the fake's minted token", cred.Password)
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := Config{
		Upstreams: []Upstream{{Host: "github.com", BaseURL: "https://github.com"}},
	}
	cfg.applyDefaults()

	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, defaultLogLevel)
	}
}

func TestApplyDefaultsDoesNotOverrideExplicitValues(t *testing.T) {
	cfg := Config{
		Listen:   "127.0.0.1:9000",
		LogLevel: "debug",
	}
	cfg.applyDefaults()

	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen = %q, want unchanged %q", cfg.Listen, "127.0.0.1:9000")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want unchanged %q", cfg.LogLevel, "debug")
	}
}

func TestLoad(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	dir := t.TempDir()
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	path := filepath.Join(dir, "haybale.yaml")
	yamlContent := `
listen: ":9999"
logLevel: warn
identity:
  type: static-token-file
  path: ` + identityPath + `
policy:
  path: ` + policyPath + `
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential: { type: static, tokenEnv: ` + testTokenEnv + ` }
  - host: git.internal.example
    baseURL: https://git.internal.example
    credential: { type: static, username: git, tokenEnv: ` + testTokenEnv + ` }
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9999")
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("len(Upstreams) = %d, want 2", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Host != "github.com" || cfg.Upstreams[0].BaseURL != "https://github.com" {
		t.Errorf("Upstreams[0] = %+v, want {github.com https://github.com}", cfg.Upstreams[0])
	}
	if cfg.Upstreams[0].CredentialSource() == nil {
		t.Error("Upstreams[0].CredentialSource() = nil after Load()")
	}
	if cfg.Upstreams[1].CredentialSource() == nil {
		t.Error("Upstreams[1].CredentialSource() = nil after Load()")
	}
	if cfg.Identity.Authenticator() == nil {
		t.Error("Identity.Authenticator() = nil after Load()")
	}
	if cfg.Policy.Engine() == nil {
		t.Error("Policy.Engine() = nil after Load()")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Setenv(testTokenEnv, testTokenEnvValue)
	dir := t.TempDir()
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	path := filepath.Join(dir, "haybale.yaml")
	yamlContent := `
identity:
  type: static-token-file
  path: ` + identityPath + `
policy:
  path: ` + policyPath + `
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential: { type: static, tokenEnv: ` + testTokenEnv + ` }
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, defaultLogLevel)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	// No upstreams: Validate() must fail, and Load() must surface it.
	// Also omits identity/policy blocks, but the missing-upstreams error
	// is checked first in Validate() only because it's asserted here —
	// the point of this test is that Load() propagates whatever error
	// Validate() returns, not which specific error fires first.
	if err := os.WriteFile(path, []byte("listen: \":8466\"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error, want error for a config with no upstreams")
	}
	if !strings.Contains(err.Error(), "at least one upstream") {
		t.Fatalf("Load() error = %q, want substring %q", err.Error(), "at least one upstream")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load() = nil error, want error for a missing file")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haybale.yaml")
	if err := os.WriteFile(path, []byte("listen: [this is not valid yaml for a string field\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error, want error for malformed YAML")
	}
}
