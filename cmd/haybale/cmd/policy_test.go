package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

func TestParsePolicyCheckRepo(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    gitproto.Repo
		wantErr string
	}{
		{
			name: "well formed",
			raw:  "github.com/acme/widgets",
			want: gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
		},
		{
			name: "trailing .git stripped",
			raw:  "github.com/acme/widgets.git",
			want: gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
		},
		{
			name:    "too few segments",
			raw:     "github.com/acme",
			wantErr: "must be host/owner/repo",
		},
		{
			name:    "too many segments",
			raw:     "github.com/acme/widgets/extra",
			wantErr: "must be host/owner/repo",
		},
		{
			name:    "empty host segment",
			raw:     "/acme/widgets",
			wantErr: "no empty segment",
		},
		{
			name:    "empty repo segment",
			raw:     "github.com/acme/",
			wantErr: "no empty segment",
		},
		{
			name:    "repo segment is only .git",
			raw:     "github.com/acme/.git",
			wantErr: "must not be empty after stripping .git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePolicyCheckRepo(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parsePolicyCheckRepo(%q) = nil error, want error containing %q", tt.raw, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parsePolicyCheckRepo(%q) error = %q, want substring %q", tt.raw, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePolicyCheckRepo(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("parsePolicyCheckRepo(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParsePolicyCheckVerb(t *testing.T) {
	tests := []struct {
		raw     string
		want    gitproto.Verb
		wantErr bool
	}{
		{raw: "read", want: gitproto.Read},
		{raw: "write", want: gitproto.Write},
		{raw: "READ", wantErr: true}, // case-sensitive: matches gitproto's own service= values
		{raw: "delete", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parsePolicyCheckVerb(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePolicyCheckVerb(%q) = nil error, want an error", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePolicyCheckVerb(%q) unexpected error: %v", tt.raw, err)
		}
		if got != tt.want {
			t.Errorf("parsePolicyCheckVerb(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

// writePolicyCheckTestConfig writes a minimal but complete haybale.yaml
// (plus the identities.yaml/policy.yaml it references) under t.TempDir(),
// with policyRulesYAML spliced in as policy.yaml's "rules:" body, and
// returns the haybale.yaml path. Sets a throwaway tokenEnv value via
// t.Setenv so the "static" upstream credential block validates.
func writePolicyCheckTestConfig(t *testing.T, policyRulesYAML string) string {
	t.Helper()
	const tokenEnv = "HAYBALE_POLICY_CHECK_TEST_TOKEN" //nolint:gosec // G101: this is an environment-variable *name*, not a credential value
	t.Setenv(tokenEnv, "test-token-value")

	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyRulesYAML), 0o600); err != nil {
		t.Fatalf("os.WriteFile(policy.yaml): %v", err)
	}

	// The jwksFile deliberately need not exist: `haybale policy check`
	// loads the config offline, and identity validation is structural (it
	// never fetches or reads the JWKS — that is BuildAuthenticator's job,
	// which policy check never invokes). This is exactly the offline path
	// keeping the JWKS fetch out of Validate() is designed to protect.
	jwksPath := filepath.Join(dir, "jwks.json")
	haybalePath := filepath.Join(dir, "haybale.yaml")
	haybaleContent := `
identity:
  type: jwt
  issuers:
    - issuer: https://issuer.example
      jwksFile: ` + jwksPath + `
      audiences: [https://haybale.internal]
      identityTemplate: "{sub}"
policy:
  path: ` + policyPath + `
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential: { type: static, tokenEnv: ` + tokenEnv + ` }
`
	if err := os.WriteFile(haybalePath, []byte(haybaleContent), 0o600); err != nil {
		t.Fatalf("os.WriteFile(haybale.yaml): %v", err)
	}
	return haybalePath
}

func TestRunPolicyCheckAllow(t *testing.T) {
	cfgPath := writePolicyCheckTestConfig(t, "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [read, write]\n")

	cmd := newTestCommand()
	if err := runPolicyCheck(cmd, cfgPath, "run-1", "github.com/acme/widgets", "read"); err != nil {
		t.Fatalf("runPolicyCheck() unexpected error: %v", err)
	}

	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	if !strings.HasPrefix(out, "ALLOW:") {
		t.Errorf("output = %q, want it to start with ALLOW:", out)
	}
	if !strings.Contains(out, "identity=run-1 repo=github.com/acme/widgets verb=read") {
		t.Errorf("output = %q, want it to describe the checked identity/repo/verb", out)
	}
}

func TestRunPolicyCheckDenyRuleMatchedButVerbNotGranted(t *testing.T) {
	cfgPath := writePolicyCheckTestConfig(t, "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [read]\n")

	cmd := newTestCommand()
	if err := runPolicyCheck(cmd, cfgPath, "run-1", "github.com/acme/widgets", "write"); err != nil {
		t.Fatalf("runPolicyCheck() unexpected error: %v", err)
	}

	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	if !strings.HasPrefix(out, "DENY:") {
		t.Errorf("output = %q, want it to start with DENY:", out)
	}
	if !strings.Contains(out, "matched rule: identities=") {
		t.Errorf("output = %q, want it to name the matched rule (not \"none\")", out)
	}
}

func TestRunPolicyCheckDenyDefaultDeny(t *testing.T) {
	cfgPath := writePolicyCheckTestConfig(t, "rules: []\n")

	cmd := newTestCommand()
	if err := runPolicyCheck(cmd, cfgPath, "run-1", "github.com/acme/widgets", "read"); err != nil {
		t.Fatalf("runPolicyCheck() unexpected error: %v", err)
	}

	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	if !strings.HasPrefix(out, "DENY:") {
		t.Errorf("output = %q, want it to start with DENY:", out)
	}
	if !strings.Contains(out, "matched rule: none (default deny)") {
		t.Errorf("output = %q, want it to report no matching rule", out)
	}
}

func TestRunPolicyCheckInvalidRepoOrVerbNeverLoadsConfig(t *testing.T) {
	// A config path that does not exist: if runPolicyCheck reached
	// config.Load with it, the error would be a "config: read ..."
	// failure rather than the --repo/--verb parsing error this test
	// asserts on — proving invalid --repo/--verb is rejected before any
	// file I/O happens.
	const missingConfigPath = "/nonexistent/haybale.yaml"

	cmd := newTestCommand()
	err := runPolicyCheck(cmd, missingConfigPath, "run-1", "not-a-valid-repo", "read")
	if err == nil {
		t.Fatal("runPolicyCheck() = nil error, want error for a malformed --repo")
	}
	if !strings.Contains(err.Error(), "must be host/owner/repo") {
		t.Errorf("error = %q, want the --repo parsing error, not a config-load error", err.Error())
	}

	err = runPolicyCheck(cmd, missingConfigPath, "run-1", "github.com/acme/widgets", "delete")
	if err == nil {
		t.Fatal("runPolicyCheck() = nil error, want error for a malformed --verb")
	}
	if !strings.Contains(err.Error(), `must be "read" or "write"`) {
		t.Errorf("error = %q, want the --verb parsing error, not a config-load error", err.Error())
	}
}

func TestRunPolicyCheckPropagatesConfigLoadError(t *testing.T) {
	cmd := newTestCommand()
	err := runPolicyCheck(cmd, filepath.Join(t.TempDir(), "does-not-exist.yaml"), "run-1", "github.com/acme/widgets", "read")
	if err == nil {
		t.Fatal("runPolicyCheck() = nil error, want error for a missing config file")
	}
}

// TestPolicyCheckCommandWiredIntoRootCmd is a single end-to-end check
// (mirroring TestTokenNewCommand's own use of rootCmd.Execute()) that
// `haybale policy check` is actually reachable as a CLI subcommand with
// its flags wired to runPolicyCheck, not just that runPolicyCheck itself
// works when called directly.
func TestPolicyCheckCommandWiredIntoRootCmd(t *testing.T) {
	cfgPath := writePolicyCheckTestConfig(t, "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [read]\n")

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"policy", "check", "--config", cfgPath, "--id", "run-1", "--repo", "github.com/acme/widgets", "--verb", "read"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if out := buf.String(); !strings.HasPrefix(out, "ALLOW:") {
		t.Errorf("output = %q, want it to start with ALLOW:", out)
	}
}

// newTestCommand returns a *cobra.Command with its output directed to a
// fresh *bytes.Buffer, for tests that call runPolicyCheck directly
// (rather than through rootCmd.Execute()) and need to read back
// cmd.OutOrStdout()'s contents via a type assertion to *bytes.Buffer.
func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	return cmd
}
