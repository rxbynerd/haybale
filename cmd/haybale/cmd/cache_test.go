package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/gitproto"
)

const (
	cachePurgeTestKeyEnv   = "HAYBALE_CACHE_PURGE_TEST_KEY"
	cachePurgeTestTokenEnv = "HAYBALE_CACHE_PURGE_TEST_TOKEN" //nolint:gosec // G101: an environment-variable *name*, not a credential value
	cachePurgeTestBase     = "https://github.com"
)

// cachePurgeTestConfig writes a haybale.yaml whose cache block is
// cacheBlock, with an empty policy file, and returns its path. Validation
// is structural, so the JWKS file need not exist.
func cachePurgeTestConfig(t *testing.T, cacheBlock string) string {
	t.Helper()
	t.Setenv(cachePurgeTestTokenEnv, "test-token-value")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(policy.yaml): %v", err)
	}
	path := filepath.Join(dir, "haybale.yaml")
	content := `
identity:
  type: jwt
  issuers:
    - issuer: https://issuer.example
      jwksFile: ` + filepath.Join(dir, "jwks.json") + `
      audiences: [https://haybale.internal]
      identityTemplate: "{sub}"
policy:
  path: ` + filepath.Join(dir, "policy.yaml") + `
upstreams:
  - host: github.com
    baseURL: ` + cachePurgeTestBase + `
    credential: { type: static, tokenEnv: ` + cachePurgeTestTokenEnv + ` }
` + cacheBlock
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(haybale.yaml): %v", err)
	}
	return path
}

func cachePurgeTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, cache.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

// cachePurgeTestDir returns a cache directory with the owner-only mode
// the store requires.
func cachePurgeTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the owner execute bit
		t.Fatalf("os.Chmod: %v", err)
	}
	return dir
}

func cachePurgeTestRepoHash(t *testing.T, key []byte, owner, name string) string {
	t.Helper()
	base, err := url.Parse(cachePurgeTestBase)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	kr, err := cache.NewKeyring(key)
	if err != nil {
		t.Fatalf("cache.NewKeyring: %v", err)
	}
	sum := kr.RepoHash(base, gitproto.Repo{Host: "github.com", Owner: owner, Name: name})
	return hex.EncodeToString(sum[:])
}

// cachePurgeTestPlace creates n entry files under group and repoHash and
// returns their paths relative to dir. Purge never reads entry contents.
func cachePurgeTestPlace(t *testing.T, dir, group, repoHash string, n int) []string {
	t.Helper()
	repoDir := filepath.Join(dir, "v1", group, repoHash)
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		t.Fatalf("os.MkdirAll: %v", err)
	}
	paths := make([]string, 0, n)
	for i := range n {
		name := strings.Repeat(string(rune('a'+i)), 64)
		if err := os.WriteFile(filepath.Join(repoDir, name), []byte("sealed"), 0o600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		paths = append(paths, filepath.Join("v1", group, repoHash, name))
	}
	return paths
}

func cachePurgeTestExists(dir, rel string) bool {
	_, err := os.Stat(filepath.Join(dir, rel))
	return err == nil
}

func TestRunCachePurge(t *testing.T) {
	tests := []struct {
		name        string
		repo        string
		group       string
		wantOut     string
		wantGone    []string // keys into the placed-entry table
		wantSurvive []string
	}{
		{
			name:        "both groups",
			repo:        "github.com/acme/widgets",
			wantOut:     "purged 5 entries\n",
			wantGone:    []string{"widgets/refs", "widgets/pack"},
			wantSurvive: []string{"gadgets/refs", "gadgets/pack"},
		},
		{
			name:        "refs only",
			repo:        "github.com/acme/widgets",
			group:       "refs",
			wantOut:     "purged 3 entries\n",
			wantGone:    []string{"widgets/refs"},
			wantSurvive: []string{"widgets/pack", "gadgets/refs", "gadgets/pack"},
		},
		{
			name:        "pack only",
			repo:        "github.com/acme/widgets",
			group:       "pack",
			wantOut:     "purged 2 entries\n",
			wantGone:    []string{"widgets/pack"},
			wantSurvive: []string{"widgets/refs", "gadgets/refs", "gadgets/pack"},
		},
		{
			name:        "trailing .git accepted",
			repo:        "github.com/acme/widgets.git",
			wantOut:     "purged 5 entries\n",
			wantGone:    []string{"widgets/refs", "widgets/pack"},
			wantSurvive: []string{"gadgets/refs", "gadgets/pack"},
		},
		{
			name:        "repository with no entries",
			repo:        "github.com/acme/unknown",
			wantOut:     "purged 0 entries\n",
			wantSurvive: []string{"widgets/refs", "widgets/pack", "gadgets/refs", "gadgets/pack"},
		},
		{
			name:        "owner case is significant",
			repo:        "github.com/ACME/widgets",
			wantOut:     "purged 0 entries\n",
			wantSurvive: []string{"widgets/refs", "widgets/pack", "gadgets/refs", "gadgets/pack"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cachePurgeTestKey(t)
			t.Setenv(cachePurgeTestKeyEnv, base64.StdEncoding.EncodeToString(key))
			dir := cachePurgeTestDir(t)
			cfgPath := cachePurgeTestConfig(t, "cache:\n  enabled: true\n  dir: "+dir+"\n  keyEnv: "+cachePurgeTestKeyEnv+"\n")

			widgets := cachePurgeTestRepoHash(t, key, "acme", "widgets")
			gadgets := cachePurgeTestRepoHash(t, key, "acme", "gadgets")
			placed := map[string][]string{
				"widgets/refs": cachePurgeTestPlace(t, dir, "refs", widgets, 3),
				"widgets/pack": cachePurgeTestPlace(t, dir, "pack", widgets, 2),
				"gadgets/refs": cachePurgeTestPlace(t, dir, "refs", gadgets, 2),
				"gadgets/pack": cachePurgeTestPlace(t, dir, "pack", gadgets, 1),
			}

			cmd := newTestCommand()
			if err := runCachePurge(cmd, cfgPath, tt.repo, tt.group, false); err != nil {
				t.Fatalf("runCachePurge() unexpected error: %v", err)
			}
			if out := cmd.OutOrStdout().(*bytes.Buffer).String(); out != tt.wantOut {
				t.Errorf("output = %q, want %q", out, tt.wantOut)
			}
			for _, k := range tt.wantGone {
				for _, rel := range placed[k] {
					if cachePurgeTestExists(dir, rel) {
						t.Errorf("%s still exists after purge", rel)
					}
				}
			}
			for _, k := range tt.wantSurvive {
				for _, rel := range placed[k] {
					if !cachePurgeTestExists(dir, rel) {
						t.Errorf("%s was deleted but should have survived", rel)
					}
				}
			}
		})
	}
}

func TestRunCachePurgeUsesRawKeyBytes(t *testing.T) {
	key := cachePurgeTestKey(t)
	t.Setenv(cachePurgeTestKeyEnv, base64.StdEncoding.EncodeToString(key))
	dir := cachePurgeTestDir(t)
	cfgPath := cachePurgeTestConfig(t, "cache:\n  enabled: true\n  dir: "+dir+"\n  keyEnv: "+cachePurgeTestKeyEnv+"\n")

	// An entry addressed under a different key is unreachable, as after a key rotation.
	other := cachePurgeTestRepoHash(t, cachePurgeTestKey(t), "acme", "widgets")
	entries := cachePurgeTestPlace(t, dir, "pack", other, 1)

	cmd := newTestCommand()
	if err := runCachePurge(cmd, cfgPath, "github.com/acme/widgets", "", false); err != nil {
		t.Fatalf("runCachePurge() unexpected error: %v", err)
	}
	if out := cmd.OutOrStdout().(*bytes.Buffer).String(); out != "purged 0 entries\n" {
		t.Errorf("output = %q, want %q", out, "purged 0 entries\n")
	}
	if !cachePurgeTestExists(dir, entries[0]) {
		t.Error("an entry addressed under another key was deleted")
	}
}

func TestRunCachePurgeErrors(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(cachePurgeTestKey(t))

	tests := []struct {
		name     string
		cache    func(dir string) string // cache block; nil means the standard enabled block
		keyValue string                  // value for cachePurgeTestKeyEnv; "" leaves it unset
		repo     string
		group    string
		remote   bool
		wantErr  string
		makeDir  bool
	}{
		{
			name:     "remote tier",
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			remote:   true,
			wantErr:  "not supported in this release",
		},
		{
			name:     "bad group",
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			group:    "objects",
			wantErr:  `--group: cache: unknown group "objects"`,
		},
		{
			name:     "malformed repo",
			keyValue: validKey,
			repo:     "acme/widgets",
			wantErr:  "must be host/owner/repo",
		},
		{
			name:     "cache disabled",
			cache:    func(dir string) string { return "cache:\n  enabled: false\n  dir: " + dir + "\n" },
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			wantErr:  "cache.enabled is false",
		},
		{
			name:     "cache block absent",
			cache:    func(string) string { return "" },
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			wantErr:  "cache.enabled is false",
		},
		{
			name:     "keyEnv not configured",
			cache:    func(dir string) string { return "cache:\n  enabled: true\n  dir: " + dir + "\n" },
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			wantErr:  "cleared when the server restarts",
		},
		{
			name:    "keyEnv variable unset",
			repo:    "github.com/acme/widgets",
			wantErr: `"` + cachePurgeTestKeyEnv + `" (keyEnv) is unset or empty`,
		},
		{
			name:     "keyEnv variable not a key",
			keyValue: "not-a-valid-key!",
			repo:     "github.com/acme/widgets",
			wantErr:  "(keyEnv): cache: key is not valid base64",
		},
		{
			name:     "keyEnv variable wrong length",
			keyValue: base64.StdEncoding.EncodeToString([]byte("too short")),
			repo:     "github.com/acme/widgets",
			wantErr:  "must decode to 32 bytes",
		},
		{
			name:     "unknown host",
			keyValue: validKey,
			repo:     "gitlab.example/acme/widgets",
			wantErr:  `host "gitlab.example" is not a configured upstream`,
		},
		{
			name:     "cache directory missing",
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			wantErr:  "open dir",
		},
		{
			name:     "cache directory open to group",
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			makeDir:  true,
			wantErr:  "grants group or other access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyValue != "" {
				t.Setenv(cachePurgeTestKeyEnv, tt.keyValue)
			}
			dir := filepath.Join(t.TempDir(), "missing")
			if tt.makeDir {
				dir = t.TempDir()
				if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: deliberately group-accessible directory
					t.Fatalf("os.Chmod: %v", err)
				}
			}
			block := "cache:\n  enabled: true\n  dir: " + dir + "\n  keyEnv: " + cachePurgeTestKeyEnv + "\n"
			if tt.cache != nil {
				block = tt.cache(dir)
			}
			cfgPath := cachePurgeTestConfig(t, block)

			cmd := newTestCommand()
			err := runCachePurge(cmd, cfgPath, tt.repo, tt.group, tt.remote)
			if err == nil {
				t.Fatalf("runCachePurge() = nil error, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
			if out := cmd.OutOrStdout().(*bytes.Buffer).String(); out != "" {
				t.Errorf("output = %q, want none on error", out)
			}
		})
	}
}

func TestRunCachePurgeDoesNotLeakKey(t *testing.T) {
	const secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQ" //nolint:gosec // G101: a wrong-length key fixture, not a credential
	t.Setenv(cachePurgeTestKeyEnv, secret)
	cfgPath := cachePurgeTestConfig(t, "cache:\n  enabled: true\n  dir: "+cachePurgeTestDir(t)+"\n  keyEnv: "+cachePurgeTestKeyEnv+"\n")

	err := runCachePurge(newTestCommand(), cfgPath, "github.com/acme/widgets", "", false)
	if err == nil {
		t.Fatal("runCachePurge() = nil error, want error for a wrong-length key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q contains the key material", err.Error())
	}
}

func TestRunCachePurgePropagatesConfigLoadError(t *testing.T) {
	err := runCachePurge(newTestCommand(), filepath.Join(t.TempDir(), "does-not-exist.yaml"), "github.com/acme/widgets", "", false)
	if err == nil {
		t.Fatal("runCachePurge() = nil error, want error for a missing config file")
	}
}

// TestCachePurgeCommandWiredIntoRootCmd checks that `haybale cache purge`
// is reachable as a CLI subcommand with its flags wired to runCachePurge.
func TestCachePurgeCommandWiredIntoRootCmd(t *testing.T) {
	key := cachePurgeTestKey(t)
	t.Setenv(cachePurgeTestKeyEnv, base64.StdEncoding.EncodeToString(key))
	dir := cachePurgeTestDir(t)
	cfgPath := cachePurgeTestConfig(t, "cache:\n  enabled: true\n  dir: "+dir+"\n  keyEnv: "+cachePurgeTestKeyEnv+"\n")
	entries := cachePurgeTestPlace(t, dir, "pack", cachePurgeTestRepoHash(t, key, "acme", "widgets"), 2)

	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"cache", "purge", "--config", cfgPath, "--repo", "github.com/acme/widgets", "--group", "pack"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if out := buf.String(); out != "purged 2 entries\n" {
		t.Errorf("output = %q, want %q", out, "purged 2 entries\n")
	}
	for _, rel := range entries {
		if cachePurgeTestExists(dir, rel) {
			t.Errorf("%s still exists after purge", rel)
		}
	}
}
