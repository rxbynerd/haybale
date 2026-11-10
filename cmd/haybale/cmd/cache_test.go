package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store/s3fake"
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
			name:     "remote tier not configured",
			keyValue: validKey,
			repo:     "github.com/acme/widgets",
			remote:   true,
			wantErr:  "--remote: cache.remote is not configured",
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

// cachePurgeRemoteBlock is an enabled cache block on dir whose remote tier
// is fake's bucket under the "tenant/" prefix.
func cachePurgeRemoteBlock(dir string, fake *s3fake.Server) string {
	return "cache:\n  enabled: true\n  dir: " + dir + "\n  keyEnv: " + cachePurgeTestKeyEnv + "\n" +
		"  remote:\n    type: s3\n    bucket: " + s3fake.Bucket + "\n    prefix: tenant/\n    region: us-east-1\n" +
		"    endpoint: " + fake.URL() + "\n    forcePathStyle: true\n"
}

// newPurgeTestCommand returns a command with its stdout and stderr
// captured.
func newPurgeTestCommand() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	return cmd, &stdout, &stderr
}

// remotePurgeFixture is a remote-configured purge setup: two local pack
// entries and remote refs and pack entries for acme/widgets, and a remote
// pack entry for acme/gadgets that must survive.
type remotePurgeFixture struct {
	fake     *s3fake.Server
	dir      string
	cfgPath  string
	widgets  string
	local    []string
	survivor string
}

func newRemotePurgeFixture(t *testing.T, dir string) *remotePurgeFixture {
	t.Helper()
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	key := cachePurgeTestKey(t)
	t.Setenv(cachePurgeTestKeyEnv, base64.StdEncoding.EncodeToString(key))
	f := &remotePurgeFixture{
		fake:    fake,
		dir:     dir,
		cfgPath: cachePurgeTestConfig(t, cachePurgeRemoteBlock(dir, fake)),
		widgets: cachePurgeTestRepoHash(t, key, "acme", "widgets"),
	}
	if _, err := os.Stat(dir); err == nil {
		f.local = cachePurgeTestPlace(t, dir, "pack", f.widgets, 2)
	}
	entry := strings.Repeat("e", 64)
	fake.PutObject("tenant/v1/refs/"+f.widgets+"/"+entry, []byte("sealed"))
	fake.PutObject("tenant/v1/pack/"+f.widgets+"/"+entry, []byte("sealed"))
	f.survivor = "tenant/v1/pack/" + cachePurgeTestRepoHash(t, key, "acme", "gadgets") + "/" + entry
	fake.PutObject(f.survivor, []byte("sealed"))
	return f
}

func (f *remotePurgeFixture) markerKey() string { return "tenant/v1/purge/" + f.widgets }

// remoteEntries returns the widgets entries left in the bucket.
func (f *remotePurgeFixture) remoteEntries() []string {
	var out []string
	for k := range f.fake.Objects() {
		if strings.Contains(k, f.widgets) && k != f.markerKey() {
			out = append(out, k)
		}
	}
	return out
}

func TestRunCachePurgeRemote(t *testing.T) {
	f := newRemotePurgeFixture(t, cachePurgeTestDir(t))
	var order []string
	var mu sync.Mutex
	f.fake.Intercept(func(_ http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/v1/purge/"):
			order = append(order, "marker")
		case r.Method == http.MethodDelete:
			step := "delete"
			if cachePurgeTestExists(f.dir, f.local[0]) {
				step += " with local entries present"
			}
			order = append(order, step)
		}
		return false
	})

	cmd, stdout, stderr := newPurgeTestCommand()
	if err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", "", true); err != nil {
		t.Fatalf("runCachePurge() unexpected error: %v", err)
	}
	want := "wrote the purge marker and purged 2 entries from the remote tier\npurged 2 entries\n"
	if out := stdout.String(); out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
	mu.Lock()
	got := strings.Join(order, ", ")
	mu.Unlock()
	if want := "marker, delete with local entries present, delete with local entries present"; got != want {
		t.Errorf("step order = %q, want %q", got, want)
	}
	if _, ok := f.fake.Objects()[f.markerKey()]; !ok {
		t.Error("no purge marker was written")
	}
	if left := f.remoteEntries(); len(left) != 0 {
		t.Errorf("remote entries %v survived the purge", left)
	}
	if _, ok := f.fake.Objects()[f.survivor]; !ok {
		t.Error("another repository's remote entry was deleted")
	}
	for _, rel := range f.local {
		if cachePurgeTestExists(f.dir, rel) {
			t.Errorf("%s still exists after the purge", rel)
		}
	}
}

func TestRunCachePurgeRemoteWithoutALocalDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	f := newRemotePurgeFixture(t, dir)
	cmd, stdout, stderr := newPurgeTestCommand()
	if err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", "", true); err != nil {
		t.Fatalf("runCachePurge() unexpected error: %v", err)
	}
	if want := "wrote the purge marker and purged 2 entries from the remote tier\n"; stdout.String() != want {
		t.Errorf("output = %q, want %q", stdout.String(), want)
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Errorf("stderr = %q, want a notice that cache.dir is missing", stderr.String())
	}
	if _, ok := f.fake.Objects()[f.markerKey()]; !ok {
		t.Error("no purge marker was written")
	}
	if left := f.remoteEntries(); len(left) != 0 {
		t.Errorf("remote entries %v survived the purge", left)
	}
}

func TestRunCachePurgeRemoteOneGroupAtATime(t *testing.T) {
	f := newRemotePurgeFixture(t, cachePurgeTestDir(t))
	for _, group := range []string{"pack", "refs"} {
		cmd, stdout, _ := newPurgeTestCommand()
		if err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", group, true); err != nil {
			t.Fatalf("runCachePurge(--group %s) unexpected error: %v", group, err)
		}
		if !strings.Contains(stdout.String(), "purged 1 entry from the remote tier") {
			t.Errorf("--group %s output = %q, want one remote entry purged", group, stdout.String())
		}
	}
	if left := f.remoteEntries(); len(left) != 0 {
		t.Errorf("remote entries %v survived both purges", left)
	}
}

func TestRunCachePurgeRemoteMarkerFailureDeletesNothing(t *testing.T) {
	f := newRemotePurgeFixture(t, cachePurgeTestDir(t))
	f.fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/v1/purge/") {
			s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return true
		}
		return false
	})
	cmd, stdout, _ := newPurgeTestCommand()
	err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", "", true)
	if err == nil || !strings.Contains(err.Error(), "nothing was deleted") || !strings.Contains(err.Error(), "AccessDenied (HTTP 403)") {
		t.Fatalf("runCachePurge() error = %v, want the marker failure with nothing deleted", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("output = %q, want nothing", stdout.String())
	}
	if left := f.remoteEntries(); len(left) != 2 {
		t.Errorf("remote entries = %v, want both kept", left)
	}
	for _, rel := range f.local {
		if !cachePurgeTestExists(f.dir, rel) {
			t.Errorf("%s was deleted", rel)
		}
	}
}

func TestRunCachePurgeRemoteDeleteFailureStillPurgesLocally(t *testing.T) {
	f := newRemotePurgeFixture(t, cachePurgeTestDir(t))
	var deletes atomic.Int32
	f.fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && deletes.Add(1) > 1 {
			s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return true
		}
		return false
	})
	cmd, stdout, _ := newPurgeTestCommand()
	err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", "", true)
	if err == nil || !strings.Contains(err.Error(), "--remote: the purge marker was written, but purging the remote tier failed (1 entry deleted so far)") {
		t.Fatalf("runCachePurge() error = %v, want the remote failure with the count so far", err)
	}
	if out := stdout.String(); out != "purged 2 entries\n" {
		t.Errorf("output = %q, want the local step's line only", out)
	}
	if _, ok := f.fake.Objects()[f.markerKey()]; !ok {
		t.Error("the purge marker is missing")
	}
	for _, rel := range f.local {
		if cachePurgeTestExists(f.dir, rel) {
			t.Errorf("%s still exists after the purge", rel)
		}
	}
}

func TestRunCachePurgeWarnsWithoutRemote(t *testing.T) {
	f := newRemotePurgeFixture(t, cachePurgeTestDir(t))
	cmd, stdout, stderr := newPurgeTestCommand()
	if err := runCachePurge(cmd, f.cfgPath, "github.com/acme/widgets", "", false); err != nil {
		t.Fatalf("runCachePurge() unexpected error: %v", err)
	}
	if out := stdout.String(); out != "purged 2 entries\n" {
		t.Errorf("output = %q, want %q", out, "purged 2 entries\n")
	}
	if !strings.Contains(stderr.String(), "will refill the purged entries") || !strings.Contains(stderr.String(), "--remote") {
		t.Errorf("stderr = %q, want the refill warning", stderr.String())
	}
	if len(f.fake.Requests()) != 0 {
		t.Error("a purge without --remote reached the bucket")
	}
}

func TestRunCachePurgeRemoteReportsAFailingBucket(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.Intercept(func(w http.ResponseWriter, _ *http.Request) bool {
		s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return true
	})
	t.Setenv(cachePurgeTestKeyEnv, base64.StdEncoding.EncodeToString(cachePurgeTestKey(t)))
	cfgPath := cachePurgeTestConfig(t, cachePurgeRemoteBlock(cachePurgeTestDir(t), fake))

	cmd, _, _ := newPurgeTestCommand()
	err := runCachePurge(cmd, cfgPath, "github.com/acme/widgets", "", true)
	if err == nil || !strings.Contains(err.Error(), "--remote: write the purge marker") || !strings.Contains(err.Error(), "AccessDenied (HTTP 403)") {
		t.Fatalf("runCachePurge() error = %v, want the remote failure reported with its code", err)
	}
}
