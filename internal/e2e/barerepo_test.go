package e2e

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bareRepoOptions shapes the fixture newBareRepo creates.
type bareRepoOptions struct {
	// branches is how many extra branches point at the commit. Git gzips
	// any upload-pack request body over 1024 bytes, so a repository with
	// forty or more refs makes a clone's fetch request arrive gzipped.
	branches int
	// blobBytes adds a file of that many random bytes to the commit, so
	// the pack exceeds a small cache entry limit.
	blobBytes int
}

// newBareRepoWithCommit creates a real git repository containing one
// commit, then clones it --bare into projectRoot/owner/name.git — the
// on-disk layout git-http-backend's GIT_PROJECT_ROOT resolution needs to
// match the /{owner}/{repo}.git path haybale forwards upstream once the
// host-in-path segment is stripped. It returns the bare repo's path and
// the commit SHA the clone under test is expected to reproduce.
func newBareRepoWithCommit(t *testing.T, gitPath, projectRoot, owner, name string) (bareDir, headSHA string) {
	t.Helper()
	return newBareRepo(t, gitPath, projectRoot, owner, name, bareRepoOptions{})
}

// newBareRepo is newBareRepoWithCommit with options.
func newBareRepo(t *testing.T, gitPath, projectRoot, owner, name string, opts bareRepoOptions) (bareDir, headSHA string) {
	t.Helper()

	home := t.TempDir()
	env := isolatedGitEnv(home)

	workDir := t.TempDir()
	runGit(t, gitPath, workDir, env, "init", "--quiet", "-b", "main")

	readme := filepath.Join(workDir, "README.md")
	if err := os.WriteFile(readme, []byte("hello from the haybale e2e harness\n"), 0o600); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runGit(t, gitPath, workDir, env, "add", "README.md")
	if opts.blobBytes > 0 {
		blob := make([]byte, opts.blobBytes)
		if _, err := rand.Read(blob); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		if err := os.WriteFile(filepath.Join(workDir, "blob.bin"), blob, 0o600); err != nil {
			t.Fatalf("write blob.bin: %v", err)
		}
		runGit(t, gitPath, workDir, env, "add", "blob.bin")
	}
	runGit(t, gitPath, workDir, env, "commit", "--quiet", "-m", "initial commit")
	headSHA = strings.TrimSpace(runGit(t, gitPath, workDir, env, "rev-parse", "HEAD"))
	for i := range opts.branches {
		runGit(t, gitPath, workDir, env, "branch", fmt.Sprintf("topic/branch-%03d", i))
	}

	ownerDir := filepath.Join(projectRoot, owner)
	if err := os.MkdirAll(ownerDir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", ownerDir, err)
	}
	bareDir = filepath.Join(ownerDir, name+".git")
	runGit(t, gitPath, projectRoot, env, "clone", "--quiet", "--bare", workDir, bareDir)

	return bareDir, headSHA
}
