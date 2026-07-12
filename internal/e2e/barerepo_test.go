package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newBareRepoWithCommit creates a real git repository containing one
// commit, then clones it --bare into projectRoot/owner/name.git — the
// on-disk layout git-http-backend's GIT_PROJECT_ROOT resolution needs to
// match the /{owner}/{repo}.git path haybale forwards upstream once the
// host-in-path segment is stripped. It returns the bare repo's path and
// the commit SHA the clone under test is expected to reproduce.
func newBareRepoWithCommit(t *testing.T, gitPath, projectRoot, owner, name string) (bareDir, headSHA string) {
	t.Helper()

	home := t.TempDir()
	env := isolatedGitEnv(home)

	workDir := t.TempDir()
	runGit(t, gitPath, workDir, env, "init", "--quiet", "-b", "main")

	readme := filepath.Join(workDir, "README.md")
	if err := os.WriteFile(readme, []byte("hello from the haybale e2e harness\n"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runGit(t, gitPath, workDir, env, "add", "README.md")
	runGit(t, gitPath, workDir, env, "commit", "--quiet", "-m", "initial commit")
	headSHA = strings.TrimSpace(runGit(t, gitPath, workDir, env, "rev-parse", "HEAD"))

	ownerDir := filepath.Join(projectRoot, owner)
	if err := os.MkdirAll(ownerDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", ownerDir, err)
	}
	bareDir = filepath.Join(ownerDir, name+".git")
	runGit(t, gitPath, projectRoot, env, "clone", "--quiet", "--bare", workDir, bareDir)

	return bareDir, headSHA
}
