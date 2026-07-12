package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireGit skips the test if git is unavailable, or returns the path
// to git-http-backend located via `git --exec-path` if it is. Both are
// present in this repo's dev/CI environment, so skipping here should
// never actually trigger — it exists so this harness degrades
// gracefully on a machine without a git installation instead of failing
// opaquely.
func requireGit(t *testing.T) (gitPath, httpBackendPath string) {
	t.Helper()

	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found on PATH; skipping real-git e2e test")
	}

	out, err := exec.Command(gitPath, "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v; skipping real-git e2e test", err)
	}
	execPath := strings.TrimSpace(string(out))
	httpBackendPath = filepath.Join(execPath, "git-http-backend")
	if _, err := os.Stat(httpBackendPath); err != nil {
		t.Skipf("git-http-backend not found at %s; skipping real-git e2e test", httpBackendPath)
	}
	return gitPath, httpBackendPath
}

// isolatedGitEnv returns an environment for a git subprocess (either
// side: the repo-prep commands or the client under test) that is
// completely isolated from the developer's real git config and
// credentials. home should be a fresh, empty temp directory: with no
// ~/.gitconfig and GIT_CONFIG_NOSYSTEM=1 to skip /etc/gitconfig, git
// falls back only to what this env explicitly provides.
//
// GIT_TERMINAL_PROMPT=0 and a no-op GIT_ASKPASS ensure a misbehaving
// test (e.g. an upstream that unexpectedly demands auth) fails fast
// with an error instead of hanging on a credential prompt that has
// nowhere to go in a test process.
func isolatedGitEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_AUTHOR_NAME=haybale-e2e",
		"GIT_AUTHOR_EMAIL=haybale-e2e@example.invalid",
		"GIT_COMMITTER_NAME=haybale-e2e",
		"GIT_COMMITTER_EMAIL=haybale-e2e@example.invalid",
	}
}

// runGit runs `git <args>` with the given working directory and
// environment, failing the test with the combined output on error.
func runGit(t *testing.T, gitPath, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(gitPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}
