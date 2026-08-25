// Package e2e exercises real Git subprocesses against an in-process haybale
// proxy and a git-http-backend CGI upstream. Tests use JWTAuthenticator,
// GlobEngine, a per-test file-backed JWKS, and a Basic-auth-protected upstream
// rather than protocol, authentication, or authorization stubs.
package e2e

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/policy"
)

// hostKey is the host-in-path segment the test client uses to reach the
// fake upstream through haybale. It intentionally does not resemble a
// real git host — proving the mapping is config-driven (any key routes
// to whatever base URL is configured for it), not hardcoded to
// "github.com".
const hostKey = "e2e-upstream.test"

const (
	owner    = "acme"
	repoName = "widgets"
)

// TestCloneThroughProxy serves a one-commit bare repository through a real
// git-http-backend CGI process. A real `git clone` subprocess reaches it
// through haybale's host-in-path URL scheme. The test asserts the clone
// succeeds with the exact upstream commit SHA, and that the Git-Protocol
// header reached the upstream unmodified (dropping it would silently
// downgrade protocol v2 to v1).
func TestCloneThroughProxy(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	_, wantSHA := newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, rec := newUpstream(t, httpBackendPath, projectRoot)

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-clone"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)

	clientHome := t.TempDir()
	clientEnv := isolatedGitEnv(clientHome)
	cloneDir := filepath.Join(t.TempDir(), "clone")

	// -c protocol.version=2 makes the Git-Protocol assertion below
	// deterministic regardless of the installed git's own default.
	runGit(t, gitPath, t.TempDir(), clientEnv,
		"-c", "protocol.version=2", "clone", "--quiet", cloneURL, cloneDir)

	gotSHA := strings.TrimSpace(runGit(t, gitPath, cloneDir, clientEnv, "rev-parse", "HEAD"))
	if gotSHA != wantSHA {
		t.Errorf("cloned HEAD = %s, want upstream HEAD %s", gotSHA, wantSHA)
	}

	if got := rec.GitProtocol(); got != "version=2" {
		t.Errorf("upstream saw Git-Protocol = %q, want %q — haybale must forward this header verbatim or protocol v2 silently downgrades to v1", got, "version=2")
	}
}

// TestPushThroughProxy exercises git-receive-pack with a real Git
// subprocess and confirms the upstream bare repository receives the commit.
func TestPushThroughProxy(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	bareDir, _ := newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	// git-http-backend disables git-receive-pack (push) by default for
	// anonymous (unauthenticated) requests — which every request through
	// this CGI upstream is, since newUpstream sets up no auth. The bare
	// repo must opt in explicitly.
	repoEnv := isolatedGitEnv(t.TempDir())
	runGit(t, gitPath, bareDir, repoEnv, "config", "http.receivepack", "true")

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-push"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)

	clientHome := t.TempDir()
	clientEnv := isolatedGitEnv(clientHome)
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runGit(t, gitPath, t.TempDir(), clientEnv, "clone", "--quiet", cloneURL, cloneDir)

	newFile := filepath.Join(cloneDir, "NEWFILE.md")
	if err := os.WriteFile(newFile, []byte("pushed through the haybale e2e harness\n"), 0o600); err != nil {
		t.Fatalf("write NEWFILE.md: %v", err)
	}
	runGit(t, gitPath, cloneDir, clientEnv, "add", "NEWFILE.md")
	runGit(t, gitPath, cloneDir, clientEnv, "commit", "--quiet", "-m", "add NEWFILE.md")
	wantSHA := strings.TrimSpace(runGit(t, gitPath, cloneDir, clientEnv, "rev-parse", "HEAD"))

	runGit(t, gitPath, cloneDir, clientEnv, "push", "--quiet", "origin", "HEAD:main")

	gotSHA := strings.TrimSpace(runGit(t, gitPath, bareDir, repoEnv, "rev-parse", "HEAD"))
	if gotSHA != wantSHA {
		t.Errorf("bare repo HEAD after push = %s, want pushed commit %s", gotSHA, wantSHA)
	}
}
