package e2e

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rxbynerd/haybale/internal/policy"
)

// TestParallelClonesThroughProxy is haybale's concurrency-hardening
// acceptance test for M5: 4 real `git clone` subprocesses run
// concurrently against the same in-process haybale proxy (itself
// forwarding to the same real `git http-backend` CGI upstream this
// package's other tests use), asserting every clone succeeds with the
// exact upstream commit SHA. Proxy is built once and reused across every
// goroutine's request, the same way a single haybale process serves
// every concurrent client in production — this is what exercises the
// "stateless server, no shared mutable state" claim internal/proxy's
// package doc makes, and it must stay green under `go test -race`.
//
// Each goroutine's git subprocess work is isolated to its own
// t.TempDir()-rooted HOME/clone directory, so no two clones share
// on-disk state either — only the proxy and the upstream are shared.
func TestParallelClonesThroughProxy(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	_, wantSHA := newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-parallel"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)

	const parallelism = 4
	results := make([]cloneResult, parallelism)
	var wg sync.WaitGroup
	for i := range parallelism {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// t.TempDir() is safe to call concurrently (it's guarded
			// internally), but t.Fatalf/t.Errorf are not — the testing
			// package requires FailNow-family methods to run only on the
			// test's own goroutine — so cloneOnce reports its outcome via
			// a plain return value instead, and every assertion below
			// happens back on this function's own goroutine after
			// wg.Wait().
			results[i] = cloneOnce(gitPath, cloneURL, t.TempDir())
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			t.Errorf("clone %d: %v", i, r.err)
			continue
		}
		if r.sha != wantSHA {
			t.Errorf("clone %d: HEAD = %s, want upstream HEAD %s", i, r.sha, wantSHA)
		}
	}
}

// cloneResult is one goroutine's outcome in TestParallelClonesThroughProxy:
// either the cloned repo's HEAD SHA, or the first error encountered.
type cloneResult struct {
	sha string
	err error
}

// cloneOnce runs `git clone` then `git rev-parse HEAD` against cloneURL
// under an isolated HOME rooted at workDir, returning the resulting HEAD
// SHA or the first error encountered. It never calls any *testing.T
// method itself — see the comment at its call site in
// TestParallelClonesThroughProxy for why that matters when this runs on
// a goroutine other than the test's own.
func cloneOnce(gitPath, cloneURL, workDir string) cloneResult {
	home := filepath.Join(workDir, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		return cloneResult{err: fmt.Errorf("mkdir home: %w", err)}
	}
	env := isolatedGitEnv(home)
	cloneDir := filepath.Join(workDir, "clone")

	cmd := exec.Command(gitPath, "clone", "--quiet", cloneURL, cloneDir) //nolint:gosec // gitPath comes from requireGit's exec.LookPath, args are test-fixed strings, never external input
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		return cloneResult{err: fmt.Errorf("git clone: %w\n%s", err, out)}
	}

	cmd = exec.Command(gitPath, "rev-parse", "HEAD") //nolint:gosec // see above
	cmd.Dir = cloneDir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return cloneResult{err: fmt.Errorf("git rev-parse HEAD: %w\n%s", err, out)}
	}
	return cloneResult{sha: strings.TrimSpace(string(out))}
}
