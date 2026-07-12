// Package e2e is haybale's crown-jewel integration harness: it exercises
// a real `git clone` subprocess against an in-process haybale proxy that
// forwards to a real `git http-backend` CGI upstream — no mocked git
// protocol, no stubbed proxy behaviour. M1's proxy has no identity or
// policy layer yet, so this covers the passthrough path end to end;
// M2/M3 extend this same harness with negative cases (bad token, policy
// denial, upstream auth) as those layers land.
package e2e

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/proxy"
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

// TestCloneThroughProxy is the real-git acceptance test for M1: a bare
// repo with one commit is served by a real git-http-backend CGI process;
// haybale proxies to it; a real `git clone` subprocess goes through
// haybale using the host-in-path URL scheme. The test asserts the clone
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

	haybale := proxy.New(map[string]*url.URL{hostKey: upstreamURL}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := haybaleSrv.URL + "/" + hostKey + "/" + owner + "/" + repoName + ".git"

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
