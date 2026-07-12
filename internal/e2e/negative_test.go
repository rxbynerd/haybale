// This file holds the M2 negative acceptance tests the plan calls out
// explicitly: a bad or absent token must fail authentication (401), a
// policy-denied repo must be indistinguishable from a genuinely
// nonexistent one (the existence-oracle check), and a read-only
// identity must be able to clone but never push.
package e2e

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/policy"
)

// TestBadOrAbsentTokenMapsTo401 clones with either a wrong token or no
// credentials at all: both must fail authentication and surface as an
// HTTP 401 to the git client, which (with GIT_TERMINAL_PROMPT=0 and a
// no-op GIT_ASKPASS) fails fast rather than hanging on a credential
// prompt.
func TestBadOrAbsentTokenMapsTo401(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-negatives-401"
	auth, _ := mintTestToken(t, testID) // the valid token is deliberately never used below
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	baseCloneURL := haybaleSrv.URL + "/" + hostKey + "/" + owner + "/" + repoName + ".git"

	tests := []struct {
		name     string
		cloneURL string
		// wantSubstr differs between the two cases because of *where*
		// git's failure surfaces, even though both stem from the same
		// 401 response: with a wrong token embedded, git sends it,
		// haybale rejects it, and curl reports the 401 directly. With
		// no credentials embedded at all, git's credential subsystem
		// tries to fill a username/password (triggered by that same
		// 401 challenge) before retrying, and fails locally on the
		// disabled terminal prompt instead — TestAuthenticationFailureMaps401
		// in internal/proxy pins the actual 401 response this
		// ultimately traces back to.
		wantSubstr string
	}{
		{
			name:       "wrong token",
			cloneURL:   withToken(t, baseCloneURL, "this-is-not-a-valid-token"),
			wantSubstr: "401",
		},
		{
			name:       "absent token",
			cloneURL:   baseCloneURL, // no credentials embedded at all
			wantSubstr: "terminal prompts disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientEnv := isolatedGitEnv(t.TempDir())
			cloneDir := filepath.Join(t.TempDir(), "clone")

			out := runGitExpectError(t, gitPath, t.TempDir(), clientEnv, "clone", "--quiet", tt.cloneURL, cloneDir)
			if !strings.Contains(out, tt.wantSubstr) {
				t.Errorf("git clone output = %q, want it to contain %q", out, tt.wantSubstr)
			}
		})
	}
}

// TestPolicyDeniedRepoCloneFailsWith404 exercises the literal "clone of
// an unlisted/denied repo" acceptance case with a real git subprocess: a
// repo that exists upstream but isn't covered by any policy rule for
// the authenticated identity must fail the clone with a 404, never a
// 403.
func TestPolicyDeniedRepoCloneFailsWith404(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-negatives-denied"
	auth, token := mintTestToken(t, testID)
	// Policy grants this identity access to a completely different repo
	// than the one being cloned, so the clone is denied by default-deny
	// — never touching upstream at all.
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, "some-other-repo")}, Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)

	clientEnv := isolatedGitEnv(t.TempDir())
	cloneDir := filepath.Join(t.TempDir(), "clone")
	out := runGitExpectError(t, gitPath, t.TempDir(), clientEnv, "clone", "--quiet", cloneURL, cloneDir)
	if !strings.Contains(out, "404") {
		t.Errorf("git clone output = %q, want it to mention HTTP 404", out)
	}
	if strings.Contains(out, "403") {
		t.Errorf("git clone output = %q, must never mention HTTP 403 — policy denial must look like a 404, not a 403", out)
	}
}

// TestPolicyDeniedRepoResponseMatchesNonexistentRepo404 is the oracle
// check itself: a request for a repo that genuinely exists upstream but
// is outside the authenticated identity's policy, and a request for a
// repo that was never created at all, are both denied by the exact
// same default-deny path (no rule's identity/repo patterns match either
// one) — so haybale never even asks upstream whether either one
// exists. The two responses must therefore be byte-identical: same
// status, same body, same (relevant) headers. This is the concrete
// guarantee behind "no existence oracle": an attacker holding a valid
// token cannot distinguish "exists but denied" from "does not exist".
func TestPolicyDeniedRepoResponseMatchesNonexistentRepo404(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	const existingButDeniedRepo = "exists-but-denied"
	const neverCreatedRepo = "never-created"
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, existingButDeniedRepo)
	// neverCreatedRepo is deliberately never created on disk.

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-negatives-oracle"
	auth, token := mintTestToken(t, testID)
	// Policy grants this identity access to a repo pattern that matches
	// neither existingButDeniedRepo nor neverCreatedRepo, so both are
	// denied before haybale ever contacts upstream.
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, "some-allowed-repo")}, Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	get := func(name string) (status int, body []byte, headers http.Header) {
		infoRefsURL := haybaleSrv.URL + "/" + hostKey + "/" + owner + "/" + name + ".git/info/refs?service=git-upload-pack"
		req, err := http.NewRequest(http.MethodGet, infoRefsURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.SetBasicAuth("haybale-e2e", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		return resp.StatusCode, b, resp.Header
	}

	deniedStatus, deniedBody, deniedHeaders := get(existingButDeniedRepo)
	nonexistentStatus, nonexistentBody, nonexistentHeaders := get(neverCreatedRepo)

	if deniedStatus != http.StatusNotFound {
		t.Fatalf("status for existing-but-denied repo = %d, want %d", deniedStatus, http.StatusNotFound)
	}
	if deniedStatus != nonexistentStatus {
		t.Errorf("status: existing-but-denied = %d, never-created = %d, want equal", deniedStatus, nonexistentStatus)
	}
	if !bytes.Equal(deniedBody, nonexistentBody) {
		t.Errorf("body: existing-but-denied = %q, never-created = %q, want byte-identical", deniedBody, nonexistentBody)
	}
	for _, h := range []string{"Content-Type", "X-Content-Type-Options"} {
		if got, want := deniedHeaders.Get(h), nonexistentHeaders.Get(h); got != want {
			t.Errorf("header %s: existing-but-denied = %q, never-created = %q, want equal", h, got, want)
		}
	}
}

// TestReadOnlyIdentityCanCloneButNotPush exercises the third M2
// negative acceptance case: an identity whose policy rule grants only
// "read" can clone successfully, but a subsequent push is denied — as a
// 404 (never a 403, and never distinguishable from a policy-denied or
// nonexistent repo), and the upstream bare repo's HEAD must be
// unchanged, confirming the push never reached it.
func TestReadOnlyIdentityCanCloneButNotPush(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	bareDir, wantSHA := newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	// git-http-backend disables git-receive-pack (push) by default for
	// anonymous requests; the bare repo must opt in explicitly (mirrors
	// TestPushThroughProxy) so a denied push below is attributable to
	// haybale's policy gate, not upstream's own default refusal.
	repoEnv := isolatedGitEnv(t.TempDir())
	runGit(t, gitPath, bareDir, repoEnv, "config", "http.receivepack", "true")

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-negatives-readonly"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead}},
	})

	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)

	clientEnv := isolatedGitEnv(t.TempDir())
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runGit(t, gitPath, t.TempDir(), clientEnv, "clone", "--quiet", cloneURL, cloneDir)

	gotSHA := strings.TrimSpace(runGit(t, gitPath, cloneDir, clientEnv, "rev-parse", "HEAD"))
	if gotSHA != wantSHA {
		t.Fatalf("cloned HEAD = %s, want upstream HEAD %s", gotSHA, wantSHA)
	}

	newFile := filepath.Join(cloneDir, "NEWFILE.md")
	if err := os.WriteFile(newFile, []byte("this push must never reach upstream\n"), 0o600); err != nil {
		t.Fatalf("write NEWFILE.md: %v", err)
	}
	runGit(t, gitPath, cloneDir, clientEnv, "add", "NEWFILE.md")
	runGit(t, gitPath, cloneDir, clientEnv, "commit", "--quiet", "-m", "add NEWFILE.md")

	out := runGitExpectError(t, gitPath, cloneDir, clientEnv, "push", "--quiet", "origin", "HEAD:main")
	if !strings.Contains(out, "404") {
		t.Errorf("git push output = %q, want it to mention HTTP 404", out)
	}
	if strings.Contains(out, "403") {
		t.Errorf("git push output = %q, must never mention HTTP 403 — write denial must look like a 404, not a 403", out)
	}

	gotAfter := strings.TrimSpace(runGit(t, gitPath, bareDir, repoEnv, "rev-parse", "HEAD"))
	if gotAfter != wantSHA {
		t.Errorf("bare repo HEAD after denied push = %s, want unchanged %s", gotAfter, wantSHA)
	}
}
