// This file holds the M3 credential-injection acceptance tests the plan
// calls out explicitly: the e2e upstream now genuinely requires Basic
// auth (see upstream_test.go's newUpstream), so a successful clone/push
// through haybale (already exercised by TestCloneThroughProxy and
// TestPushThroughProxy in e2e_test.go) is proof injection works, not a
// passthrough that happened to succeed because the upstream never
// checked anything. This file adds the remaining M3 acceptance cases:
// the control test proving the upstream's auth requirement is real, the
// leak assertions in both directions, and the post-injection upstream
// 401 -> 502 mapping.
package e2e

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/policy"
)

// TestUpstreamRequiresBasicAuthDirectly is the "passthrough-without-injection
// fails loudly" control test the M3 plan calls for: hitting the fake
// upstream directly, with no credentials at all, must fail with a 401.
// This is what makes TestCloneThroughProxy/TestPushThroughProxy's
// success meaningful — the upstream genuinely enforces auth, so haybale
// injecting the right credential is doing real work, not passing through
// an upstream that would have accepted anything anyway.
func TestUpstreamRequiresBasicAuthDirectly(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)

	infoRefsURL := upstreamSrv.URL + "/" + owner + "/" + repoName + ".git/info/refs?service=git-upload-pack"

	t.Run("no credentials at all", func(t *testing.T) {
		resp, err := http.Get(infoRefsURL) //nolint:gosec // fixed test-local httptest URL, not attacker-controlled
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d — the e2e upstream must genuinely enforce auth", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("wrong credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, infoRefsURL, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.SetBasicAuth("someone-else", "not-the-right-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}

// TestCredentialInjectionLeakAssertions is the M3 "leak assertions both
// directions" acceptance case: a successful proxied request must never
// let the upstream credential (upstreamBasicAuthToken) reach the client
// — not in the response body, not in any response header — and the
// upstream must never see the client's own haybale token; it must see
// exactly the injected upstreamBasicAuthUsername/upstreamBasicAuthToken
// credential instead.
func TestCredentialInjectionLeakAssertions(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, rec := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-leak"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead}},
	})
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)

	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger())
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	infoRefsURL := haybaleSrv.URL + "/" + hostKey + "/" + owner + "/" + repoName + ".git/info/refs?service=git-upload-pack"
	req, err := http.NewRequest(http.MethodGet, infoRefsURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("haybale-e2e", token)
	req.Header.Set("Git-Protocol", "version=2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (the request must succeed for the leak assertions below to be meaningful)", resp.StatusCode, http.StatusOK)
	}

	// Leak assertion 1: the upstream credential must never reach the
	// client — neither in the response body nor in any response header.
	if strings.Contains(string(body), upstreamBasicAuthToken) {
		t.Errorf("response body contains the upstream credential %q, want it absent", upstreamBasicAuthToken)
	}
	for name, values := range resp.Header {
		for _, v := range values {
			if strings.Contains(v, upstreamBasicAuthToken) {
				t.Errorf("response header %s = %q, must never contain the upstream credential", name, v)
			}
		}
	}

	// Leak assertion 2: the client's own haybale token must never reach
	// upstream — the upstream must see exactly the injected credential.
	gotAuth := rec.Authorization()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamBasicAuthUsername+":"+upstreamBasicAuthToken))
	if gotAuth != wantAuth {
		t.Errorf("upstream saw Authorization = %q, want the injected credential %q", gotAuth, wantAuth)
	}
	if strings.Contains(gotAuth, token) {
		t.Errorf("upstream saw Authorization = %q, must never contain the client's haybale token", gotAuth)
	}

	// Git-Protocol must still reach upstream unmodified — pinned again
	// here (alongside TestCloneThroughProxy's real-git-subprocess
	// version) since this test exercises the raw HTTP request path and
	// can therefore assert the exact value it sent.
	if got := rec.GitProtocol(); got != "version=2" {
		t.Errorf("upstream saw Git-Protocol = %q, want %q", got, "version=2")
	}
}

// TestPostInjectionUpstream401Maps502 is the M3 "post-injection upstream
// 401 -> 502" acceptance case: haybale is configured with a StaticSource
// carrying the WRONG upstream token, so the e2e upstream's Basic-auth
// middleware rejects every request haybale forwards. The client must see
// a 502 — never the upstream's 401 — with no WWW-Authenticate header (so
// a real git client never re-prompts for a credential the sandbox has no
// way to supply), and haybale must log the upstream_auth_failed security
// event.
func TestPostInjectionUpstream401Maps502(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)

	upstreamSrv, _ := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-502"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: []policy.Permission{policy.PermissionRead}},
	})
	// The wrong upstream token: newUpstream's Basic-auth middleware
	// rejects it with a 401, which haybale's modifyResponse must then
	// map to a 502 for the client.
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, "wrong-upstream-token")

	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, nil))
	haybale := mustNewProxy(t, map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, logger)
	haybaleSrv := httptest.NewServer(haybale)
	t.Cleanup(haybaleSrv.Close)

	infoRefsURL := haybaleSrv.URL + "/" + hostKey + "/" + owner + "/" + repoName + ".git/info/refs?service=git-upload-pack"
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
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want it stripped so a real git client never re-prompts", got)
	}
	if logOutput := waitForLogSubstring(logBuf, "upstream_auth_failed"); !strings.Contains(logOutput, "upstream_auth_failed") {
		t.Errorf("log output = %q, want it to contain the upstream_auth_failed security event", logOutput)
	}

	// Also exercise the real git subprocess path: with GIT_TERMINAL_PROMPT=0
	// and a no-op GIT_ASKPASS, a client that saw a genuine 401 with a
	// WWW-Authenticate challenge would fail with "terminal prompts
	// disabled" while trying to re-fill credentials (exactly
	// TestBadOrAbsentTokenMapsTo401's "absent token" case); a client that
	// sees a 502 instead has nothing to re-prompt for and fails with a
	// plain HTTP-error message.
	cloneURL := withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token)
	clientEnv := isolatedGitEnv(t.TempDir())
	cloneDir := filepath.Join(t.TempDir(), "clone")
	out := runGitExpectError(t, gitPath, t.TempDir(), clientEnv, "clone", "--quiet", cloneURL, cloneDir)
	if strings.Contains(out, "terminal prompts disabled") {
		t.Errorf("git clone output = %q, must not attempt a credential re-prompt after a 502", out)
	}
}
