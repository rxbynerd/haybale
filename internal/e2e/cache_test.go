// These tests exercise the response cache with real git clients against
// the git-http-backend upstream: deduplication, coalescing, distinct
// entries per request shape, push invalidation, unstorable responses,
// bypasses, policy before lookup, Cache-Status and the disk budget.
package e2e

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/pktline"
	"github.com/rxbynerd/haybale/internal/policy"
)

var readOnly = []policy.Permission{policy.PermissionRead}

// TestSecondCloneIsServedFromCache: two identical clones cost one upstream
// pack transfer. With the default refs policy every clone still asks the
// upstream for the advertisement and ls-refs, so the second clone's only
// saving is the fetch POST, which is the large one.
func TestSecondCloneIsServedFromCache(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{}, readOnly)

	_, _, first := h.clone(t, "-c", "protocol.version=2")
	_, _, second := h.clone(t, "-c", "protocol.version=2")
	if first != h.headSHA || second != h.headSHA {
		t.Errorf("clone HEADs = %s, %s; want %s", first, second, h.headSHA)
	}
	h.expectCounts(t, 2, 2, 1)
	if packs := h.packEntries(t); len(packs) != 1 {
		t.Errorf("pack entries = %v, want one", packs)
	}
}

// TestGzippedFetchRequestIsCached: a repository with at least forty refs
// makes git gzip the fetch request body. The cache decodes it to classify
// and key the request, sends the upstream an identity body, and serves
// the second clone from the entry.
func TestGzippedFetchRequestIsCached(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{branches: 45}, readOnly)

	_, _, first := h.clone(t, "-c", "protocol.version=2")
	_, _, second := h.clone(t, "-c", "protocol.version=2")
	if first != h.headSHA || second != h.headSHA {
		t.Errorf("clone HEADs = %s, %s; want %s", first, second, h.headSHA)
	}

	inbound := h.inbound.Encodings(endpointFetch)
	if len(inbound) != 2 || inbound[0] != "gzip" || inbound[1] != "gzip" {
		t.Fatalf("client fetch Content-Encoding = %q, want gzip on both clones (the fixture must produce a body over 1024 bytes)", inbound)
	}
	h.expectCounts(t, 2, 2, 1)
	if up := h.upstream.Encodings(endpointFetch); len(up) != 1 || up[0] != "" {
		t.Errorf("upstream fetch Content-Encoding = %q, want one identity body", up)
	}
}

// TestConcurrentClonesCoalesce: four clones started together cost one
// upstream pack transfer. Whether a clone joins the fill in flight or
// finds the committed entry, none of them starts a second fetch.
func TestConcurrentClonesCoalesce(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{blobBytes: 512 << 10}, readOnly)

	const parallelism = 4
	results := make([]cloneResult, parallelism)
	var wg sync.WaitGroup
	for i := range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = cloneOnce(h.gitPath, h.cloneURL, t.TempDir())
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Errorf("clone %d: %v", i, r.err)
			continue
		}
		if r.sha != h.headSHA {
			t.Errorf("clone %d: HEAD = %s, want %s", i, r.sha, h.headSHA)
		}
	}
	if got := h.upstream.Count(endpointFetch); got != 1 {
		t.Errorf("upstream fetch requests = %d, want 1 for four concurrent clones", got)
	}
}

// TestShallowAndFullClonesAreDistinctEntries: a --depth 1 clone and a full
// clone send different fetch arguments, so each is its own entry and each
// hits on repeat.
func TestShallowAndFullClonesAreDistinctEntries(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{}, readOnly)

	for range 2 {
		if _, _, sha := h.clone(t, "--depth", "1"); sha != h.headSHA {
			t.Errorf("shallow clone HEAD = %s, want %s", sha, h.headSHA)
		}
		if _, _, sha := h.clone(t); sha != h.headSHA {
			t.Errorf("full clone HEAD = %s, want %s", sha, h.headSHA)
		}
	}
	if got := h.upstream.Count(endpointFetch); got != 2 {
		t.Errorf("upstream fetch requests = %d, want 2 (one per clone shape)", got)
	}
	if packs := h.packEntries(t); len(packs) != 2 {
		t.Errorf("pack entries = %v, want two", packs)
	}
}

// TestProtocolV0CloneHits: a protocol v0 client (no Git-Protocol header, a
// v0 ref advertisement and want lines with a capability list) is cached
// like a v2 one.
func TestProtocolV0CloneHits(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{}, readOnly)

	for range 2 {
		if _, _, sha := h.clone(t, "-c", "protocol.version=0"); sha != h.headSHA {
			t.Errorf("v0 clone HEAD = %s, want %s", sha, h.headSHA)
		}
	}
	if got := h.upstream.GitProtocol(); got != "" {
		t.Errorf("upstream saw Git-Protocol = %q from a v0 client, want none", got)
	}
	h.expectCounts(t, 2, 0, 1)
}

// TestPushInvalidatesRefsEntries: with refsMaxAge above zero a clone after
// a push through the proxy still sees the pushed commit, because the push
// deleted the repository's refs entries.
func TestPushInvalidatesRefsEntries(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{refsMaxAge: time.Minute}, bareRepoOptions{}, []policy.Permission{policy.PermissionRead, policy.PermissionWrite})

	dir, env, sha := h.clone(t, "-c", "protocol.version=2")
	if sha != h.headSHA {
		t.Fatalf("first clone HEAD = %s, want %s", sha, h.headSHA)
	}
	if err := os.WriteFile(filepath.Join(dir, "NEWFILE.md"), []byte("pushed through the cache harness\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, h.gitPath, dir, env, "add", "NEWFILE.md")
	runGit(t, h.gitPath, dir, env, "commit", "--quiet", "-m", "add NEWFILE.md")
	pushed := headOf(t, h.gitPath, dir, env)
	runGit(t, h.gitPath, dir, env, "push", "--quiet", "origin", "HEAD:main")

	if _, _, sha := h.clone(t, "-c", "protocol.version=2"); sha != pushed {
		t.Errorf("clone after push HEAD = %s, want the pushed commit %s (stale refs served)", sha, pushed)
	}
	// Both clones asked upstream for refs: the entries the first clone
	// stored were removed by the push rather than served to the second.
	if got := h.upstream.Count(endpointLsRefs); got != 2 {
		t.Errorf("upstream ls-refs requests = %d, want 2", got)
	}
}

// TestUnstorableResponsesAreNotStored: an in-band ERR from upload-pack
// (a want for an unknown object) and a response cut short by the upstream
// are delivered but never stored, and the next request goes upstream.
func TestUnstorableResponsesAreNotStored(t *testing.T) {
	t.Run("ERR packet", func(t *testing.T) {
		h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{}, readOnly)
		body := pktStream(t, "command=fetch\n", pktline.Delim,
			"want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "done\n", pktline.Flush)
		for i := range 2 {
			req, err := http.NewRequest(http.MethodPost, h.serverURL+"/"+hostKey+"/"+owner+"/"+repoName+".git/git-upload-pack", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth("haybale-e2e", h.token)
			req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
			req.Header.Set("Git-Protocol", "version=2")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(got), "ERR") {
				t.Fatalf("request %d: status %d body %q, want upstream's 200 with its ERR packet", i, resp.StatusCode, got)
			}
		}
		if got := h.upstream.Count(endpointFetch); got != 2 {
			t.Errorf("upstream fetch requests = %d, want 2: an ERR response must not be served from the cache", got)
		}
		if packs := h.packEntries(t); len(packs) != 0 {
			t.Errorf("pack entries = %v, want none", packs)
		}
	})

	t.Run("truncated response", func(t *testing.T) {
		h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{blobBytes: 256 << 10}, readOnly)
		h.faults.truncateFetch.Store(true)
		env := isolatedGitEnv(t.TempDir())
		runGitExpectError(t, h.gitPath, t.TempDir(), env, "clone", "--quiet", h.cloneURL, filepath.Join(t.TempDir(), "clone"))
		if packs := h.packEntries(t); len(packs) != 0 {
			t.Fatalf("pack entries after a truncated response = %v, want none", packs)
		}

		h.faults.truncateFetch.Store(false)
		if _, _, sha := h.clone(t); sha != h.headSHA {
			t.Errorf("clone after the fault HEAD = %s, want %s", sha, h.headSHA)
		}
		if got := h.upstream.Count(endpointFetch); got != 2 {
			t.Errorf("upstream fetch requests = %d, want 2", got)
		}
	})
}

// TestIncrementalFetchBypassesTheCache: a fetch into an existing clone
// sends have lines, which the cache never serves; the upstream sees it.
func TestIncrementalFetchBypassesTheCache(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{}, bareRepoOptions{}, readOnly)

	dir, env, _ := h.clone(t, "-c", "protocol.version=2")

	// Advance the upstream directly, outside the proxy, so the clone is
	// behind and its fetch has something to negotiate for.
	work := t.TempDir()
	workEnv := isolatedGitEnv(t.TempDir())
	runGit(t, h.gitPath, t.TempDir(), workEnv, "clone", "--quiet", h.bareDir, work)
	if err := os.WriteFile(filepath.Join(work, "MORE.md"), []byte("a second commit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, h.gitPath, work, workEnv, "add", "MORE.md")
	runGit(t, h.gitPath, work, workEnv, "commit", "--quiet", "-m", "second commit")
	want := headOf(t, h.gitPath, work, workEnv)
	runGit(t, h.gitPath, work, workEnv, "push", "--quiet", "origin", "HEAD:main")

	runGit(t, h.gitPath, dir, env, "-c", "protocol.version=2", "fetch", "--quiet", "origin")
	if got := strings.TrimSpace(runGit(t, h.gitPath, dir, env, "rev-parse", "origin/main")); got != want {
		t.Errorf("origin/main after fetch = %s, want %s", got, want)
	}
	if got := h.upstream.Count(endpointFetch); got != 2 {
		t.Errorf("upstream fetch requests = %d, want 2 (clone, then the incremental fetch)", got)
	}
	if got := h.upstream.Haves(); got < 1 {
		t.Errorf("upstream saw %d fetch requests with have lines, want at least 1", got)
	}
}

// TestPolicyDeniedRequestWithCacheEnabled: a denied read is a 404 that
// never reaches the cache or the upstream.
func TestPolicyDeniedRequestWithCacheEnabled(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)
	projectRoot := t.TempDir()
	newBareRepoWithCommit(t, gitPath, projectRoot, owner, repoName)
	upstreamSrv, rec := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL := mustParseURL(t, upstreamSrv.URL)

	const testID = "run-e2e-cache-denied"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, "some-other-repo")}, Permissions: readOnly},
	})
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	c, cacheDir := newTestCache(t, cacheSettings{})
	haybale := mustNewProxyWithCache(t, upstreamURL, creds, auth, eng, c)
	haybaleSrv := newServer(t, haybale)

	for _, path := range []string{
		"/" + hostKey + "/" + owner + "/" + repoName + ".git/info/refs?service=git-upload-pack",
		"/" + hostKey + "/" + owner + "/" + repoName + ".git/git-upload-pack",
	} {
		method := http.MethodGet
		var body io.Reader
		if strings.HasSuffix(path, "git-upload-pack") {
			method = http.MethodPost
			body = strings.NewReader(pktStream(t, "command=ls-refs\n", pktline.Flush))
		}
		req, err := http.NewRequest(method, haybaleSrv.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("haybale-e2e", token)
		req.Header.Set("Git-Protocol", "version=2")
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404", method, path, resp.StatusCode)
		}
		if _, ok := resp.Header["Cache-Status"]; ok {
			t.Errorf("%s %s: a denied request carried Cache-Status", method, path)
		}
	}
	if rec.Count(endpointInfoRefs)+rec.Count(endpointLsRefs)+rec.Count(endpointFetch) != 0 {
		t.Error("upstream saw a request for a policy-denied read")
	}
	if files := cacheEntries(t, cacheDir); len(files) != 0 {
		t.Errorf("cache directory gained %v for a policy-denied read", files)
	}
}

// TestCacheStatusHeader: with exposeStatus the response carries RFC 9211
// Cache-Status values for a miss, a hit, and a bypass; by default the
// header is absent.
func TestCacheStatusHeader(t *testing.T) {
	get := func(t *testing.T, h *cacheHarness) http.Header {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, h.serverURL+"/"+hostKey+"/"+owner+"/"+repoName+".git/info/refs?service=git-upload-pack", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("haybale-e2e", h.token)
		req.Header.Set("Git-Protocol", "version=2")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		return resp.Header
	}
	haves := func(t *testing.T, h *cacheHarness) http.Header {
		t.Helper()
		body := pktStream(t, "command=fetch\n", pktline.Delim,
			"want "+h.headSHA+"\n", "have aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "done\n", pktline.Flush)
		req, err := http.NewRequest(http.MethodPost, h.serverURL+"/"+hostKey+"/"+owner+"/"+repoName+".git/git-upload-pack", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("haybale-e2e", h.token)
		req.Header.Set("Git-Protocol", "version=2")
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.Header
	}

	t.Run("exposed", func(t *testing.T) {
		h := newCacheHarness(t, cacheSettings{exposeStatus: true, refsMaxAge: time.Minute}, bareRepoOptions{}, readOnly)
		if got := get(t, h).Get("Cache-Status"); got != "haybale; fwd=miss" {
			t.Errorf("first advertisement Cache-Status = %q, want %q", got, "haybale; fwd=miss")
		}
		if got := get(t, h).Get("Cache-Status"); got != "haybale; hit" {
			t.Errorf("second advertisement Cache-Status = %q, want %q", got, "haybale; hit")
		}
		if got := haves(t, h).Get("Cache-Status"); got != "haybale; fwd=bypass" {
			t.Errorf("fetch with haves Cache-Status = %q, want %q", got, "haybale; fwd=bypass")
		}
		if got := h.upstream.Count(endpointInfoRefs); got != 1 {
			t.Errorf("upstream info/refs requests = %d, want 1", got)
		}
	})
	t.Run("default", func(t *testing.T) {
		h := newCacheHarness(t, cacheSettings{refsMaxAge: time.Minute}, bareRepoOptions{}, readOnly)
		for i := range 2 {
			if _, ok := get(t, h)["Cache-Status"]; ok {
				t.Errorf("advertisement %d carried Cache-Status without exposeStatus", i)
			}
		}
		if _, ok := haves(t, h)["Cache-Status"]; ok {
			t.Error("bypassed fetch carried Cache-Status without exposeStatus")
		}
	})
}

// TestTinyDiskBudgetBypassesLargeClone: a pack larger than maxEntrySize is
// streamed to the first clone through the spool but not stored, and the
// key is marked so the second clone passes straight through; both
// succeed.
func TestTinyDiskBudgetBypassesLargeClone(t *testing.T) {
	h := newCacheHarness(t, cacheSettings{maxDiskSize: 2 << 20, maxEntrySize: 64 << 10}, bareRepoOptions{blobBytes: 300 << 10}, readOnly)

	for i := range 2 {
		if _, _, sha := h.clone(t, "-c", "protocol.version=2"); sha != h.headSHA {
			t.Errorf("clone %d HEAD = %s, want %s", i, sha, h.headSHA)
		}
	}
	if got := h.upstream.Count(endpointFetch); got != 2 {
		t.Errorf("upstream fetch requests = %d, want 2 (an oversize pack is never served from the cache)", got)
	}
	if packs := h.packEntries(t); len(packs) != 0 {
		t.Errorf("pack entries = %v, want none for an oversize pack", packs)
	}
}

// pktStream encodes parts as a pkt-line stream: a string becomes a data
// packet and a pktline.Kind the corresponding special packet.
func pktStream(t *testing.T, parts ...any) string {
	t.Helper()
	var out []byte
	var err error
	for _, part := range parts {
		switch v := part.(type) {
		case string:
			out, err = pktline.AppendData(out, []byte(v))
		case pktline.Kind:
			out, err = pktline.AppendPacket(out, pktline.Packet{Kind: v})
		default:
			t.Fatalf("pktStream: unsupported part %T", part)
		}
		if err != nil {
			t.Fatalf("pktStream: %v", err)
		}
	}
	return string(out)
}
