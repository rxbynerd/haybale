package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/proxy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// cacheSettings are the knobs the cache scenarios vary; everything else
// is fixed small so a test clone exercises the limits.
type cacheSettings struct {
	exposeStatus bool
	refsMaxAge   time.Duration
	maxDiskSize  int64
	maxEntrySize int64
}

// newTestCache opens a response cache on a fresh directory under an
// ephemeral key, closing it when the test ends.
func newTestCache(t *testing.T, s cacheSettings, metrics *observability.Metrics) (*cache.Cache, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	kr, err := cache.EphemeralKeyring()
	if err != nil {
		t.Fatalf("cache.EphemeralKeyring(): %v", err)
	}
	maxDisk, maxEntry := s.maxDiskSize, s.maxEntrySize
	if maxDisk == 0 {
		maxDisk = 256 << 20
	}
	if maxEntry == 0 {
		maxEntry = 8 << 20
	}
	c, err := cache.New(cache.Options{
		Dir:                   dir,
		Keyring:               kr,
		MaxDiskSize:           maxDisk,
		MaxEntrySize:          maxEntry,
		MaxConcurrentFills:    8,
		MaxRequestBody:        1 << 20,
		Retention:             time.Hour,
		RefsMaxAge:            s.refsMaxAge,
		AccessRecheck:         5 * time.Minute,
		ResponseHeaderTimeout: time.Minute,
		IdleTimeout:           time.Minute,
		ExposeStatus:          s.exposeStatus,
		Logger:                discardLogger(),
		Metrics:               metrics,
	})
	if err != nil {
		t.Fatalf("cache.New(): %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("cache.Close(): %v", err)
		}
	})
	return c, dir
}

// cacheEntries lists the entry files under the cache directory, relative
// to it with forward slashes, so a test can assert what was stored.
func cacheEntries(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return files
}

// cacheHarness is a haybale proxy with a response cache in front of the
// real git-http-backend upstream, with recorders on both sides: inbound
// sees what the git client sent and upstream sees what haybale forwarded.
type cacheHarness struct {
	gitPath   string
	bareDir   string
	headSHA   string
	upstream  *requestRecorder
	faults    *upstreamFaults
	inbound   *requestRecorder
	cache     *cache.Cache
	cacheDir  string
	metrics   *sdkmetric.ManualReader
	serverURL string
	token     string
	cloneURL  string
}

// newCacheHarness builds the harness for one test. perms are the
// permissions the test identity holds on the fixture repository.
func newCacheHarness(t *testing.T, settings cacheSettings, repo bareRepoOptions, perms []policy.Permission) *cacheHarness {
	t.Helper()
	gitPath, httpBackendPath := requireGit(t)

	projectRoot := t.TempDir()
	bareDir, headSHA := newBareRepo(t, gitPath, projectRoot, owner, repoName, repo)
	// Pushes through the proxy need receive-pack enabled on the bare repo.
	runGit(t, gitPath, bareDir, isolatedGitEnv(t.TempDir()), "config", "http.receivepack", "true")

	upstreamSrv, upstreamRec, faults := newFaultyUpstream(t, httpBackendPath, projectRoot)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamSrv.URL, err)
	}

	const testID = "run-e2e-cache"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: perms},
	})
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)

	metrics, reader := observability.NewTestMetrics()
	c, cacheDir := newTestCache(t, settings, metrics)
	haybale, err := proxy.New(map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger(), metrics, proxy.WithCache(c))
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	inbound := newRequestRecorder()
	haybaleSrv := httptest.NewServer(inbound.handler(haybale))
	t.Cleanup(haybaleSrv.Close)

	return &cacheHarness{
		gitPath:   gitPath,
		bareDir:   bareDir,
		headSHA:   headSHA,
		upstream:  upstreamRec,
		faults:    faults,
		inbound:   inbound,
		cache:     c,
		cacheDir:  cacheDir,
		metrics:   reader,
		serverURL: haybaleSrv.URL,
		token:     token,
		cloneURL:  withToken(t, haybaleSrv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token),
	}
}

// clone runs `git clone` through the proxy into a fresh directory with
// the given extra arguments and returns the clone directory, its
// environment and its HEAD SHA.
func (h *cacheHarness) clone(t *testing.T, extra ...string) (dir string, env []string, sha string) {
	t.Helper()
	env = isolatedGitEnv(t.TempDir())
	dir = filepath.Join(t.TempDir(), "clone")
	args := append([]string{"clone", "--quiet"}, extra...)
	runGit(t, h.gitPath, t.TempDir(), env, append(args, h.cloneURL, dir)...)
	sha = headOf(t, h.gitPath, dir, env)
	return dir, env, sha
}

func headOf(t *testing.T, gitPath, dir string, env []string) string {
	t.Helper()
	return strings.TrimSpace(runGit(t, gitPath, dir, env, "rev-parse", "HEAD"))
}

// mustParseURL parses rawURL, failing the test on error.
func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return u
}

// mustNewProxyWithCache is mustNewProxy with a response cache installed
// for the single upstream hostKey names.
func mustNewProxyWithCache(t *testing.T, upstreamURL *url.URL, credentialSources map[string]upstream.CredentialSource, authenticator identity.Authenticator, policyEngine policy.Engine, c *cache.Cache) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(map[string]*url.URL{hostKey: upstreamURL}, credentialSources, authenticator, policyEngine, discardLogger(), observability.NewNoopMetrics(), proxy.WithCache(c))
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	return p
}

// newServer serves handler for the test's lifetime.
func newServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// expectCounts asserts the upstream saw exactly the given number of
// requests per endpoint.
func (h *cacheHarness) expectCounts(t *testing.T, infoRefs, lsRefs, fetch int) {
	t.Helper()
	if got := h.upstream.Count(endpointInfoRefs); got != infoRefs {
		t.Errorf("upstream info/refs requests = %d, want %d", got, infoRefs)
	}
	if got := h.upstream.Count(endpointLsRefs); got != lsRefs {
		t.Errorf("upstream ls-refs requests = %d, want %d", got, lsRefs)
	}
	if got := h.upstream.Count(endpointFetch); got != fetch {
		t.Errorf("upstream fetch requests = %d, want %d", got, fetch)
	}
}

// fillsDiscarded returns how many fills ended discarded with reason.
func (h *cacheHarness) fillsDiscarded(t *testing.T, reason string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := h.metrics.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != "haybale.response_cache.fills.total" {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("fills.total is %T", md.Data)
			}
			for _, dp := range sum.DataPoints {
				res, _ := dp.Attributes.Value("haybale.result")
				why, _ := dp.Attributes.Value("haybale.reason")
				if res.AsString() == observability.FillResultDiscarded && why.AsString() == reason {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// refsEntries returns the stored refs entries.
func (h *cacheHarness) refsEntries(t *testing.T) []string {
	t.Helper()
	var refs []string
	for _, f := range cacheEntries(t, h.cacheDir) {
		if strings.HasPrefix(f, "v1/refs/") {
			refs = append(refs, f)
		}
	}
	return refs
}

// packEntries returns the stored pack entries.
func (h *cacheHarness) packEntries(t *testing.T) []string {
	t.Helper()
	var packs []string
	for _, f := range cacheEntries(t, h.cacheDir) {
		if len(f) > 8 && f[:8] == "v1/pack/" {
			packs = append(packs, f)
		}
	}
	return packs
}
