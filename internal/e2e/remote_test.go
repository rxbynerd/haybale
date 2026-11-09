package e2e

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store"
	"github.com/rxbynerd/haybale/internal/cache/s3store/s3fake"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/proxy"
	"github.com/rxbynerd/haybale/internal/upstream"
)

// remotePrefix is the bucket prefix the replicas share.
const remotePrefix = "e2e/"

// replica is one haybale proxy with its own cache directory, sharing the
// remote tier with its peers.
type replica struct {
	cache    *cache.Cache
	cacheDir string
	metrics  *sdkmetric.ManualReader
	statuses *statusRecorder
	cloneURL string
}

// statusRecorder keeps the Cache-Status of every upload-pack POST
// response, in order.
type statusRecorder struct {
	mu   sync.Mutex
	post []string
}

func (s *statusRecorder) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			s.mu.Lock()
			s.post = append(s.post, w.Header().Get("Cache-Status"))
			s.mu.Unlock()
		}
	})
}

// last returns the Cache-Status of the latest upload-pack POST, which
// for a clone is its fetch.
func (s *statusRecorder) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.post) == 0 {
		return ""
	}
	return s.post[len(s.post)-1]
}

// newReplica builds a proxy whose cache seals under kr and uses the
// fake's bucket as its remote tier.
func newReplica(t *testing.T, upstreamURL *url.URL, creds map[string]upstream.CredentialSource, auth identity.Authenticator, eng policy.Engine, token string, kr cache.Keyring, fake *s3fake.Server) *replica {
	t.Helper()
	store, err := s3store.New(context.Background(), s3store.Config{
		Bucket:         s3fake.Bucket,
		Prefix:         remotePrefix,
		Region:         "us-east-1",
		Endpoint:       fake.URL(),
		ForcePathStyle: true,
		HeaderTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("s3store.New(): %v", err)
	}
	metrics, reader := observability.NewTestMetrics()
	dir := filepath.Join(t.TempDir(), "cache")
	c, err := cache.New(cache.Options{
		Dir:                   dir,
		Keyring:               kr,
		MaxDiskSize:           256 << 20,
		MaxEntrySize:          8 << 20,
		MaxConcurrentFills:    8,
		MaxRequestBody:        1 << 20,
		Retention:             time.Hour,
		AccessRecheck:         5 * time.Minute,
		ResponseHeaderTimeout: time.Minute,
		IdleTimeout:           time.Minute,
		ExposeStatus:          true,
		Remote:                store,
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
	p, err := proxy.New(map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, discardLogger(), metrics, proxy.WithCache(c))
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	statuses := &statusRecorder{}
	srv := httptest.NewServer(statuses.handler(p))
	t.Cleanup(srv.Close)
	return &replica{
		cache:    c,
		cacheDir: dir,
		metrics:  reader,
		statuses: statuses,
		cloneURL: withToken(t, srv.URL+"/"+hostKey+"/"+owner+"/"+repoName+".git", token),
	}
}

func (r *replica) clone(t *testing.T, gitPath string) string {
	t.Helper()
	env := isolatedGitEnv(t.TempDir())
	dir := filepath.Join(t.TempDir(), "clone")
	runGit(t, gitPath, t.TempDir(), env, "clone", "--quiet", "-c", "protocol.version=2", r.cloneURL, dir)
	return headOf(t, gitPath, dir, env)
}

func (r *replica) packEntries(t *testing.T) []string {
	t.Helper()
	var packs []string
	for _, f := range cacheEntries(t, r.cacheDir) {
		if strings.HasPrefix(f, "v1/pack/") {
			packs = append(packs, f)
		}
	}
	return packs
}

// fillBytes totals fill_bytes for tier.
func (r *replica) fillBytes(t *testing.T, tier string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.metrics.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != "haybale.response_cache.fill_bytes.total" {
				continue
			}
			for _, dp := range md.Data.(metricdata.Sum[int64]).DataPoints {
				if v, _ := dp.Attributes.Value("haybale.tier"); v.AsString() == tier {
					total += dp.Value
				}
			}
		}
	}
	return total
}

func remoteObjects(fake *s3fake.Server, prefix string) []string {
	var keys []string
	for k := range fake.Objects() {
		if strings.HasPrefix(k, remotePrefix+prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRemoteTierSharesEntriesBetweenReplicas: two replicas with their own
// cache directories, sealing under the same configured key and sharing
// one bucket. A clone through A uploads its entries, so the same clone
// through B fills from the remote tier instead of upstream. B reports the
// fill as a miss (the remote tier feeds a fill, as upstream does) and
// counts its bytes under tier remote. A purge through A with the remote
// tier writes the purge marker, and B drops its older entries at its next
// refs request, so B's next clone fetches upstream again.
func TestRemoteTierSharesEntriesBetweenReplicas(t *testing.T) {
	gitPath, httpBackendPath := requireGit(t)
	s3fake.IsolateAWSEnv(t)

	projectRoot := t.TempDir()
	_, headSHA := newBareRepo(t, gitPath, projectRoot, owner, repoName, bareRepoOptions{})
	upstreamSrv, upstreamRec := newUpstream(t, httpBackendPath, projectRoot)
	upstreamURL := mustParseURL(t, upstreamSrv.URL)

	const testID = "run-e2e-remote"
	auth, token := mintTestToken(t, testID)
	eng := newPolicy(t, []policy.Rule{
		{Identities: []string{testID}, Repos: []string{repoKey(hostKey, owner, repoName)}, Permissions: readOnly},
	})
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)

	key := make([]byte, cache.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	kr, err := cache.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	fake := s3fake.New(t)
	a := newReplica(t, upstreamURL, creds, auth, eng, token, kr, fake)
	b := newReplica(t, upstreamURL, creds, auth, eng, token, kr, fake)

	if sha := a.clone(t, gitPath); sha != headSHA {
		t.Fatalf("clone through A HEAD = %s, want %s", sha, headSHA)
	}
	waitForCondition(t, "A's pack upload", func() bool { return len(remoteObjects(fake, "v1/pack/")) == 1 })

	if sha := b.clone(t, gitPath); sha != headSHA {
		t.Fatalf("clone through B HEAD = %s, want %s", sha, headSHA)
	}
	if got := upstreamRec.Count(endpointFetch); got != 1 {
		t.Errorf("upstream fetch requests = %d, want 1: B should fill from the remote tier", got)
	}
	if got := b.statuses.last(); got != "haybale; fwd=miss" {
		t.Errorf("B's fetch Cache-Status = %q, want the fill form %q", got, "haybale; fwd=miss")
	}
	if got := b.fillBytes(t, observability.TierRemote); got == 0 {
		t.Error("B recorded no fill bytes from the remote tier")
	}
	if got := b.fillBytes(t, observability.TierUpstream); got == 0 {
		t.Error("B recorded no upstream fill bytes for its refs requests")
	}
	if packs := b.packEntries(t); len(packs) != 1 {
		t.Errorf("B's pack entries = %v, want the remote entry committed locally", packs)
	}

	repo := gitproto.Repo{Host: hostKey, Owner: owner, Name: repoName}
	if _, err := a.cache.Purge(context.Background(), repo, upstreamURL, ""); err != nil {
		t.Fatalf("purge through A: %v", err)
	}
	if got := remoteObjects(fake, "v1/purge/"); len(got) != 1 {
		t.Fatalf("purge markers = %v, want one", got)
	}
	if got := remoteObjects(fake, "v1/pack/"); len(got) != 0 {
		t.Fatalf("remote pack objects after the purge = %v", got)
	}

	if sha := b.clone(t, gitPath); sha != headSHA {
		t.Fatalf("clone through B after the purge HEAD = %s, want %s", sha, headSHA)
	}
	if got := upstreamRec.Count(endpointFetch); got != 2 {
		t.Errorf("upstream fetch requests = %d, want 2: B should drop its purged pack at its next refs request", got)
	}
}
