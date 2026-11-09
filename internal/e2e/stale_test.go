package e2e

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/policy"
	"github.com/rxbynerd/haybale/internal/proxy"
)

const (
	// staleIdentity is the verified identity of the stale tests' client.
	staleIdentity = "run-e2e-stale"
	// unseenRepoName is a repository upstream holds that no test clones
	// before the outage.
	unseenRepoName = "gadgets"
	// staleHeaderTimeout is the cache's response-header timeout in the
	// stale tests: the time a request to a hanging upstream would wait.
	staleHeaderTimeout = 30 * time.Second
)

// outageUpstream serves the fake git upstream on an address a test can
// take down: stop closes the server so connections are refused, and hang
// listens on the same address again but never answers.
type outageUpstream struct {
	srv  *httptest.Server
	addr string

	mu       sync.Mutex
	hangLn   net.Listener
	held     []net.Conn
	accepted atomic.Int32
}

func newOutageUpstream(t *testing.T, handler http.Handler) *outageUpstream {
	t.Helper()
	o := &outageUpstream{srv: httptest.NewServer(handler)}
	o.addr = o.srv.Listener.Addr().String()
	t.Cleanup(o.srv.Close)
	t.Cleanup(o.closeHang)
	return o
}

// stop takes the upstream down; connecting to it is then refused.
func (o *outageUpstream) stop() {
	o.srv.CloseClientConnections()
	o.srv.Close()
}

// hang accepts connections on the upstream's address and never answers
// them.
func (o *outageUpstream) hang(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		t.Fatalf("listen again on %s: %v", o.addr, err)
	}
	o.mu.Lock()
	o.hangLn = ln
	o.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.accepted.Add(1)
			o.mu.Lock()
			o.held = append(o.held, c)
			o.mu.Unlock()
		}
	}()
}

// closeHang stops hanging, so connecting is refused again.
func (o *outageUpstream) closeHang() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.hangLn != nil {
		_ = o.hangLn.Close()
		o.hangLn = nil
	}
	for _, c := range o.held {
		_ = c.Close()
	}
	o.held = nil
}

// cacheStatuses records the Cache-Status of every response, with its
// method and endpoint, in order. The 401 challenges git receives before
// it sends its credential are left out.
type cacheStatuses struct {
	mu   sync.Mutex
	seen []string
}

func (s *cacheStatuses) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if w.Header().Get("WWW-Authenticate") != "" {
			return
		}
		endpoint := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+endpoint+" "+w.Header().Get("Cache-Status"))
		s.mu.Unlock()
	})
}

// since returns the statuses recorded after the first n.
func (s *cacheStatuses) since(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen[n:]...)
}

func (s *cacheStatuses) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// staleHarness is a haybale proxy with a stale-if-error cache in front of
// an upstream the test can take down.
type staleHarness struct {
	gitPath  string
	headSHA  string
	upstream *outageUpstream
	faults   *upstreamFaults
	logs     *syncBuffer
	statuses *cacheStatuses
	baseURL  string
	token    string
}

func newStaleHarness(t *testing.T) *staleHarness {
	t.Helper()
	gitPath, httpBackendPath := requireGit(t)
	projectRoot := t.TempDir()
	bareDir, headSHA := newBareRepo(t, gitPath, projectRoot, owner, repoName, bareRepoOptions{})
	runGit(t, gitPath, bareDir, isolatedGitEnv(t.TempDir()), "config", "http.receivepack", "true")
	newBareRepo(t, gitPath, projectRoot, owner, unseenRepoName, bareRepoOptions{})

	handler, _, faults := newUpstreamHandler(httpBackendPath, projectRoot)
	up := newOutageUpstream(t, handler)
	upstreamURL, err := url.Parse(up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	auth, token := mintTestToken(t, staleIdentity)
	eng := newPolicy(t, []policy.Rule{{
		Identities:  []string{staleIdentity},
		Repos:       []string{repoKey(hostKey, owner, repoName), repoKey(hostKey, owner, unseenRepoName)},
		Permissions: []policy.Permission{policy.PermissionRead, policy.PermissionWrite},
	}})
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	kr, err := cache.EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(cache.Options{
		Dir:                   filepath.Join(t.TempDir(), "cache"),
		Keyring:               kr,
		MaxDiskSize:           256 << 20,
		MaxEntrySize:          8 << 20,
		MaxConcurrentFills:    8,
		MaxRequestBody:        1 << 20,
		Retention:             time.Hour,
		AccessRecheck:         5 * time.Minute,
		ResponseHeaderTimeout: staleHeaderTimeout,
		IdleTimeout:           time.Minute,
		ExposeStatus:          true,
		StaleIfErrorFor:       time.Hour,
		Logger:                logger,
		Metrics:               observability.NewNoopMetrics(),
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
	creds := credentialsForHost(t, hostKey, upstreamBasicAuthUsername, upstreamBasicAuthToken)
	p, err := proxy.New(map[string]*url.URL{hostKey: upstreamURL}, creds, auth, eng, logger, observability.NewNoopMetrics(), proxy.WithCache(c))
	if err != nil {
		t.Fatalf("proxy.New(): %v", err)
	}
	statuses := &cacheStatuses{}
	srv := httptest.NewServer(statuses.handler(p))
	t.Cleanup(srv.Close)
	return &staleHarness{
		gitPath: gitPath, headSHA: headSHA, upstream: up, faults: faults,
		logs: logs, statuses: statuses, baseURL: srv.URL, token: token,
	}
}

func (h *staleHarness) cloneURL(t *testing.T, name string) string {
	return withToken(t, h.baseURL+"/"+hostKey+"/"+owner+"/"+name+".git", h.token)
}

// clone clones name through the proxy with protocol v2 and returns the
// clone directory and its environment.
func (h *staleHarness) clone(t *testing.T, name string) (dir string, env []string) {
	t.Helper()
	env = isolatedGitEnv(t.TempDir())
	dir = filepath.Join(t.TempDir(), "clone")
	runGit(t, h.gitPath, t.TempDir(), env, "clone", "--quiet", "-c", "protocol.version=2", h.cloneURL(t, name), dir)
	return dir, env
}

// cloneFails asserts that cloning name through the proxy fails.
func (h *staleHarness) cloneFails(t *testing.T, name string) {
	t.Helper()
	env := isolatedGitEnv(t.TempDir())
	runGitExpectError(t, h.gitPath, t.TempDir(), env, "clone", "--quiet", "-c", "protocol.version=2", h.cloneURL(t, name), filepath.Join(t.TempDir(), "clone"))
}

// wantStatuses asserts the Cache-Status of every response since mark.
func (h *staleHarness) wantStatuses(t *testing.T, mark int, want ...string) {
	t.Helper()
	got := h.statuses.since(mark)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("responses since the mark =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// TestStaleIfErrorServesClonesDuringAnOutage: once the upstream is down, a
// repeat of a clone that went through haybale still succeeds, its refs
// requests answered stale and logged as security events, and the health
// gate keeps a later clone from waiting on an upstream that accepts
// connections but never answers. A push and a clone of a repository
// haybale never saw still fail.
func TestStaleIfErrorServesClonesDuringAnOutage(t *testing.T) {
	h := newStaleHarness(t)
	h.clone(t, repoName)

	h.upstream.stop()
	mark := h.statuses.count()
	dir, env := h.clone(t, repoName)
	if sha := headOf(t, h.gitPath, dir, env); sha != h.headSHA {
		t.Errorf("outage clone HEAD = %s, want %s", sha, h.headSHA)
	}
	h.wantStatuses(t, mark,
		"GET refs haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit",
	)
	logs := waitForLogSubstring(h.logs, `"cache":"stale"`)
	for _, want := range []string{
		`"event":"cache_stale_served"`,
		`"identity":"` + staleIdentity + `"`,
		`"msg":"upstream health gate opened; stale entries answer requests without contacting upstream"`,
		`"cache":"stale"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs do not contain %s", want)
		}
	}
	if n := strings.Count(logs, `"event":"cache_stale_served"`); n != 2 {
		t.Errorf("cache_stale_served events = %d, want one per stale response", n)
	}

	// The gate is open, so a clone against an upstream that would hang
	// every request for the header timeout is answered without
	// connecting at all.
	h.upstream.hang(t)
	start := time.Now()
	h.clone(t, repoName)
	if elapsed := time.Since(start); elapsed > staleHeaderTimeout/3 {
		t.Errorf("clone with the gate open took %v, want well under the %v header timeout", elapsed, staleHeaderTimeout)
	}
	if n := h.upstream.accepted.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections with the gate open, want none", n)
	}
	h.upstream.closeHang()

	if err := os.WriteFile(filepath.Join(dir, "OUTAGE.md"), []byte("written during the outage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, h.gitPath, dir, env, "add", "OUTAGE.md")
	runGit(t, h.gitPath, dir, env, "commit", "--quiet", "-m", "add OUTAGE.md")
	runGitExpectError(t, h.gitPath, dir, env, "push", "--quiet", "origin", "HEAD:main")

	h.cloneFails(t, unseenRepoName)
}

// TestStaleIfErrorNeverAnswersARejectedCredential: an upstream that
// rejects haybale's credential is not an outage, so a repeat clone fails
// with the sanitised 502 and nothing is served stale.
func TestStaleIfErrorNeverAnswersARejectedCredential(t *testing.T) {
	h := newStaleHarness(t)
	h.clone(t, repoName)

	h.faults.rejectCredentials.Store(true)
	mark := h.statuses.count()
	h.cloneFails(t, repoName)
	h.wantStatuses(t, mark, "GET refs haybale; fwd=miss")
	logs := waitForLogSubstring(h.logs, `"status":502`)
	if strings.Contains(logs, `"event":"cache_stale_served"`) {
		t.Error("a rejected credential was answered stale")
	}
	if !strings.Contains(logs, `"event":"upstream_auth_failed"`) {
		t.Error("the rejected credential was not logged as upstream_auth_failed")
	}
}
