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
	"github.com/rxbynerd/haybale/internal/pktline"
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
	// pastProbeInterval moves the clock past the cache's health gate
	// probe interval, so the next request is admitted as the probe.
	pastProbeInterval = time.Minute
	// pastAccessRecheck moves the clock past the cache's accessRecheck,
	// so a stored pack is no longer a hit.
	pastAccessRecheck = 6 * time.Minute
)

// manualClock is a clock that moves only when the test advances it.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// outageUpstream serves the fake git upstream on an address a test can
// take down: stop closes the server so connections are refused, and hang
// listens on the same address again but never answers.
type outageUpstream struct {
	srv     *httptest.Server
	addr    string
	handler http.Handler

	mu       sync.Mutex
	hangLn   net.Listener
	held     []net.Conn
	accepted atomic.Int32
}

func newOutageUpstream(t *testing.T, handler http.Handler) *outageUpstream {
	t.Helper()
	o := &outageUpstream{srv: httptest.NewServer(handler), handler: handler}
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

// restart serves the upstream on its address again.
func (o *outageUpstream) restart(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		t.Fatalf("listen again on %s: %v", o.addr, err)
	}
	srv := &http.Server{Handler: o.handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
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
// an upstream the test can take down. The cache runs on clock, which
// moves only when the test advances it, so entry ages and the health
// gate's probe interval do not depend on how fast the test runs.
type staleHarness struct {
	gitPath  string
	headSHA  string
	upstream *outageUpstream
	faults   *upstreamFaults
	logs     *syncBuffer
	statuses *cacheStatuses
	clock    *manualClock
	baseURL  string
	token    string
}

// newStaleHarness builds the harness; mutate, when given, adjusts the
// cache options first.
func newStaleHarness(t *testing.T, mutate ...func(*cache.Options)) *staleHarness {
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
	clock := &manualClock{t: time.Now()}
	opts := cache.Options{
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
		Now:                   clock.Now,
	}
	for _, m := range mutate {
		m(&opts)
	}
	c, err := cache.New(opts)
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
		logs: logs, statuses: statuses, clock: clock, baseURL: srv.URL, token: token,
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
// repeat of a clone that went through haybale still succeeds, every
// response answered stale and logged as a security event, and the health
// gate keeps a later clone from waiting on an upstream that accepts
// connections but never answers. A push and a clone of a repository
// haybale never saw still fail. Once the upstream is back and the probe
// interval has passed, the next request probes it, the gate closes and
// clones are served from the upstream again.
func TestStaleIfErrorServesClonesDuringAnOutage(t *testing.T) {
	h := newStaleHarness(t)
	h.clone(t, repoName)

	h.upstream.stop()
	h.clock.Advance(pastAccessRecheck)
	mark := h.statuses.count()
	dir, env := h.clone(t, repoName)
	if sha := headOf(t, h.gitPath, dir, env); sha != h.headSHA {
		t.Errorf("outage clone HEAD = %s, want %s", sha, h.headSHA)
	}
	h.wantStatuses(t, mark,
		"GET refs haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit; fwd=stale",
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
	if n := strings.Count(logs, `"event":"cache_stale_served"`); n != 3 {
		t.Errorf("cache_stale_served events = %d, want one per stale response", n)
	}

	// The gate is open and the clock has not moved, so no probe is due: a
	// clone against an upstream that would hang every request for the
	// header timeout is answered without connecting at all.
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

	h.upstream.restart(t)
	h.clock.Advance(pastProbeInterval)
	mark = h.statuses.count()
	dir, env = h.clone(t, repoName)
	if sha := headOf(t, h.gitPath, dir, env); sha != h.headSHA {
		t.Errorf("clone after the outage HEAD = %s, want %s", sha, h.headSHA)
	}
	h.wantStatuses(t, mark,
		"GET refs haybale; fwd=miss",
		"POST git-upload-pack haybale; fwd=miss",
		"POST git-upload-pack haybale; hit",
	)
	if logs := waitForLogSubstring(h.logs, `"msg":"upstream health gate closed"`); !strings.Contains(logs, `"msg":"upstream health gate closed"`) {
		t.Error("the gate did not close once the upstream answered")
	}
}

// TestStaleIfErrorAnswersAnUpstream5xx: an upstream answering 503 is
// reachable, so the gate stays closed, but every response of a repeat
// clone is answered stale with the upstream's status.
func TestStaleIfErrorAnswersAnUpstream5xx(t *testing.T) {
	h := newStaleHarness(t)
	h.clone(t, repoName)

	h.faults.unavailable.Store(true)
	h.clock.Advance(pastAccessRecheck)
	mark := h.statuses.count()
	dir, env := h.clone(t, repoName)
	if sha := headOf(t, h.gitPath, dir, env); sha != h.headSHA {
		t.Errorf("clone during the 503s HEAD = %s, want %s", sha, h.headSHA)
	}
	h.wantStatuses(t, mark,
		"GET refs haybale; hit; fwd=stale; fwd-status=503",
		"POST git-upload-pack haybale; hit; fwd=stale; fwd-status=503",
		"POST git-upload-pack haybale; hit; fwd=stale; fwd-status=503",
	)
	logs := waitForLogSubstring(h.logs, `"cache":"stale"`)
	if strings.Contains(logs, "upstream health gate opened") {
		t.Error("an upstream 503 opened the health gate")
	}
}

// TestStaleIfErrorAnswersAClonePastTheProbeWithTheSlotHeld: with the only
// pack fill slot held by an uncached fetch stuck on an upstream that
// accepts connections but never answers, a clone that arrives once a probe
// is due is answered stale within the probe deadline instead of waiting on
// that upstream.
func TestStaleIfErrorAnswersAClonePastTheProbeWithTheSlotHeld(t *testing.T) {
	h := newStaleHarness(t, func(o *cache.Options) { o.MaxConcurrentFills = 1 })
	h.clone(t, repoName)
	h.upstream.stop()
	h.clock.Advance(pastAccessRecheck)
	h.clone(t, repoName)
	h.upstream.hang(t)
	defer h.upstream.closeHang()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stuck := make(chan struct{})
	go func() {
		defer close(stuck)
		body := pktStream(t, "command=fetch\n", pktline.Delim, "want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "done\n", pktline.Flush)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/"+hostKey+"/"+owner+"/"+repoName+".git/git-upload-pack", strings.NewReader(body))
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth("haybale-e2e", h.token)
		req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
		req.Header.Set("Git-Protocol", "version=2")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for h.upstream.accepted.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the uncached fetch never reached the hung upstream")
		}
		time.Sleep(10 * time.Millisecond)
	}

	h.clock.Advance(pastProbeInterval)
	mark := h.statuses.count()
	// Each response moves the clock past the probe interval, as the probe
	// deadline does in real time, so every request of the clone finds a
	// probe due unless one is still in flight.
	stopAdvancing := make(chan struct{})
	advancing := make(chan struct{})
	go func() {
		defer close(advancing)
		seen := mark
		for {
			select {
			case <-stopAdvancing:
				return
			case <-time.After(time.Millisecond):
			}
			if n := h.statuses.count(); n > seen {
				seen = n
				h.clock.Advance(pastProbeInterval)
			}
		}
	}()
	start := time.Now()
	h.clone(t, repoName)
	close(stopAdvancing)
	<-advancing
	if elapsed := time.Since(start); elapsed > staleHeaderTimeout/3 {
		t.Errorf("clone with the slot held took %v, want about the probe deadline", elapsed)
	}
	h.wantStatuses(t, mark,
		"GET refs haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit; fwd=stale",
		"POST git-upload-pack haybale; hit; fwd=stale",
	)
	cancel()
	h.upstream.closeHang()
	select {
	case <-stuck:
	case <-time.After(10 * time.Second):
		t.Error("the uncached fetch never finished")
	}
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
