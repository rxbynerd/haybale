package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/pktline"
)

// lateFollower holds the moving parts of a follower that attaches to a
// fill while it is in flight but opens the spool only after the fill has
// decided: the shared fetcher answers headers once two subscribers are
// attached, and the follower waits in the before-open-reader hook until
// the decision hook has fired.
type lateFollower struct {
	fetch   Fetcher
	calls   atomic.Int32
	rec     *httptest.ResponseRecorder
	out     Outcome
	handled bool
	done    chan struct{}
}

func newLateFollower(t *testing.T, c *Cache, r *http.Request, respond func() *http.Response) *lateFollower {
	t.Helper()
	lf := &lateFollower{rec: httptest.NewRecorder(), done: make(chan struct{})}
	attached := make(chan struct{})
	decided := make(chan struct{})
	lf.fetch = fetchFunc(func(context.Context, Request) (*http.Response, error) {
		lf.calls.Add(1)
		<-attached
		return respond(), nil
	})
	var opens atomic.Int32
	c.hooks.beforeOpenReader = func(entryKey) {
		if opens.Add(1) == 2 {
			<-decided
		}
	}
	var once sync.Once
	c.hooks.afterDecision = func(entryKey) { once.Do(func() { close(decided) }) }
	// The goroutine never calls t.Fatal and the cleanup waits for it, so
	// it cannot report a failure after the test has finished.
	t.Cleanup(func() { <-lf.done })
	go func() {
		if !pollFor(func() bool { return subscribersAre(c, 1) }) {
			t.Error("the leader's fill never started")
			close(lf.done)
			return
		}
		go func() {
			defer close(lf.done)
			lf.out, lf.handled, _ = serve(c, lf.rec, r, lf.fetch)
		}()
		if !pollFor(func() bool { return subscribersAre(c, 2) }) {
			t.Error("the late follower never attached to the fill")
		}
		close(attached)
	}()
	return lf
}

func (lf *lateFollower) wait() (Outcome, bool) {
	<-lf.done
	return lf.out, lf.handled
}

func TestLateSubscriberAfterCommitIsServedFromTheEntry(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0; o.ExposeStatus = true })
	want := fetchResultBody(t, 20, 5000)
	lf := newLateFollower(t, c, fetchRequest(t), func() *http.Response {
		return response(http.StatusOK, contentTypeResult, want)
	})
	leader := httptest.NewRecorder()
	out, handled, _ := serve(c, leader, fetchRequest(t), lf.fetch)
	if !handled || !out.Stored {
		t.Fatalf("leader = %+v handled %v, want a stored miss", out, handled)
	}
	lateOut, lateHandled := lf.wait()
	if !lateHandled || lateOut.Result != observability.ResultMiss || !lateOut.Collapsed || !lateOut.Stored {
		t.Fatalf("late subscriber = %+v handled %v, want a stored, collapsed miss", lateOut, lateHandled)
	}
	if !bytes.Equal(lf.rec.Body.Bytes(), want) || !bytes.Equal(leader.Body.Bytes(), want) {
		t.Error("subscribers did not both receive the complete body")
	}
	if got := lf.rec.Header().Get("Cache-Status"); got != "haybale; fwd=miss; collapsed" {
		t.Errorf("late Cache-Status = %q", got)
	}
	if lf.calls.Load() != 1 {
		t.Errorf("upstream fetched %d times, want 1", lf.calls.Load())
	}
	assertStoreIdle(t, c)
}

func TestLateSubscriberAfterDiscardStillReadsTheSpool(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
	want := pkts(t, "ERR upload-pack: not our ref "+oidA+"\n")
	lf := newLateFollower(t, c, fetchRequest(t), func() *http.Response {
		return streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(want)))
	})
	leader := httptest.NewRecorder()
	out, handled, _ := serve(c, leader, fetchRequest(t), lf.fetch)
	if !handled || out.Stored {
		t.Fatalf("leader = %+v handled %v, want an unstored miss", out, handled)
	}
	lateOut, lateHandled := lf.wait()
	if !lateHandled || lateOut.Result != observability.ResultMiss || !lateOut.Collapsed || lateOut.Stored {
		t.Fatalf("late subscriber = %+v handled %v, want an unstored, collapsed miss", lateOut, lateHandled)
	}
	if !bytes.Equal(lf.rec.Body.Bytes(), want) || !bytes.Equal(leader.Body.Bytes(), want) {
		t.Errorf("bodies: leader %q, late %q, want %q", leader.Body.Bytes(), lf.rec.Body.Bytes(), want)
	}
	if lf.calls.Load() != 1 {
		t.Errorf("upstream fetched %d times, want 1", lf.calls.Load())
	}
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("discarded fill left files: %v", files)
	}
	assertStoreIdle(t, c)
}

func TestJoinAfterCommit(t *testing.T) {
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0 })
	want := fetchResultBody(t, 10, 5000)
	var calls atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		calls.Add(1)
		return response(http.StatusOK, contentTypeResult, want), nil
	})
	const n = 6
	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, n)
	outs := make([]Outcome, n)
	var once sync.Once
	c.hooks.afterDecision = func(entryKey) {
		once.Do(func() {
			for i := range n {
				recs[i] = httptest.NewRecorder()
				wg.Add(1)
				go func() {
					defer wg.Done()
					outs[i], _, _ = serve(c, recs[i], fetchRequest(t), fetch)
				}()
			}
		})
	}
	if out, handled, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); !handled || !out.Stored {
		t.Fatalf("leader = %+v handled %v", out, handled)
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream fetched %d times, want 1", calls.Load())
	}
	for i := range n {
		if !bytes.Equal(recs[i].Body.Bytes(), want) {
			t.Errorf("request %d received %d bytes, want %d", i, recs[i].Body.Len(), len(want))
		}
		hit := outs[i].Result == observability.ResultHit
		collapsedMiss := outs[i].Result == observability.ResultMiss && outs[i].Collapsed
		if !hit && !collapsedMiss {
			t.Errorf("request %d outcome = %+v, want a hit or a collapsed miss", i, outs[i])
		}
	}
	assertStoreIdle(t, c)
}

func TestPushBetweenGenerationCheckAndCommitDeletesTheEntry(t *testing.T) {
	m, reader := observability.NewTestMetrics()
	c, _ := newTestCache(t, func(o *Options) { o.RefsMaxAge = time.Minute; o.AccessRecheck = 0; o.Metrics = m })
	c.hooks.beforeCommit = func(key entryKey) {
		if key.Group == GroupRefs {
			c.Invalidate(context.Background(), testRepo, testBaseURL)
		}
	}
	refs := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: advertisementBody(t)}
	rec := httptest.NewRecorder()
	out, handled, _ := serve(c, rec, get(), refs)
	if !handled || out.Result != observability.ResultMiss || out.Stored || !bytes.Equal(rec.Body.Bytes(), refs.body) {
		t.Fatalf("refs fill raced by a push = %+v handled %v, want an unstored miss with the full body", out, handled)
	}
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("entries after the race = %v, want none", files)
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonGeneration); got != 1 {
		t.Errorf("fills discarded generation = %d, want 1", got)
	}
	c.hooks.beforeCommit = nil
	if out, _, _ := serve(c, httptest.NewRecorder(), get(), refs); out.Result != observability.ResultMiss || refs.calls.Load() != 2 {
		t.Errorf("next refs request = %+v with %d fetches, want a miss and 2", out, refs.calls.Load())
	}
	assertStoreIdle(t, c)
}

func TestRefsRequestAfterAPushDoesNotJoinAStaleFill(t *testing.T) {
	c, logs, _ := exitCache(t, func(o *Options) { o.RefsMaxAge = time.Minute })
	pr, pw := io.Pipe()
	var fetches atomic.Int32
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		fetches.Add(1)
		return streamingResponse(contentTypeAdvertisement, pr), nil
	})
	body := advertisementBody(t)
	leaderOut := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(c, httptest.NewRecorder(), get(), fetch)
		leaderOut <- out
	}()
	waitForSubscribers(t, c, 1)
	c.Invalidate(context.Background(), testRepo, testBaseURL)

	type result struct {
		out     Outcome
		handled bool
	}
	afterPush := make(chan result, 1)
	go func() {
		out, handled, _ := serve(c, httptest.NewRecorder(), get(), fetch)
		afterPush <- result{out, handled}
	}()
	answered := false
	select {
	case res := <-afterPush:
		answered = true
		if res.handled || res.out.Result != observability.ResultBypass {
			t.Errorf("request after the push = %+v handled %v, want a bypass", res.out, res.handled)
		}
	case <-time.After(shortly):
		t.Error("request after the push joined the stale fill and waited on it")
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("upstream fetches = %d, want 1: the request must not start a second fill", got)
	}

	_, _ = pw.Write(body)
	_ = pw.Close()
	if !answered {
		<-afterPush
	}
	if recs := logs.records(t, "bypass"); len(recs) != 1 || recs[0]["reason"] != "stale_fill" {
		t.Errorf("bypass log records = %v, want one with reason stale_fill", recs)
	}
	if out := <-leaderOut; out.Result != observability.ResultMiss || out.Stored {
		t.Errorf("leader = %+v, want an unstored miss", out)
	}
	if files := entryFiles(t, c.opts.Dir); len(files) != 0 {
		t.Errorf("entries after the stale fill = %v, want none", files)
	}
	fresh := &fixedFetcher{status: 200, contentType: contentTypeAdvertisement, body: body}
	if out, handled, _ := serve(c, httptest.NewRecorder(), get(), fresh); !handled || !out.Stored {
		t.Errorf("request once the stale fill ended = %+v handled %v, want a stored miss", out, handled)
	}
	assertStoreIdle(t, c)
}

// commitFault makes the next commit into a repository directory fail.
// breakDir runs in the beforeCommit hook on the fill goroutine, where t
// must not be used, so it reports failure as an error.
type commitFault struct {
	needsNonRoot bool // root ignores directory permissions
	breakDir     func(repoDir string) (restore func(), err error)
}

func TestCommitFailureAfterTheTrailerIsADiscard(t *testing.T) {
	cases := map[string]commitFault{
		"a file where the repository directory belongs": {breakDir: func(repoDir string) (func(), error) {
			if err := os.MkdirAll(filepath.Dir(repoDir), 0o700); err != nil {
				return nil, err
			}
			if err := os.WriteFile(repoDir, []byte("in the way"), 0o600); err != nil {
				return nil, err
			}
			return func() { _ = os.Remove(repoDir) }, nil
		}},
		"repository directory made read-only": {needsNonRoot: true, breakDir: func(repoDir string) (func(), error) {
			if err := os.MkdirAll(repoDir, 0o700); err != nil {
				return nil, err
			}
			if err := os.Chmod(repoDir, 0o500); err != nil { //nolint:gosec // G302: a read-only directory is the fault under test
				return nil, err
			}
			return func() { _ = os.Chmod(repoDir, 0o700) }, nil //nolint:gosec // G302: restores the store's own directory mode
		}},
	}
	for name, fault := range cases {
		t.Run(name, func(t *testing.T) {
			if fault.needsNonRoot && os.Geteuid() == 0 {
				t.Skip("root ignores directory permissions")
			}
			m, reader := observability.NewTestMetrics()
			c, clock := newTestCache(t, func(o *Options) { o.AccessRecheck = 0; o.Metrics = m })
			key := entryKeyFor(t, c, fetchRequest(t))
			repoDir := filepath.Join(c.opts.Dir, filepath.FromSlash(RepoPrefix(GroupPack, key.RepoHash)))
			var restore func()
			var breakErr error
			c.hooks.beforeCommit = func(k entryKey) {
				if k == key && restore == nil && breakErr == nil {
					restore, breakErr = fault.breakDir(repoDir)
				}
			}
			t.Cleanup(func() {
				if restore != nil {
					restore()
				}
			})

			want := fetchResultBody(t, 20, 5000)
			pr, pw := io.Pipe()
			fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
				return streamingResponse(contentTypeResult, pr), nil
			})
			leader := newCollectWriter()
			var leaderOut, followerOut Outcome
			var leaderAborted, followerAborted bool
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				leaderOut, _, leaderAborted = serve(c, leader, fetchRequest(t), fetch)
			}()
			if _, err := pw.Write(want[:70000]); err != nil {
				t.Fatal(err)
			}
			<-leader.first
			follower := newCollectWriter()
			wg.Add(1)
			go func() {
				defer wg.Done()
				followerOut, _, followerAborted = serve(c, follower, fetchRequest(t), fetch)
			}()
			waitForSubscribers(t, c, 2)
			if _, err := pw.Write(want[70000:]); err != nil {
				t.Fatal(err)
			}
			_ = pw.Close()
			wg.Wait()

			if breakErr != nil {
				t.Fatalf("breaking the repository directory: %v", breakErr)
			}
			if leaderAborted || followerAborted {
				t.Fatal("a commit failure aborted a subscriber that had the complete body")
			}
			for name, w := range map[string]*collectWriter{"leader": leader, "follower": follower} {
				if _, body, _ := w.result(); !bytes.Equal(body, want) {
					t.Errorf("%s received %d bytes, want the complete %d", name, len(body), len(want))
				}
			}
			if leaderOut.Stored || followerOut.Stored {
				t.Errorf("outcomes report stored: %+v %+v", leaderOut, followerOut)
			}
			if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonStoreError); got != 1 {
				t.Errorf("fills discarded store_error = %d, want 1", got)
			}
			if got := storeErrors(t, reader, observability.OperationCommit); got != 1 {
				t.Errorf("store_errors(commit) = %d, want 1", got)
			}
			if _, ok, _ := serve(c, httptest.NewRecorder(), fetchRequest(t), fetch); ok {
				t.Error("key was not marked after the commit failure")
			}
			if restore != nil {
				restore()
			}
			assertStoreIdle(t, c)
			if !c.marks.marked(key, clock.Now().Add(30*time.Second)) {
				t.Error("mark did not last the transient cooldown")
			}
			if c.marks.marked(key, clock.Now().Add(2*time.Minute)) {
				t.Error("mark outlived the transient cooldown")
			}
		})
	}
}

func TestContentLengthSmallerThanBodyIsTruncatedButServed(t *testing.T) {
	m, reader := observability.NewTestMetrics()
	c, _ := newTestCache(t, func(o *Options) { o.AccessRecheck = 0; o.Metrics = m })
	want := pkts(t, "packfile\n", "\x01PACK", pktline.Flush)
	fetch := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		resp := streamingResponse(contentTypeResult, io.NopCloser(bytes.NewReader(want)))
		resp.ContentLength = int64(len(want)) - 3
		return resp, nil
	})
	rec := httptest.NewRecorder()
	out, handled, aborted := serve(c, rec, fetchRequest(t), fetch)
	if aborted || !handled || out.Stored || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("Serve = %+v handled %v aborted %v body %q", out, handled, aborted, rec.Body.Bytes())
	}
	if got := fillsWithReason(t, reader, observability.FillResultDiscarded, observability.FillReasonTruncated); got != 1 {
		t.Errorf("fills discarded truncated = %d, want 1", got)
	}
	assertStoreIdle(t, c)
}
