package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/observability"
	"github.com/rxbynerd/haybale/internal/security"
)

const (
	gateOpenedMsg = "upstream health gate opened; stale entries answer requests without contacting upstream"
	gateClosedMsg = "upstream health gate closed"
)

func TestHealthGateStateMachine(t *testing.T) {
	logger, logs := newLogCapture()
	g := &healthGates{logger: logger, interval: healthProbeInterval}
	t0 := time.Unix(1_000_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	expect := func(t *testing.T, step string, now time.Time, wantHeld, wantProbe bool) {
		t.Helper()
		if held, probe := g.admit("up", now); held != wantHeld || probe != wantProbe {
			t.Fatalf("%s: admit = held %v probe %v, want held %v probe %v", step, held, probe, wantHeld, wantProbe)
		}
	}
	refused := classifyFetchError(errDialRefused, false)

	expect(t, "closed", t0, false, false)
	g.report("up", classifyStatus(http.StatusServiceUnavailable), t0, t0)
	g.report("up", classifyFetchError(context.Canceled, true), t0, t0)
	g.report("up", classifyFetchError(context.Canceled, false), t0, t0)
	expect(t, "after 5xx and timeouts", t0, false, false)

	g.report("up", refused, t0, t0)
	expect(t, "just opened", at(time.Second), true, false)
	if held, probe := g.admit("other", at(time.Second)); held || probe {
		t.Fatalf("another host's gate is open: held %v probe %v", held, probe)
	}
	expect(t, "probe due", at(healthProbeInterval), false, true)
	expect(t, "probe in flight", at(healthProbeInterval+time.Second), true, false)
	expect(t, "probe in flight later", at(3*healthProbeInterval), true, false)
	g.report("up", refused, at(3*healthProbeInterval), at(3*healthProbeInterval))
	g.endProbe("up")
	expect(t, "after a failed probe", at(3*healthProbeInterval), false, true)
	g.report("up", classifyStatus(http.StatusServiceUnavailable), at(3*healthProbeInterval), at(3*healthProbeInterval))
	g.endProbe("up")
	expect(t, "a 5xx probe leaves it open", at(3*healthProbeInterval+time.Second), true, false)

	g.report("up", classifyStatus(http.StatusOK), at(4*healthProbeInterval), at(4*healthProbeInterval))
	expect(t, "closed by a success", at(4*healthProbeInterval), false, false)
	g.report("up", classifyStatus(http.StatusNotFound), at(4*healthProbeInterval), at(4*healthProbeInterval))
	expect(t, "a success on a closed gate", at(4*healthProbeInterval), false, false)

	if got := len(logs.records(t, gateOpenedMsg)); got != 1 {
		t.Errorf("gate opened logs = %d, want 1", got)
	}
	closed := logs.records(t, gateClosedMsg)
	if len(closed) != 1 || closed[0]["level"] != "INFO" || closed[0]["host"] != "up" {
		t.Errorf("gate closed logs = %v, want one at INFO for the host", closed)
	}

	g.report("up", classifyFetchError(errDialRefused, false), at(5*healthProbeInterval), at(5*healthProbeInterval))
	expect(t, "reopened", at(5*healthProbeInterval), true, false)
}

// TestHealthGateAdmitsOneProbeAtATime races many admits against an open
// gate whose probe is due: exactly one becomes the probe.
func TestHealthGateAdmitsOneProbeAtATime(t *testing.T) {
	g := &healthGates{logger: slog.New(slog.DiscardHandler), interval: healthProbeInterval}
	t0 := time.Unix(1_000_000_000, 0)
	g.report("up", classifyFetchError(errDialRefused, false), t0, t0)
	now := t0.Add(healthProbeInterval)
	var probes, held atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, p := g.admit("up", now)
			if p {
				probes.Add(1)
			}
			if h {
				held.Add(1)
			}
		}()
	}
	wg.Wait()
	if probes.Load() != 1 || held.Load() != 31 {
		t.Errorf("probes = %d held = %d, want exactly one probe and the rest held", probes.Load(), held.Load())
	}
}

// blockingFetch blocks every fetch until release is closed, then answers
// with resp, and signals each call on called.
type blockingFetch struct {
	called  chan struct{}
	release chan struct{}
	resp    func() *http.Response
	calls   atomic.Int32
}

func newBlockingFetch(resp func() *http.Response) *blockingFetch {
	return &blockingFetch{called: make(chan struct{}, 16), release: make(chan struct{}), resp: resp}
}

func (b *blockingFetch) Fetch(ctx context.Context, _ Request) (*http.Response, error) {
	b.calls.Add(1)
	b.called <- struct{}{}
	select {
	case <-b.release:
		return b.resp(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestHealthGateServesStaleWithoutContactingUpstream walks an outage
// through the engine: a refused connection opens the gate; while it is
// open a key with a stale entry is answered without a fetch, a key
// without one still goes upstream, one probe reaches upstream after the
// interval while other requests are held, and the probe's success closes
// the gate. The phases share one cache and run in order.
func TestHealthGateServesStaleWithoutContactingUpstream(t *testing.T) {
	h := newStaleHarness(t, nil)
	otherPack := fetchResultBody(t, 2, 50)
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), packFetcher(otherPack)); !out.Stored {
		t.Fatalf("seeding the second key = %+v", out)
	}
	h.clock.Advance(10 * time.Minute)

	t.Run("a refused connection opens the gate", func(t *testing.T) {
		refused := &failing{err: errDialRefused}
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), refused); out.Result != observability.ResultStale {
			t.Fatalf("refused fetch = %+v, want stale", out)
		}
		if got := len(h.logs.records(t, gateOpenedMsg)); got != 1 {
			t.Fatalf("gate opened logs = %d, want 1", got)
		}
	})

	t.Run("a key with an entry is held", func(t *testing.T) {
		untouched := &failing{err: errDialRefused}
		rec := newCollectWriter()
		out, _, _ := serve(h.c, rec, fetchRequest(t), untouched)
		if status, body, _ := rec.result(); out.Result != observability.ResultStale || status != 200 || !bytes.Equal(body, h.pack) {
			t.Fatalf("held request = %+v status %d, want the stale pack", out, status)
		}
		if untouched.count() != 0 {
			t.Errorf("held request fetched %d times, want none", untouched.count())
		}
		if got := rec.Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale" {
			t.Errorf("held Cache-Status = %q, want the stale form without fwd-status", got)
		}
		events := h.logs.securityEvents(t, security.EventCacheStaleServed)
		if last := events[len(events)-1]; last["reason"] != staleReasonHealthGate || last["identity"] != testIdentity {
			t.Errorf("held event = %v, want reason %s for the identity", last, staleReasonHealthGate)
		}
	})

	t.Run("a key without an entry goes upstream", func(t *testing.T) {
		unseen := &failing{err: errDialRefused}
		if out, handled, _ := serve(h.c, newCollectWriter(), postV2(fetchBody(t, "want "+oidA+"\n", "done\n")), unseen); handled || unseen.count() != 1 {
			t.Errorf("unseen key = %+v handled %v fetches %d, want it sent upstream and released", out, handled, unseen.count())
		}
	})

	t.Run("one probe while others are held, and its success closes the gate", func(t *testing.T) {
		h.clock.Advance(healthProbeInterval)
		probe := newBlockingFetch(func() *http.Response { return response(200, contentTypeResult, h.pack) })
		probeReq := fetchRequest(t)
		probeDone := make(chan Outcome, 1)
		go func() {
			out, _, _ := serve(h.c, newCollectWriter(), probeReq, probe)
			probeDone <- out
		}()
		select {
		case <-probe.called:
		case <-time.After(shortly):
			t.Fatal("the probe never reached upstream")
		}
		heldFetch := &failing{err: errDialRefused}
		rec := newCollectWriter()
		if out, _, _ := serve(h.c, rec, otherFetchRequest(t), heldFetch); out.Result != observability.ResultStale {
			t.Errorf("request during the probe = %+v, want stale", out)
		}
		if _, body, _ := rec.result(); !bytes.Equal(body, otherPack) {
			t.Errorf("request during the probe served %d bytes, want the second key's entry", len(body))
		}
		if heldFetch.count() != 0 {
			t.Errorf("request during the probe fetched %d times, want none", heldFetch.count())
		}
		close(probe.release)
		select {
		case out := <-probeDone:
			if out.Result != observability.ResultMiss || !out.Stored {
				t.Errorf("probe = %+v, want a stored miss", out)
			}
		case <-time.After(shortly):
			t.Fatal("the probe never finished")
		}
		if got := len(h.logs.records(t, gateClosedMsg)); got != 1 {
			t.Errorf("gate closed logs = %d, want 1", got)
		}
	})

	t.Run("after the gate closed requests go upstream", func(t *testing.T) {
		after := &failing{status: 503}
		if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), after); out.Result != observability.ResultStale || after.count() != 1 {
			t.Errorf("after the gate closed = %+v fetches %d, want an upstream attempt answered stale", out, after.count())
		}
	})
	assertStoreIdle(t, h.c)
}

// TestHealthGateIgnoresStatusesAndHeaderTimeouts: a 5xx or a header
// timeout is answered stale but leaves the gate closed, so the next
// request still goes upstream.
func TestHealthGateIgnoresStatusesAndHeaderTimeouts(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.ResponseHeaderTimeout = 20 * time.Millisecond })
	h.clock.Advance(10 * time.Minute)
	slow := fetchFunc(func(ctx context.Context, _ Request) (*http.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	for _, fetch := range []Fetcher{&failing{status: 503}, slow} {
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), fetch); out.Result != observability.ResultStale {
			t.Fatalf("failure = %+v, want stale", out)
		}
	}
	next := &failing{status: 502}
	serve(h.c, newCollectWriter(), fetchRequest(t), next)
	if next.count() != 1 {
		t.Errorf("next request fetched %d times, want it to reach upstream", next.count())
	}
	if got := len(h.logs.records(t, gateOpenedMsg)); got != 0 {
		t.Errorf("gate opened logs = %d, want none", got)
	}
}

// TestHealthGateIsInertWithoutStaleIfError: with stale service disabled a
// refused connection opens no gate.
func TestHealthGateIsInertWithoutStaleIfError(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.StaleIfErrorFor = 0 })
	h.clock.Advance(10 * time.Minute)
	serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: errDialRefused})
	h.c.gates.mu.Lock()
	hosts := len(h.c.gates.hosts)
	h.c.gates.mu.Unlock()
	if hosts != 0 {
		t.Errorf("gates = %d, want none", hosts)
	}
	if got := len(h.logs.records(t, gateOpenedMsg)); got != 0 {
		t.Errorf("gate opened logs = %d, want none", got)
	}
}

// TestHealthGateIgnoresAFailureOlderThanTheLatestSuccess: a connect
// failure of an attempt that began before the latest success leaves the
// gate closed; one that began at or after it opens the gate.
func TestHealthGateIgnoresAFailureOlderThanTheLatestSuccess(t *testing.T) {
	g := &healthGates{logger: slog.New(slog.DiscardHandler), interval: healthProbeInterval}
	t0 := time.Unix(1_000_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	refused := classifyFetchError(errDialRefused, false)

	g.report("up", classifyStatus(http.StatusOK), at(time.Second), at(2*time.Second))
	g.report("up", refused, t0, at(30*time.Second))
	if g.held("up", at(30*time.Second)) {
		t.Fatal("a failure begun before the latest success opened the gate")
	}
	g.report("up", refused, at(2*time.Second), at(31*time.Second))
	if !g.held("up", at(31*time.Second)) {
		t.Fatal("a failure begun at the instant of the latest success left the gate closed")
	}

	g.report("other", classifyStatus(http.StatusOK), t0, t0)
	g.report("other", refused, at(time.Second), at(2*time.Second))
	if !g.held("other", at(2*time.Second)) {
		t.Fatal("a failure begun after the latest success left the gate closed")
	}
}

// openGate opens the harness's health gate with a refused connection,
// which is answered stale.
func openGate(t *testing.T, h *staleHarness) {
	t.Helper()
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), &failing{err: errDialRefused}); out.Result != observability.ResultStale {
		t.Fatalf("refused fetch = %+v, want stale", out)
	}
	if !h.c.gates.held(testRepo.Host, h.c.now()) {
		t.Fatal("the refused connection did not open the gate")
	}
}

// hangingFetch blocks every fetch until its context ends or release is
// closed, then fails it as a dial error. It counts the calls and reports
// each call's context error on cancelled.
type hangingFetch struct {
	release   chan struct{}
	calls     atomic.Int32
	cancelled chan error
}

func newHangingFetch() *hangingFetch {
	return &hangingFetch{release: make(chan struct{}), cancelled: make(chan error, 16)}
}

func (h *hangingFetch) Fetch(ctx context.Context, _ Request) (*http.Response, error) {
	h.calls.Add(1)
	select {
	case <-h.release:
	case <-ctx.Done():
		h.cancelled <- ctx.Err()
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")}
}

// served is one concurrent request's result.
type served struct {
	out     Outcome
	handled bool
	body    []byte
}

// TestHealthGateHoldsRequestsBeforeFillSlots: while the gate is open and
// every pack fill slot is held by a fill stuck on upstream, requests with
// a qualifying tier-1 entry are still answered stale, without a slot, a
// spool, an upstream request or a fill metric. A request without an entry
// is slot-limited as before, a marked key is answered stale, and once the
// probe is due a request goes to a fill.
func TestHealthGateHoldsRequestsBeforeFillSlots(t *testing.T) {
	h := newStaleHarness(t, func(o *Options) { o.MaxConcurrentFills = 2 })
	otherPack := fetchResultBody(t, 2, 50)
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), packFetcher(otherPack)); !out.Stored {
		t.Fatalf("seeding the second key = %+v", out)
	}
	h.clock.Advance(10 * time.Minute)
	openGate(t, h)

	hang := newHangingFetch()
	stuckReqs := []*http.Request{fetchRequestFor(t, 1), fetchRequestFor(t, 2)}
	stuck := make(chan Outcome, len(stuckReqs))
	for _, r := range stuckReqs {
		go func() {
			out, _, _ := serve(h.c, newCollectWriter(), r, hang)
			stuck <- out
		}()
	}
	waitFor(t, "both fill slots to be held", func() bool { return hang.calls.Load() == 2 })

	allFills := func() int64 { return sumWhere(t, h.reader, "haybale.response_cache.fills.total", nil) }
	fillsBefore, staleBefore := allFills(), lookups(t, h.reader, observability.ResultStale)
	untouched := &failing{err: errDialRefused}
	const clients = 6
	reqs := make([]*http.Request, clients)
	wants := make([][]byte, clients)
	for i := range reqs {
		reqs[i], wants[i] = fetchRequest(t), h.pack
		if i%2 == 1 {
			reqs[i], wants[i] = otherFetchRequest(t), otherPack
		}
	}
	results := make(chan served, clients)
	for _, r := range reqs {
		go func() {
			rec := newCollectWriter()
			out, handled, _ := serve(h.c, rec, r, untouched)
			_, body, _ := rec.result()
			results <- served{out: out, handled: handled, body: body}
		}()
	}
	got := map[string]int{}
	for range clients {
		res := <-results
		if !res.handled || res.out.Result != observability.ResultStale {
			t.Fatalf("held request = %+v handled %v, want stale", res.out, res.handled)
		}
		switch {
		case bytes.Equal(res.body, h.pack):
			got["pack"]++
		case bytes.Equal(res.body, otherPack):
			got["other"]++
		}
	}
	if got["pack"] != clients/2 || got["other"] != clients/2 {
		t.Errorf("bodies served = %v, want %d of each entry", got, clients/2)
	}
	if untouched.count() != 0 {
		t.Errorf("held requests fetched %d times, want none", untouched.count())
	}
	if n := allFills() - fillsBefore; n != 0 {
		t.Errorf("fills recorded for held requests = %d, want none", n)
	}
	if n := lookups(t, h.reader, observability.ResultStale) - staleBefore; n != clients {
		t.Errorf("stale lookups = %d, want %d", n, clients)
	}
	if _, inflight, _ := h.c.store.usage(); inflight != 0 {
		t.Errorf("reserved bytes = %d, want no spool", inflight)
	}
	events := h.logs.securityEvents(t, security.EventCacheStaleServed)
	for _, ev := range events[len(events)-clients:] {
		if ev["reason"] != staleReasonHealthGate {
			t.Errorf("held event = %v, want reason %s", ev, staleReasonHealthGate)
		}
	}
	for _, rec := range h.logs.records(t, "bypass") {
		if rec["reason"] == "no_slot" {
			t.Fatalf("a held request was declined for no slot: %v", rec)
		}
	}

	if out, handled, _ := serve(h.c, newCollectWriter(), fetchRequestFor(t, 3), untouched); handled || out.Result != observability.ResultBypass {
		t.Errorf("request without an entry = %+v handled %v, want a bypass", out, handled)
	}
	noSlot := 0
	for _, rec := range h.logs.records(t, "bypass") {
		if rec["reason"] == "no_slot" {
			noSlot++
		}
	}
	if noSlot != 1 || untouched.count() != 0 {
		t.Errorf("no_slot bypasses = %d, fetches %d; want the entry-less request slot-limited", noSlot, untouched.count())
	}

	now := h.c.now()
	h.c.marks.mark(entryKeyFor(t, h.c, fetchRequest(t)), now, now.Add(time.Minute))
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), untouched); out.Result != observability.ResultStale {
		t.Errorf("marked key with the gate open = %+v, want stale", out)
	}

	close(hang.release)
	for range stuckReqs {
		<-stuck
	}
	h.clock.Advance(healthProbeInterval)
	probe := &failing{status: 503}
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), probe); out.Result != observability.ResultStale || probe.count() != 1 {
		t.Errorf("probe-due request = %+v fetches %d, want it sent upstream as the probe and answered stale", out, probe.count())
	}
	assertStoreIdle(t, h.c)
}

// TestHealthGateServesTheRemoteTierThroughAFill: a held request whose
// only qualifying entry is in the remote tier is answered stale from it
// through a fill, without contacting upstream.
func TestHealthGateServesTheRemoteTierThroughAFill(t *testing.T) {
	store := newMemBlobStore()
	pack := remotePack(t)
	seedPeer(t, store, pack)
	c, clock, _ := newRemoteTestCache(t, store, func(o *Options) {
		enableStale(o)
		o.ExposeStatus = true
	})
	clock.Advance(2 * time.Minute)
	if out, handled, _ := serve(c, newCollectWriter(), otherFetchRequest(t), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without any entry = %+v, want a release", out)
	}
	if !c.gates.held(testRepo.Host, c.now()) {
		t.Fatal("the refused connection did not open the gate")
	}
	untouched := &failing{err: errDialRefused}
	rec := newCollectWriter()
	out, handled, _ := serve(c, rec, fetchRequest(t), untouched)
	if _, body, _ := rec.result(); !handled || out.Result != observability.ResultStale || !bytes.Equal(body, pack) {
		t.Fatalf("held request = %+v handled %v, want the remote copy served stale", out, handled)
	}
	if got := rec.Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale" {
		t.Errorf("Cache-Status = %q, want the stale form", got)
	}
	if untouched.count() != 0 {
		t.Errorf("held request fetched %d times, want none", untouched.count())
	}
	assertStoreIdle(t, c)
}

// TestHealthGateProbeEndsAtResponseHeaders: a probe whose upstream
// answers closes the gate and ends at its response headers, so a failure
// that reopens the gate while the probe's body still streams lets the
// next probe through once the interval has passed.
func TestHealthGateProbeEndsAtResponseHeaders(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.clock.Advance(10 * time.Minute)
	openGate(t, h)
	h.clock.Advance(healthProbeInterval)

	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	streaming := fetchFunc(func(context.Context, Request) (*http.Response, error) {
		resp := response(http.StatusOK, contentTypeResult, nil)
		resp.Body, resp.ContentLength = pr, -1
		return resp, nil
	})
	probeReq := fetchRequestFor(t, 1)
	probeDone := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(h.c, newCollectWriter(), probeReq, streaming)
		probeDone <- out
	}()
	waitFor(t, "the probe to close the gate", func() bool { return len(h.logs.records(t, gateClosedMsg)) == 1 })

	h.clock.Advance(time.Second)
	if out, handled, _ := serve(h.c, newCollectWriter(), fetchRequestFor(t, 2), &failing{err: errDialRefused}); handled {
		t.Fatalf("refused fetch without an entry = %+v, want a release", out)
	}
	if !h.c.gates.held(testRepo.Host, h.c.now()) {
		t.Fatal("a failure after the probe's success did not reopen the gate")
	}
	h.clock.Advance(healthProbeInterval)
	next := &failing{status: 503}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), next); out.Result != observability.ResultStale || next.count() != 1 {
		t.Errorf("request once the probe was due = %+v fetches %d, want it admitted as the probe", out, next.count())
	}

	_, _ = pw.Write(h.pack)
	_ = pw.Close()
	select {
	case out := <-probeDone:
		if out.Result != observability.ResultMiss || !out.Stored {
			t.Errorf("streaming probe = %+v, want a stored miss", out)
		}
	case <-time.After(shortly):
		t.Fatal("the streaming probe never finished")
	}
	assertStoreIdle(t, h.c)
}

// TestHealthGateAdmitsTheNextProbeAfterAFailedOrAbandonedOne: a probe
// refused by upstream, and a probe whose client left before headers
// arrived, both let the next probe through once the interval has passed.
func TestHealthGateAdmitsTheNextProbeAfterAFailedOrAbandonedOne(t *testing.T) {
	h := newStaleHarness(t, nil)
	h.c.idleGrace = time.Millisecond
	h.clock.Advance(10 * time.Minute)
	openGate(t, h)

	h.clock.Advance(healthProbeInterval)
	refused := &failing{err: errDialRefused}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), refused); out.Result != observability.ResultStale || refused.count() != 1 {
		t.Fatalf("first probe = %+v fetches %d, want a refused probe answered stale", out, refused.count())
	}

	h.clock.Advance(healthProbeInterval)
	hang := newHangingFetch()
	ctx, cancel := context.WithCancel(context.Background())
	leaving := fetchRequest(t).WithContext(ctx)
	left := make(chan struct{})
	go func() {
		defer close(left)
		serve(h.c, newCollectWriter(), leaving, hang)
	}()
	waitFor(t, "the second probe to reach upstream", func() bool { return hang.calls.Load() == 1 })
	cancel()
	<-left
	select {
	case err := <-hang.cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("abandoned probe's fetch ended with %v, want it cancelled", err)
		}
	case <-time.After(shortly):
		t.Fatal("the abandoned probe's fetch was never cancelled")
	}
	waitFor(t, "the abandoned fill to end", func() bool {
		h.c.mu.Lock()
		defer h.c.mu.Unlock()
		return len(h.c.fills) == 0
	})

	h.clock.Advance(healthProbeInterval)
	next := &failing{status: 503}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), next); out.Result != observability.ResultStale || next.count() != 1 {
		t.Errorf("third probe = %+v fetches %d, want it to reach upstream", out, next.count())
	}
}

// TestHealthGateProbeDeadline: a probe that holds a qualifying entry
// waits at most the probe interval for upstream headers, is then answered
// stale with reason health_gate and leaves the gate open; its upstream
// attempt is cancelled. A probe whose entry vanished meanwhile is
// released, a shorter response-header timeout wins with its own reason,
// and a probe without an entry is not cut.
func TestHealthGateProbeDeadline(t *testing.T) {
	const interval = 50 * time.Millisecond
	setup := func(t *testing.T, mutate func(*Options)) *staleHarness {
		h := newStaleHarness(t, mutate)
		h.c.gates.interval = interval
		h.clock.Advance(10 * time.Minute)
		openGate(t, h)
		h.clock.Advance(interval)
		return h
	}

	t.Run("served stale at the deadline", func(t *testing.T) {
		h := setup(t, nil)
		hang := newHangingFetch()
		rec := newCollectWriter()
		start := time.Now()
		out, _, _ := serve(h.c, rec, fetchRequest(t), hang)
		if elapsed := time.Since(start); elapsed > shortly {
			t.Errorf("probe took %v, want about the %v deadline", elapsed, interval)
		}
		if _, body, _ := rec.result(); out.Result != observability.ResultStale || !bytes.Equal(body, h.pack) {
			t.Fatalf("probe = %+v, want the stale pack", out)
		}
		if got := rec.Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale" {
			t.Errorf("Cache-Status = %q, want the stale form without fwd-status", got)
		}
		events := h.logs.securityEvents(t, security.EventCacheStaleServed)
		if last := events[len(events)-1]; last["reason"] != staleReasonHealthGate {
			t.Errorf("event = %v, want reason %s", last, staleReasonHealthGate)
		}
		select {
		case err := <-hang.cancelled:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("upstream attempt ended with %v, want it cancelled", err)
			}
		case <-time.After(shortly):
			t.Fatal("the upstream attempt was never cancelled")
		}
		if !h.c.gates.held(testRepo.Host, h.c.now()) || len(h.logs.records(t, gateClosedMsg)) != 0 {
			t.Error("the probe deadline closed the gate")
		}
		h.clock.Advance(interval)
		next := &failing{status: 503}
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), next); out.Result != observability.ResultStale || next.count() != 1 {
			t.Errorf("next probe = %+v fetches %d, want it admitted", out, next.count())
		}
		assertStoreIdle(t, h.c)
	})

	t.Run("entry gone at the deadline", func(t *testing.T) {
		h := setup(t, nil)
		hang := newHangingFetch()
		done := make(chan served, 1)
		r := fetchRequest(t)
		go func() {
			out, handled, _ := serve(h.c, newCollectWriter(), r, hang)
			done <- served{out: out, handled: handled}
		}()
		waitFor(t, "the probe to reach upstream", func() bool { return hang.calls.Load() == 1 })
		if _, err := h.c.Purge(context.Background(), testRepo, testBaseURL, ""); err != nil {
			t.Fatal(err)
		}
		select {
		case res := <-done:
			if res.handled || res.out.Result != observability.ResultBypass {
				t.Errorf("probe after the entry went = %+v handled %v, want a release", res.out, res.handled)
			}
		case <-time.After(shortly):
			t.Fatal("the probe never finished")
		}
	})

	t.Run("a shorter header timeout wins", func(t *testing.T) {
		h := newStaleHarness(t, func(o *Options) { o.ResponseHeaderTimeout = 20 * time.Millisecond })
		h.clock.Advance(10 * time.Minute)
		openGate(t, h)
		h.clock.Advance(healthProbeInterval)
		if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), newHangingFetch()); out.Result != observability.ResultStale {
			t.Fatalf("probe = %+v, want stale", out)
		}
		events := h.logs.securityEvents(t, security.EventCacheStaleServed)
		if last := events[len(events)-1]; last["reason"] != staleReasonHeaderTimeout {
			t.Errorf("event = %v, want reason %s", last, staleReasonHeaderTimeout)
		}
	})

	t.Run("a probe without an entry is not cut", func(t *testing.T) {
		h := setup(t, nil)
		hang := newHangingFetch()
		done := make(chan served, 1)
		r := fetchRequestFor(t, 1)
		go func() {
			out, handled, _ := serve(h.c, newCollectWriter(), r, hang)
			done <- served{out: out, handled: handled}
		}()
		waitFor(t, "the probe to reach upstream", func() bool { return hang.calls.Load() == 1 })
		select {
		case res := <-done:
			t.Fatalf("probe without an entry finished early: %+v", res.out)
		case <-time.After(10 * interval):
		}
		close(hang.release)
		select {
		case res := <-done:
			if res.handled {
				t.Errorf("probe without an entry = %+v, want a release", res.out)
			}
		case <-time.After(shortly):
			t.Fatal("the probe never finished")
		}
	})
}
