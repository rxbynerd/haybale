package cache

import (
	"bytes"
	"context"
	"log/slog"
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
	g := &healthGates{logger: logger}
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
	g.report("up", classifyStatus(http.StatusServiceUnavailable), t0)
	g.report("up", classifyFetchError(context.Canceled, true), t0)
	g.report("up", classifyFetchError(context.Canceled, false), t0)
	expect(t, "after 5xx and timeouts", t0, false, false)

	g.report("up", refused, t0)
	expect(t, "just opened", at(time.Second), true, false)
	if held, probe := g.admit("other", at(time.Second)); held || probe {
		t.Fatalf("another host's gate is open: held %v probe %v", held, probe)
	}
	expect(t, "probe due", at(healthProbeInterval), false, true)
	expect(t, "probe in flight", at(healthProbeInterval+time.Second), true, false)
	expect(t, "probe in flight later", at(3*healthProbeInterval), true, false)
	g.report("up", refused, at(3*healthProbeInterval))
	g.endProbe("up")
	expect(t, "after a failed probe", at(3*healthProbeInterval), false, true)
	g.report("up", classifyStatus(http.StatusServiceUnavailable), at(3*healthProbeInterval))
	g.endProbe("up")
	expect(t, "a 5xx probe leaves it open", at(3*healthProbeInterval+time.Second), true, false)

	g.report("up", classifyStatus(http.StatusOK), at(4*healthProbeInterval))
	expect(t, "closed by a success", at(4*healthProbeInterval), false, false)
	g.report("up", classifyStatus(http.StatusNotFound), at(4*healthProbeInterval))
	expect(t, "a success on a closed gate", at(4*healthProbeInterval), false, false)

	if got := len(logs.records(t, gateOpenedMsg)); got != 1 {
		t.Errorf("gate opened logs = %d, want 1", got)
	}
	closed := logs.records(t, gateClosedMsg)
	if len(closed) != 1 || closed[0]["level"] != "INFO" || closed[0]["host"] != "up" {
		t.Errorf("gate closed logs = %v, want one at INFO for the host", closed)
	}

	g.report("up", classifyFetchError(errDialRefused, false), at(5*healthProbeInterval))
	expect(t, "reopened", at(5*healthProbeInterval), true, false)
}

// TestHealthGateAdmitsOneProbeAtATime races many admits against an open
// gate whose probe is due: exactly one becomes the probe.
func TestHealthGateAdmitsOneProbeAtATime(t *testing.T) {
	g := &healthGates{logger: slog.New(slog.DiscardHandler)}
	t0 := time.Unix(1_000_000_000, 0)
	g.report("up", classifyFetchError(errDialRefused, false), t0)
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
// the gate.
func TestHealthGateServesStaleWithoutContactingUpstream(t *testing.T) {
	h := newStaleHarness(t, nil)
	otherPack := fetchResultBody(t, 2, 50)
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), packFetcher(otherPack)); !out.Stored {
		t.Fatalf("seeding the second key = %+v", out)
	}
	h.clock.Advance(10 * time.Minute)

	refused := &failing{err: errDialRefused}
	if out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), refused); out.Result != observability.ResultStale {
		t.Fatalf("refused fetch = %+v, want stale", out)
	}
	if got := len(h.logs.records(t, gateOpenedMsg)); got != 1 {
		t.Fatalf("gate opened logs = %d, want 1", got)
	}

	untouched := newBlockingFetch(nil)
	rec := newCollectWriter()
	out, _, _ := serve(h.c, rec, fetchRequest(t), untouched)
	if status, body, _ := rec.result(); out.Result != observability.ResultStale || status != 200 || !bytes.Equal(body, h.pack) {
		t.Fatalf("held request = %+v status %d, want the stale pack", out, status)
	}
	if untouched.calls.Load() != 0 {
		t.Errorf("held request fetched %d times, want none", untouched.calls.Load())
	}
	if got := rec.Header().Get("Cache-Status"); got != "haybale; hit; fwd=stale" {
		t.Errorf("held Cache-Status = %q, want the stale form without fwd-status", got)
	}
	events := h.logs.securityEvents(t, security.EventCacheStaleServed)
	if last := events[len(events)-1]; last["reason"] != staleReasonHealthGate || last["identity"] != testIdentity {
		t.Errorf("held event = %v, want reason %s for the identity", last, staleReasonHealthGate)
	}

	unseen := &failing{err: errDialRefused}
	if out, handled, _ := serve(h.c, newCollectWriter(), postV2(fetchBody(t, "want "+oidA+"\n", "done\n")), unseen); handled || unseen.count() != 1 {
		t.Errorf("unseen key = %+v handled %v fetches %d, want it sent upstream and released", out, handled, unseen.count())
	}

	h.clock.Advance(healthProbeInterval)
	probe := newBlockingFetch(func() *http.Response { return response(200, contentTypeResult, h.pack) })
	probeDone := make(chan Outcome, 1)
	go func() {
		out, _, _ := serve(h.c, newCollectWriter(), fetchRequest(t), probe)
		probeDone <- out
	}()
	select {
	case <-probe.called:
	case <-time.After(shortly):
		t.Fatal("the probe never reached upstream")
	}
	heldFetch := newBlockingFetch(nil)
	rec = newCollectWriter()
	if out, _, _ := serve(h.c, rec, otherFetchRequest(t), heldFetch); out.Result != observability.ResultStale {
		t.Errorf("request during the probe = %+v, want stale", out)
	}
	if _, body, _ := rec.result(); !bytes.Equal(body, otherPack) {
		t.Errorf("request during the probe served %d bytes, want the second key's entry", len(body))
	}
	if heldFetch.calls.Load() != 0 {
		t.Errorf("request during the probe fetched %d times, want none", heldFetch.calls.Load())
	}
	close(probe.release)
	if out := <-probeDone; out.Result != observability.ResultMiss || !out.Stored {
		t.Errorf("probe = %+v, want a stored miss", out)
	}
	if got := len(h.logs.records(t, gateClosedMsg)); got != 1 {
		t.Errorf("gate closed logs = %d, want 1", got)
	}

	after := &failing{status: 503}
	if out, _, _ := serve(h.c, newCollectWriter(), otherFetchRequest(t), after); out.Result != observability.ResultStale || after.count() != 1 {
		t.Errorf("after the gate closed = %+v fetches %d, want an upstream attempt answered stale", out, after.count())
	}
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
	next := &failing{err: errDialRefused}
	serve(h.c, newCollectWriter(), otherFetchRequest(t), next)
	if next.count() != 1 {
		t.Errorf("next request fetched %d times, want it to reach upstream", next.count())
	}
	if got := len(h.logs.records(t, gateOpenedMsg)); got != 0 {
		t.Errorf("gate opened logs = %d, want none", got)
	}
}
