package cache

import (
	"log/slog"
	"sync"
	"time"
)

// healthProbeInterval is how long an open health gate waits after its
// last probe ended before it lets another request reach upstream as a
// probe, and how long a probe's subscribers wait for upstream response
// headers before a qualifying stale entry answers them.
const healthProbeInterval = 5 * time.Second

// gateSignal is what one upstream result tells its host's health gate.
type gateSignal uint8

const (
	// gateNeutral leaves the gate as it is.
	gateNeutral gateSignal = iota
	// gateSuccess shows upstream answered, and closes the gate.
	gateSuccess
	// gateFailure shows upstream could not be reached, and opens the gate.
	gateFailure
)

// healthGates holds a health gate per upstream host. A gate opens when a
// fill for the host cannot connect or the credential source reports its
// API unavailable, failures a client cannot induce. While it is open, a
// request with a qualifying stale entry is answered from it without
// contacting upstream, except for one probe at a time, admitted once the
// interval has passed since the previous probe ended. Requests without a
// stale entry still go upstream. Any upstream answer other than an
// eligible 5xx closes the gate, and a connect failure of an attempt that
// began before the latest success is ignored. Gates exist only while
// stale-if-error is enabled.
type healthGates struct {
	logger *slog.Logger
	// interval is the probe interval; New sets it to healthProbeInterval.
	interval time.Duration

	mu    sync.Mutex
	hosts map[string]*healthGate
}

type healthGate struct {
	open    bool
	probing bool
	// lastProbe is when the gate opened or its last probe ended.
	lastProbe time.Time
	// lastSuccess is when an upstream request for the host last
	// succeeded.
	lastSuccess time.Time
}

// held reports whether a request for host at now would be held by its
// gate: the gate is open and either a probe is in flight or none is due.
// It admits no probe.
func (g *healthGates) held(host string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	return h != nil && h.open && (h.probing || now.Sub(h.lastProbe) < g.interval)
}

// isOpen reports whether host's gate is open, whether or not a probe is
// due.
func (g *healthGates) isOpen(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	return h != nil && h.open
}

// admit decides how a fill for host proceeds at now. held is true while
// the gate is open and the fill is not its probe: the fill should answer
// from a stale entry without contacting upstream. probe is true when the
// fill is the gate's probe; its caller must call endProbe once upstream
// response headers or the fetch error have arrived, even when the probe's
// subscribers were already answered stale.
func (g *healthGates) admit(host string, now time.Time) (held, probe bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	switch {
	case h == nil || !h.open:
		return false, false
	case !h.probing && now.Sub(h.lastProbe) >= g.interval:
		h.probing = true
		return false, true
	default:
		return true, false
	}
}

// endProbe ends host's probe at now; the gate admits its next probe once
// the interval has passed from then.
func (g *healthGates) endProbe(host string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if h := g.hosts[host]; h != nil {
		h.probing = false
		h.lastProbe = now
	}
}

// report applies, at now, the result of an upstream request for host
// that began at started.
func (g *healthGates) report(host string, res upstreamResult, started, now time.Time) {
	if res.signal == gateNeutral {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	if h == nil {
		if g.hosts == nil {
			g.hosts = make(map[string]*healthGate)
		}
		h = &healthGate{}
		g.hosts[host] = h
	}
	switch res.signal {
	case gateFailure:
		if h.open || started.Before(h.lastSuccess) {
			return
		}
		h.open = true
		h.lastProbe = now
		g.logger.Info("upstream health gate opened; stale entries answer requests without contacting upstream", "host", host, "reason", res.reason)
	case gateSuccess:
		h.lastSuccess = now
		if h.open {
			h.open = false
			g.logger.Info("upstream health gate closed", "host", host)
		}
	}
}
