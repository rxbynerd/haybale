package cache

import (
	"log/slog"
	"sync"
	"time"
)

// healthProbeInterval is how long an open health gate waits after its
// last probe before it lets another request reach upstream as a probe.
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
// fill with a qualifying stale entry is answered from it without
// contacting upstream, except for one probe at a time, admitted at most
// once per healthProbeInterval. Fills without a stale entry still go
// upstream. Any upstream answer other than an eligible 5xx closes the
// gate. Gates exist only while stale-if-error is enabled.
type healthGates struct {
	logger *slog.Logger

	mu    sync.Mutex
	hosts map[string]*healthGate
}

type healthGate struct {
	open    bool
	probing bool
	// lastProbe is when the gate opened or last admitted a probe.
	lastProbe time.Time
}

// admit decides how a fill for host proceeds at now. held is true while
// the gate is open and the fill is not its probe: the fill should answer
// from a stale entry without contacting upstream. probe is true when the
// fill is the gate's probe; its caller must call endProbe once the
// upstream request has finished.
func (g *healthGates) admit(host string, now time.Time) (held, probe bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	switch {
	case h == nil || !h.open:
		return false, false
	case !h.probing && now.Sub(h.lastProbe) >= healthProbeInterval:
		h.probing = true
		h.lastProbe = now
		return false, true
	default:
		return true, false
	}
}

// endProbe lets host's gate admit its next probe.
func (g *healthGates) endProbe(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if h := g.hosts[host]; h != nil {
		h.probing = false
	}
}

// report applies the result of an upstream request for host at now.
func (g *healthGates) report(host string, res upstreamResult, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h := g.hosts[host]
	switch res.signal {
	case gateFailure:
		if h == nil {
			if g.hosts == nil {
				g.hosts = make(map[string]*healthGate)
			}
			h = &healthGate{}
			g.hosts[host] = h
		}
		if !h.open {
			h.open = true
			h.lastProbe = now
			g.logger.Info("upstream health gate opened; stale entries answer requests without contacting upstream", "host", host, "reason", res.reason)
		}
	case gateSuccess:
		if h != nil && h.open {
			h.open = false
			g.logger.Info("upstream health gate closed", "host", host)
		}
	}
}
