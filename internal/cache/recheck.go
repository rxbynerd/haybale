package cache

import (
	"sync"
	"time"
)

// pruneThreshold is the map size at which the in-memory per-repository
// records drop their expired entries, bounding memory for a process that
// sees many repositories.
const pruneThreshold = 4096

// accessRecords remembers, per repository, when this process last saw a
// successful upstream refs response. A pack hit is served only when that
// record is within the access-recheck window, so a client that posts want
// lines directly cannot read retained packs after upstream access ends.
type accessRecords struct {
	window time.Duration

	mu   sync.Mutex
	last map[[32]byte]time.Time
}

// record notes a successful upstream refs response for repoHash at now.
func (a *accessRecords) record(repoHash [32]byte, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		a.last = make(map[[32]byte]time.Time)
	}
	if len(a.last) >= pruneThreshold {
		for h, t := range a.last {
			if now.Sub(t) > a.window {
				delete(a.last, h)
			}
		}
	}
	a.last[repoHash] = now
}

// recent reports whether repoHash had a successful refs response within
// the window before now. A zero window disables the rule and always
// reports true.
func (a *accessRecords) recent(repoHash [32]byte, now time.Time) bool {
	if a.window <= 0 {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.last[repoHash]
	return ok && now.Sub(t) <= a.window
}
