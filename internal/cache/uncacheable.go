package cache

import (
	"sync"
	"time"
)

// uncacheableMarks records keys whose fills recently failed to produce a
// storable entry, so the next burst for such a key takes the passthrough
// path instead of spooling to the same end again. An oversize response
// marks its key for the retention period; a transient failure marks it
// for a short cooldown.
type uncacheableMarks struct {
	mu    sync.Mutex
	until map[Key]time.Time
}

// mark records key as uncacheable until the given time.
func (m *uncacheableMarks) mark(key Key, until time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.until == nil {
		m.until = make(map[Key]time.Time)
	}
	if len(m.until) >= pruneThreshold {
		for k, t := range m.until {
			if !until.Before(t) {
				delete(m.until, k)
			}
		}
	}
	m.until[key] = until
}

// marked reports whether key is marked uncacheable at now, dropping an
// expired mark.
func (m *uncacheableMarks) marked(key Key, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.until[key]
	if !ok {
		return false
	}
	if !now.Before(until) {
		delete(m.until, key)
		return false
	}
	return true
}
