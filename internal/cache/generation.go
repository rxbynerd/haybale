package cache

import (
	"sync"
	"time"
)

// generations holds a per-repository invalidation counter and the time of
// the repository's last push seen by this process. A push bumps the
// repository's generation; a refs fill records the generation when its
// upstream request begins and is discarded at commit if it changed, so a
// fill that raced a push never stores the pre-push tips. The push time
// lets a remote refs entry created before the push be ignored. Both are
// in memory only.
type generations struct {
	mu     sync.Mutex
	gen    map[[32]byte]uint64
	pushed map[[32]byte]time.Time
}

// current returns the generation of repoHash, zero until the first bump.
func (g *generations) current(repoHash [32]byte) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen[repoHash]
}

// pushedAt returns when repoHash was last pushed, zero if never.
func (g *generations) pushedAt(repoHash [32]byte) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pushed[repoHash]
}

// bump advances the generation of repoHash and records a push at now.
func (g *generations) bump(repoHash [32]byte, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen == nil {
		g.gen = make(map[[32]byte]uint64)
		g.pushed = make(map[[32]byte]time.Time)
	}
	g.gen[repoHash]++
	g.pushed[repoHash] = now
}
