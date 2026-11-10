package cache

import "sync"

// generations holds a per-repository invalidation counter. A push bumps
// the repository's generation; a refs fill records the generation when
// its upstream request begins and is discarded at commit if it changed,
// so a fill that raced a push never stores the pre-push tips.
type generations struct {
	mu  sync.Mutex
	gen map[[32]byte]uint64
}

// current returns the generation of repoHash, zero until the first bump.
func (g *generations) current(repoHash [32]byte) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gen[repoHash]
}

// bump advances the generation of repoHash.
func (g *generations) bump(repoHash [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen == nil {
		g.gen = make(map[[32]byte]uint64)
	}
	g.gen[repoHash]++
}
