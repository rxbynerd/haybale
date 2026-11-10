package cache

import (
	"net/http"

	"github.com/rxbynerd/haybale/internal/observability"
)

// cacheStatusHeader is the RFC 9211 response header the cache emits when
// Options.ExposeStatus is set.
const cacheStatusHeader = "Cache-Status"

// cacheStatusValue renders the Cache-Status value for a result: "haybale;
// hit", "haybale; fwd=miss" with "; collapsed" when the request joined an
// in-flight fill, or "haybale; fwd=bypass". Whether a fill stored its
// entry is only known after the response has been written, so no form
// carries a stored parameter.
func cacheStatusValue(result string, collapsed bool) string {
	switch result {
	case observability.ResultHit:
		return "haybale; hit"
	case observability.ResultMiss:
		if collapsed {
			return "haybale; fwd=miss; collapsed"
		}
		return "haybale; fwd=miss"
	default:
		return "haybale; fwd=bypass"
	}
}

// setCacheStatus writes the Cache-Status header for result when the cache
// exposes it. For a bypass it is set before the proxy's passthrough path
// writes its own headers, which copy over it without clearing it.
func (c *Cache) setCacheStatus(h http.Header, result string, collapsed bool) {
	if c.opts.ExposeStatus {
		h.Set(cacheStatusHeader, cacheStatusValue(result, collapsed))
	}
}
