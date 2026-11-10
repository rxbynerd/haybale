package cache

import (
	"net/http"
	"strconv"

	"github.com/rxbynerd/haybale/internal/observability"
)

// cacheStatusHeader is the RFC 9211 response header the cache emits when
// Options.ExposeStatus is set.
const cacheStatusHeader = "Cache-Status"

// cacheStatus is what the Cache-Status header reports for one response.
type cacheStatus struct {
	result    string
	collapsed bool
	// fwdStatus is the upstream status that made a stale response
	// eligible; zero when no upstream response arrived.
	fwdStatus int
}

// value renders the Cache-Status value: "haybale; hit", "haybale;
// fwd=miss" with "; collapsed" when the request joined an in-flight fill,
// "haybale; hit; fwd=stale" with "; fwd-status=<n>" when an upstream
// status made the request eligible for stale service, or "haybale;
// fwd=bypass". Whether a fill stored its entry is only known after the
// response has been written, so no form carries a stored parameter.
func (s cacheStatus) value() string {
	switch s.result {
	case observability.ResultHit:
		return "haybale; hit"
	case observability.ResultMiss:
		if s.collapsed {
			return "haybale; fwd=miss; collapsed"
		}
		return "haybale; fwd=miss"
	case observability.ResultStale:
		if s.fwdStatus > 0 {
			return "haybale; hit; fwd=stale; fwd-status=" + strconv.Itoa(s.fwdStatus)
		}
		return "haybale; hit; fwd=stale"
	default:
		return "haybale; fwd=bypass"
	}
}

// setCacheStatus writes the Cache-Status header when the cache exposes
// it. For a bypass it is set before the proxy's passthrough path writes
// its own headers, which copy over it without clearing it.
func (c *Cache) setCacheStatus(h http.Header, s cacheStatus) {
	if c.opts.ExposeStatus {
		h.Set(cacheStatusHeader, s.value())
	}
}
