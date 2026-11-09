package cache

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"time"
)

var (
	// ErrNotFound is returned by a BlobStore for a key it does not hold.
	ErrNotFound = errors.New("cache: object not found")
	// ErrIntegrity is returned when a stored entry fails verification:
	// truncation, reordering, relocation under another key, or
	// modification.
	ErrIntegrity = errors.New("cache: entry failed integrity check")
)

// ObjectInfo describes one object held by a BlobStore.
type ObjectInfo struct {
	Key     string
	Size    int64
	ModTime time.Time
}

// BlobStore is the optional remote storage tier. Keys are Key.Path
// values. Implementations are safe for concurrent use; callers own
// deadlines through ctx.
type BlobStore interface {
	// Stat returns ErrNotFound when key is absent.
	Stat(ctx context.Context, key string) (ObjectInfo, error)
	// Get reads key from offset to its end.
	Get(ctx context.Context, key string, offset int64) (io.ReadCloser, ObjectInfo, error)
	// Put stores size bytes from body under key.
	Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error
	// Delete removes key and returns nil when it is already absent.
	Delete(ctx context.Context, key string) error
	// List yields every object whose key begins with prefix.
	List(ctx context.Context, prefix string) iter.Seq2[ObjectInfo, error]
}

// Fetcher performs the upstream round trip for a classified request. It
// is supplied by the proxy, which owns credential injection, the
// transport, and response sanitising (an upstream 401 or 403 becomes a
// 502). It must honour ctx.
type Fetcher interface {
	Fetch(ctx context.Context, req Request) (*http.Response, error)
}

// Outcome describes how the cache handled one request, for the proxy's
// metrics and request log.
type Outcome struct {
	// Result is "hit", "miss", "stale" or "bypass".
	Result string
	// Collapsed reports that the request joined an in-flight fill.
	Collapsed bool
	// Stored reports that the fill serving the request committed an entry.
	Stored bool
	// Status is the HTTP status written to the client.
	Status int
	// BytesOut is the number of body bytes written to the client.
	BytesOut int64
}
