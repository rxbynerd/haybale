package s3store

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store/s3fake"
	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/pktline"
)

// These tests run the cache engine against the S3 backend and the fake,
// covering the read-through and upload paths end to end over HTTP.

const (
	oidA = "1f1e5c8e3a0b9d2c4e6f8a0b1c2d3e4f5a6b7c8d"
	oidB = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
	// passthroughHeader marks a request an interceptor sends to the fake
	// itself, so it is not intercepted again.
	passthroughHeader = "X-S3fake-Test-Passthrough" //nolint:gosec // G101: a header name, not a credential
)

var (
	cacheTestRepo    = gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	cacheTestBaseURL = &url.URL{Scheme: "https", Host: "upstream.test"}
)

func pkts(t *testing.T, parts ...string) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		var err error
		switch p {
		case "0000":
			out = pktline.AppendFlush(out)
		case "0001":
			out = pktline.AppendDelim(out)
		default:
			out, err = pktline.AppendData(out, []byte(p))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func uploadPackRequest(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/github.com/acme/widgets.git/git-upload-pack", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	r.Header.Set("Git-Protocol", "version=2")
	return r
}

func lsRefsRequest(t *testing.T) *http.Request {
	return uploadPackRequest(pkts(t, "command=ls-refs\n", "object-format=sha1\n", "0001", "peel\n", "symrefs\n", "ref-prefix HEAD\n", "0000"))
}

func cloneRequest(t *testing.T) *http.Request {
	return uploadPackRequest(pkts(t, "command=fetch\n", "agent=git/2.54.0\n", "object-format=sha1\n", "0001",
		"thin-pack\n", "ofs-delta\n", "want "+oidA+"\n", "want "+oidB+"\n", "done\n", "0000"))
}

// upstreamStub answers ls-refs and fetch requests and counts fetches.
type upstreamStub struct {
	refs, pack []byte
	packCalls  atomic.Int32
}

func newUpstreamStub(t *testing.T) *upstreamStub {
	parts := []string{"packfile\n"}
	for i := range 30 {
		parts = append(parts, "\x01"+strings.Repeat(string(rune('a'+i%26)), 9000))
	}
	return &upstreamStub{
		refs: pkts(t, oidA+" HEAD symref-target:refs/heads/main\n", oidA+" refs/heads/main\n", "0000"),
		pack: pkts(t, append(parts, "0000")...),
	}
}

func (u *upstreamStub) Fetch(_ context.Context, req cache.Request) (*http.Response, error) {
	body := u.refs
	if req.Class.Group() == cache.GroupPack {
		u.packCalls.Add(1)
		body = u.pack
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}, nil
}

// newS3Cache opens a cache whose remote tier is the fake's bucket.
func newS3Cache(t *testing.T, fake *s3fake.Server) *cache.Cache {
	t.Helper()
	kr, err := cache.NewKeyring(bytes.Repeat([]byte{0x33}, cache.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(fake.URL())
	cfg.HeaderTimeout = 5 * time.Second
	c, err := cache.New(cache.Options{
		Dir:                t.TempDir() + "/cache",
		Keyring:            kr,
		MaxDiskSize:        64 << 20,
		MaxEntrySize:       8 << 20,
		MaxConcurrentFills: 4,
		MaxRequestBody:     1 << 20,
		Retention:          time.Hour,
		AccessRecheck:      5 * time.Minute,
		IdleTimeout:        5 * time.Second,
		ExposeStatus:       true,
		Remote:             newStore(t, cfg),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

func serveCache(t *testing.T, c *cache.Cache, r *http.Request, fetch cache.Fetcher) (cache.Outcome, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	out, handled := c.Serve(rec, r, cacheTestRepo, cacheTestBaseURL, fetch)
	if !handled {
		t.Fatalf("Serve did not handle the request: %+v", out)
	}
	return out, rec
}

// objectsUnder returns the fake's object keys under prefix.
func objectsUnder(fake *s3fake.Server, prefix string) []string {
	var keys []string
	for k := range fake.Objects() {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// seedThroughA clones through a first cache so its pack is uploaded. At
// the default refsMaxAge of zero refs entries are not uploaded.
func seedThroughA(t *testing.T, fake *s3fake.Server, up *upstreamStub) {
	t.Helper()
	a := newS3Cache(t, fake)
	serveCache(t, a, lsRefsRequest(t), up)
	if out, _ := serveCache(t, a, cloneRequest(t), up); !out.Stored {
		t.Fatalf("clone through A = %+v, want a stored miss", out)
	}
	waitUntil(t, "A's pack upload", func() bool {
		return len(objectsUnder(fake, "tenant/v1/pack/")) == 1
	})
}

func TestCacheReadsThroughTheS3Tier(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	up := newUpstreamStub(t)
	seedThroughA(t, fake, up)

	for _, r := range fake.Requests() {
		if r.Method != http.MethodPut {
			continue
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("PUT %s Content-Type = %q", r.Key, got)
		}
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
				t.Errorf("PUT %s carries user metadata %s", r.Key, name)
			}
		}
	}

	b := newS3Cache(t, fake)
	serveCache(t, b, lsRefsRequest(t), up)
	out, rec := serveCache(t, b, cloneRequest(t), up)
	if !out.Stored || out.Result != "miss" || up.packCalls.Load() != 1 {
		t.Fatalf("clone through B = %+v with %d upstream fetches, want a stored miss filled from the remote tier", out, up.packCalls.Load())
	}
	if !bytes.Equal(rec.Body.Bytes(), up.pack) {
		t.Errorf("B served %d bytes, want the %d pack bytes", rec.Body.Len(), len(up.pack))
	}
	if out, _ := serveCache(t, b, cloneRequest(t), up); out.Result != "hit" {
		t.Errorf("second clone through B = %+v, want a disk hit", out)
	}
}

func TestCacheResumesAnInterruptedS3Read(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	up := newUpstreamStub(t)
	seedThroughA(t, fake, up)

	var cut atomic.Bool
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/v1/pack/") || r.Header.Get("Range") != "" ||
			r.Header.Get(passthroughHeader) != "" || !cut.CompareAndSwap(false, true) {
			return false
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fake.URL()+r.URL.Path, nil) //nolint:gosec // G704: the fake's own loopback URL
		if err != nil {
			t.Error(err)
			return false
		}
		req.Header.Set(passthroughHeader, "1")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the fake's own loopback URL
		if err != nil {
			t.Error(err)
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.CopyN(w, resp.Body, 100000)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	})

	b := newS3Cache(t, fake)
	serveCache(t, b, lsRefsRequest(t), up)
	out, rec := serveCache(t, b, cloneRequest(t), up)
	if !out.Stored || up.packCalls.Load() != 1 || !bytes.Equal(rec.Body.Bytes(), up.pack) {
		t.Fatalf("clone through B = %+v (%d bytes, %d upstream fetches), want the full pack from the remote tier", out, rec.Body.Len(), up.packCalls.Load())
	}
	resumed := false
	for _, r := range fake.Requests() {
		if r.Method == http.MethodGet && strings.Contains(r.Key, "v1/pack/") && r.Header.Get("Range") != "" {
			resumed = true
		}
	}
	if !resumed {
		t.Error("no ranged GET resumed the interrupted read")
	}
}

func TestCachePurgeRemoteWritesAMarkerAndDeletesObjects(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	up := newUpstreamStub(t)
	seedThroughA(t, fake, up)

	kr, err := cache.NewKeyring(bytes.Repeat([]byte{0x33}, cache.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	store := newStore(t, testConfig(fake.URL()))
	res, err := cache.PurgeRepository(context.Background(), kr, cache.PurgeRequest{
		Repo:    cacheTestRepo,
		BaseURL: cacheTestBaseURL,
		Groups:  []cache.Group{cache.GroupRefs, cache.GroupPack},
		Now:     time.Now(),
		Remote:  store,
	})
	if err != nil || res.Remote != 1 {
		t.Fatalf("PurgeRepository = %+v, %v; want the pack deleted", res, err)
	}
	if got := objectsUnder(fake, "tenant/v1/purge/"); len(got) != 1 {
		t.Errorf("purge markers = %v, want one", got)
	}
	if got := append(objectsUnder(fake, "tenant/v1/pack/"), objectsUnder(fake, "tenant/v1/refs/")...); len(got) != 0 {
		t.Errorf("entries left = %v", got)
	}
}
