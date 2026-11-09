package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store/s3fake"
	"github.com/rxbynerd/haybale/internal/observability"
)

// remoteCacheConfig returns a validated, enabled block whose remote tier
// is the fake's bucket.
func remoteCacheConfig(t *testing.T, fake *s3fake.Server, bucket string) CacheConfig {
	t.Helper()
	t.Setenv(testCacheKeyEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, cache.KeySize)))
	c := CacheConfig{
		Enabled: true,
		Dir:     filepath.Join(t.TempDir(), "cache"),
		KeyEnv:  testCacheKeyEnv,
		Remote: RemoteCacheConfig{
			Type:           "s3",
			Bucket:         bucket,
			Prefix:         "tenant/",
			Region:         "us-east-1",
			Endpoint:       fake.URL(),
			ForcePathStyle: true,
		},
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c
}

func probeRequests(fake *s3fake.Server) int {
	n := 0
	for _, r := range fake.Requests() {
		if r.Method == http.MethodGet && r.Key == "tenant/v1/.probe" && r.Signed {
			n++
		}
	}
	return n
}

func TestBuildCacheProbesTheRemoteTier(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	var buf bytes.Buffer
	got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if n := probeRequests(fake); n != 1 {
		t.Errorf("probe requests = %d, want one signed GET of the probe key", n)
	}
	if line := logLine(t, buf.String(), "remote tier enabled"); !strings.Contains(line, "bucket="+s3fake.Bucket) {
		t.Errorf("line = %q, want the bucket named", line)
	}
}

func TestBuildCacheFailsWhenTheBucketIsUnusable(t *testing.T) {
	tests := map[string]struct {
		bucket    string
		intercept s3fake.Interceptor
	}{
		"access denied": {s3fake.Bucket, func(w http.ResponseWriter, _ *http.Request) bool {
			s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return true
		}},
		"bad signature": {s3fake.Bucket, func(w http.ResponseWriter, _ *http.Request) bool {
			s3fake.WriteError(w, http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match")
			return true
		}},
		"missing bucket": {"not-the-bucket", nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s3fake.IsolateAWSEnv(t)
			fake := s3fake.New(t)
			fake.Intercept(tt.intercept)
			c := remoteCacheConfig(t, fake, tt.bucket)
			got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
			if err == nil {
				closeCache(t, got)
				t.Fatal("BuildCache succeeded against an unusable bucket")
			}
			if !strings.Contains(err.Error(), "cache.remote: the bucket cannot be used") {
				t.Errorf("err = %v, want the bucket named as unusable", err)
			}
		})
	}
}

func TestBuildCacheContinuesWhenTheProbeFailsTransiently(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.Intercept(func(w http.ResponseWriter, _ *http.Request) bool {
		s3fake.WriteError(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
		return true
	})
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	var buf bytes.Buffer
	got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v, want startup to continue past a 503", err)
	}
	defer closeCache(t, got)
	line := logLine(t, buf.String(), "startup probe")
	if !strings.Contains(line, "level=WARN") || !strings.Contains(line, "SlowDown") {
		t.Errorf("line = %q, want a warning naming the error code", line)
	}
}

func TestBuildCacheIgnoresAWSEndpointEnvironment(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	var decoyHits atomic.Int32
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		decoyHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(decoy.Close)
	t.Setenv("AWS_ENDPOINT_URL", decoy.URL)
	t.Setenv("AWS_ENDPOINT_URL_S3", decoy.URL)

	fake := s3fake.New(t)
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if decoyHits.Load() != 0 || probeRequests(fake) != 1 {
		t.Errorf("decoy requests = %d, fake probes = %d; want the configured endpoint only", decoyHits.Load(), probeRequests(fake))
	}
}
