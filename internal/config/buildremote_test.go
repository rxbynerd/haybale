package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store"
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
		if r.Method == http.MethodGet && strings.HasPrefix(r.Key, "tenant/v1/.probe/") && r.Signed {
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

func TestBuildRemoteRefusesAmbientAWSSettingsItCannotHonour(t *testing.T) {
	tests := map[string]struct {
		name, value, want string
	}{
		"a custom CA bundle": {"AWS_CA_BUNDLE", "/etc/ssl/custom.pem", "unset AWS_CA_BUNDLE and add the CA certificate to the system trust store"},
		"a missing profile":  {"AWS_PROFILE", "no-such-profile", "AWS_PROFILE names a profile that does not exist"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s3fake.IsolateAWSEnv(t)
			fake := s3fake.New(t)
			c := remoteCacheConfig(t, fake, s3fake.Bucket)
			t.Setenv(tt.name, tt.value)
			store, err := c.BuildRemote(context.Background())
			if err == nil || store != nil {
				t.Fatalf("BuildRemote = %v, %v; want an error", store, err)
			}
			if !strings.HasPrefix(err.Error(), "cache.remote: ") || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want one containing %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "failed to get shared config profile") || strings.Contains(err.Error(), "RootCAs") {
				t.Errorf("err = %q carries SDK text", err)
			}
			if n := len(fake.Requests()); n != 0 {
				t.Errorf("the fake received %d requests", n)
			}
		})
	}
}

// probeStub is a BlobStore whose Get returns err, or an empty body when
// err is nil.
type probeStub struct {
	cache.BlobStore
	err    error
	closed atomic.Bool
}

func (p *probeStub) Get(context.Context, string, int64) (io.ReadCloser, cache.ObjectInfo, error) {
	if p.err != nil {
		return nil, cache.ObjectInfo{}, p.err
	}
	return closeRecorder{Reader: strings.NewReader(""), closed: &p.closed}, cache.ObjectInfo{}, nil
}

type closeRecorder struct {
	io.Reader
	closed *atomic.Bool
}

func (c closeRecorder) Close() error { c.closed.Store(true); return nil }

func TestProbeRemoteClassifiesFailures(t *testing.T) {
	probeErr := func(code s3store.Code, status int) error {
		return &s3store.Error{Op: "get", Key: "v1/.probe", Code: code, Status: status}
	}
	tests := []struct {
		name     string
		err      error
		wantFail bool
	}{
		{"no object", cache.ErrNotFound, false},
		{"access denied", probeErr("AccessDenied", 403), true},
		{"unknown access key", probeErr("InvalidAccessKeyId", 403), true},
		{"bad signature", probeErr("SignatureDoesNotMatch", 403), true},
		{"missing bucket", probeErr("NoSuchBucket", 404), true},
		{"wrong region", probeErr("PermanentRedirect", 301), true},
		{"bare 301", probeErr("MovedPermanently", 301), true},
		{"temporary redirect", probeErr("TemporaryRedirect", 307), false},
		{"permanent redirect status 308", probeErr("PermanentRedirect308", 308), false},
		{"malformed authorization", probeErr("AuthorizationHeaderMalformed", 400), true},
		{"expired token", probeErr("ExpiredToken", 400), true},
		{"invalid token", probeErr("InvalidToken", 400), true},
		{"invalid bucket name", probeErr("InvalidBucketName", 400), true},
		{"bare 401", probeErr("Unauthorized", 401), true},
		{"bare 403", probeErr("Forbidden", 403), true},
		{"no credentials", probeErr("NoCredentials", 0), true},
		{"credentials temporarily unavailable", probeErr("CredentialsUnavailable", 0), false},
		{"untrusted certificate", probeErr("TLSVerificationFailed", 0), true},
		{"dial failure", probeErr("RequestSendFailed", 0), false},
		{"header timeout", probeErr("HeaderTimeout", 0), false},
		{"deadline", probeErr("DeadlineExceeded", 0), false},
		{"cancelled", probeErr("Canceled", 0), false},
		{"server error", probeErr("InternalError", 500), false},
		{"unavailable", probeErr("ServiceUnavailable", 503), false},
		{"slow down", probeErr("SlowDown", 503), false},
		{"request timeout", probeErr("RequestTimeout", 408), false},
		{"too many requests", probeErr("TooManyRequests", 429), false},
		{"not an s3store error", errors.New("memblob: reset"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := probeRemote(context.Background(), &probeStub{err: tt.err}, slog.New(slog.NewTextHandler(&buf, nil)))
			if gotFail := err != nil; gotFail != tt.wantFail {
				t.Fatalf("probeRemote = %v, want failure %v", err, tt.wantFail)
			}
			var se *s3store.Error
			switch {
			case err != nil && errors.As(tt.err, &se) && se.Code == "NoCredentials":
				if !strings.Contains(err.Error(), "no AWS credentials") || !strings.Contains(err.Error(), "IRSA") {
					t.Errorf("err = %q, want the problem and the remedy", err)
				}
			case err != nil:
				want := "cache.remote: the bucket cannot be used with these credentials and settings: " + tt.err.Error()
				if err.Error() != want {
					t.Errorf("err = %q, want %q", err, want)
				}
			case !errors.Is(tt.err, cache.ErrNotFound) && !strings.Contains(buf.String(), "startup probe"):
				t.Errorf("log = %q, want a warning", buf.String())
			}
		})
	}
}

func TestProbeRemoteFailsWhenTheProbeKeyExists(t *testing.T) {
	stub := &probeStub{}
	err := probeRemote(context.Background(), stub, slog.New(slog.DiscardHandler))
	if !errors.Is(err, errProbeKeyFound) {
		t.Fatalf("probeRemote = %v, want errProbeKeyFound", err)
	}
	if !stub.closed.Load() {
		t.Error("the probe body was not closed")
	}
}

func TestBuildCacheFailsWithoutCredentials(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	fake := s3fake.New(t)
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err == nil {
		closeCache(t, got)
		t.Fatal("BuildCache succeeded with no credentials")
	}
	if !strings.Contains(err.Error(), "no AWS credentials") || !strings.HasSuffix(err.Error(), ": NoCredentials") {
		t.Errorf("err = %q, want the NoCredentials failure", err)
	}
}

func TestBuildCacheFailsAgainstAnUntrustedCertificate(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	c := remoteCacheConfig(t, s3fake.New(t), s3fake.Bucket)
	c.Remote.Endpoint = srv.URL
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err == nil {
		closeCache(t, got)
		t.Fatal("BuildCache succeeded against an untrusted certificate")
	}
	want := regexp.MustCompile(`^cache\.remote: the bucket cannot be used with these credentials and settings: s3store: get v1/\.probe/[0-9a-f]{32}: TLSVerificationFailed$`)
	if !want.MatchString(err.Error()) {
		t.Errorf("err = %q, want one matching %s", err, want)
	}
}

func TestAPlantedProbeObjectDoesNotStopStartup(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.PutObject("tenant/v1/.probe", []byte("planted"))
	fake.PutObject("tenant/v1/.probe/00000000000000000000000000000000", []byte("planted"))
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	for range 2 {
		got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
		if err != nil {
			t.Fatalf("BuildCache with a planted probe object: %v", err)
		}
		closeCache(t, got)
	}
	var keys []string
	for _, r := range fake.Requests() {
		if r.Method == http.MethodGet && strings.HasPrefix(r.Key, "tenant/v1/.probe/") {
			keys = append(keys, r.Key)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] || !regexp.MustCompile(`^tenant/v1/\.probe/[0-9a-f]{32}$`).MatchString(keys[0]) {
		t.Errorf("probe keys = %v, want a new random key per start", keys)
	}
}

func TestBuildCacheFailsWhenEveryProbeKeyExists(t *testing.T) {
	s3fake.IsolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			return false
		}
		w.WriteHeader(http.StatusOK)
		return true
	})
	c := remoteCacheConfig(t, fake, s3fake.Bucket)
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err == nil {
		closeCache(t, got)
		t.Fatal("BuildCache succeeded against an endpoint that answers 200 to every key")
	}
	if !errors.Is(err, errProbeKeyFound) {
		t.Errorf("err = %v, want errProbeKeyFound", err)
	}
}
