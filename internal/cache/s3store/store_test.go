package s3store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/cache/s3store/s3fake"
)

const testKey = "v1/pack/0123456789abcdef/fedcba9876543210"

func isolateAWSEnv(t *testing.T) {
	t.Helper()
	s3fake.IsolateAWSEnv(t)
}

func testConfig(endpoint string) Config {
	return Config{
		Bucket:         s3fake.Bucket,
		Prefix:         "tenant/",
		Region:         "us-east-1",
		Endpoint:       endpoint,
		ForcePathStyle: true,
	}
}

func newStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func put(t *testing.T, s *Store, key string, data []byte) {
	t.Helper()
	if err := s.Put(context.Background(), key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
}

func readAll(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return b
}

func TestPutGetRoundTripMultiMegabyte(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	data := randomBytes(t, 8<<20+123)

	put(t, s, testKey, data)

	if got := fake.Objects()["tenant/"+testKey]; !bytes.Equal(got, data) {
		t.Fatalf("stored object: %d bytes, want the %d bytes put", len(got), len(data))
	}
	rc, info, err := s.Get(context.Background(), testKey, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, data) {
		t.Fatalf("Get returned %d bytes that differ from the %d bytes put", len(got), len(data))
	}
	if info.Key != testKey || info.Size != int64(len(data)) || info.ModTime.IsZero() {
		t.Fatalf("Get info = %+v, want key %s and size %d with a modification time", info, testKey, len(data))
	}
	st, err := s.Stat(context.Background(), testKey)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Key != testKey || st.Size != int64(len(data)) || st.ModTime.IsZero() {
		t.Fatalf("Stat = %+v, want key %s and size %d with a modification time", st, testKey, len(data))
	}
	for _, r := range fake.Requests() {
		if !r.Signed {
			t.Errorf("%s %s carried no Authorization header", r.Method, r.Key)
		}
	}
}

func TestPutWritesOpaqueObject(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	put(t, s, testKey, []byte("sealed"))

	reqs := fake.Requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPut {
		t.Fatalf("requests = %+v, want one PUT", reqs)
	}
	h := reqs[0].Header
	if got := h.Get("Content-Type"); got != contentType {
		t.Errorf("Content-Type = %q, want %q", got, contentType)
	}
	if got := h.Get("Content-Length"); got != "6" {
		t.Errorf("Content-Length = %q, want 6", got)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
			t.Errorf("PUT carried user metadata header %s", name)
		}
		if strings.HasPrefix(strings.ToLower(name), "x-amz-checksum-") || strings.EqualFold(name, "X-Amz-Sdk-Checksum-Algorithm") {
			t.Errorf("PUT carried checksum header %s", name)
		}
	}
	if got := h.Get("X-Amz-Server-Side-Encryption"); got != "" {
		t.Errorf("X-Amz-Server-Side-Encryption = %q without SSE configured", got)
	}
}

func TestPutServerSideEncryption(t *testing.T) {
	tests := []struct {
		name, sse, kmsKeyID string
		wantSSE, wantKMSKey string
	}{
		{name: "s3 managed", sse: "AES256", wantSSE: "AES256"},
		{name: "kms default key", sse: "aws:kms", wantSSE: "aws:kms"},
		{name: "kms named key", sse: "aws:kms", kmsKeyID: "arn:aws:kms:us-east-1:111122223333:key/test", wantSSE: "aws:kms", wantKMSKey: "arn:aws:kms:us-east-1:111122223333:key/test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAWSEnv(t)
			fake := s3fake.New(t)
			cfg := testConfig(fake.URL())
			cfg.SSE, cfg.KMSKeyID = tt.sse, tt.kmsKeyID
			put(t, newStore(t, cfg), testKey, []byte("sealed"))

			h := fake.Requests()[0].Header
			if got := h.Get("X-Amz-Server-Side-Encryption"); got != tt.wantSSE {
				t.Errorf("X-Amz-Server-Side-Encryption = %q, want %q", got, tt.wantSSE)
			}
			if got := h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"); got != tt.wantKMSKey {
				t.Errorf("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id = %q, want %q", got, tt.wantKMSKey)
			}
		})
	}
}

func TestGetFromOffsetUsesRange(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	data := randomBytes(t, 1<<20)
	put(t, s, testKey, data)

	const offset = 300_001
	rc, info, err := s.Get(context.Background(), testKey, offset)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, data[offset:]) {
		t.Fatalf("Get from %d returned %d bytes, want the %d bytes from that offset", offset, len(got), len(data)-offset)
	}
	if info.Size != int64(len(data)) {
		t.Errorf("info.Size = %d, want the whole object's %d", info.Size, len(data))
	}
	reqs := fake.Requests()
	if got := reqs[len(reqs)-1].Header.Get("Range"); got != "bytes="+strconv.Itoa(offset)+"-" {
		t.Errorf("Range = %q, want bytes=%d-", got, offset)
	}

	rc, _, err = s.Get(context.Background(), testKey, 0)
	if err != nil {
		t.Fatalf("Get from 0: %v", err)
	}
	_ = readAll(t, rc)
	reqs = fake.Requests()
	if got := reqs[len(reqs)-1].Header.Get("Range"); got != "" {
		t.Errorf("Get from offset 0 sent Range %q", got)
	}
}

func TestGetRejectsIgnoredRange(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0123456789")
		return true
	})

	_, _, err := s.Get(context.Background(), testKey, 4)
	var e *Error
	if !errors.As(err, &e) || e.Code != codeBadResponse {
		t.Fatalf("Get against a server ignoring Range: err = %v, want an %s error", err, codeBadResponse)
	}
}

func TestMissingKey(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	ctx := context.Background()

	if _, err := s.Stat(ctx, testKey); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("Stat: err = %v, want cache.ErrNotFound", err)
	}
	if _, _, err := s.Get(ctx, testKey, 0); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("Get: err = %v, want cache.ErrNotFound", err)
	}
	if _, _, err := s.Get(ctx, testKey, 10); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("ranged Get: err = %v, want cache.ErrNotFound", err)
	}
	if err := s.Delete(ctx, testKey); err != nil {
		t.Errorf("Delete: err = %v, want nil for an absent key", err)
	}
}

func TestMissingBucketIsNotNotFound(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	cfg := testConfig(fake.URL())
	cfg.Bucket = "no-such-bucket"
	s := newStore(t, cfg)

	_, _, err := s.Get(context.Background(), testKey, 0)
	var e *Error
	if !errors.As(err, &e) || e.Code != "NoSuchBucket" || e.Status != http.StatusNotFound {
		t.Fatalf("Get: err = %v, want NoSuchBucket (HTTP 404)", err)
	}
	if errors.Is(err, cache.ErrNotFound) {
		t.Errorf("a missing bucket matched cache.ErrNotFound")
	}
	if err := s.Delete(context.Background(), testKey); err == nil {
		t.Errorf("Delete in a missing bucket returned nil")
	}
}

func TestDeleteRemovesObject(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	put(t, s, testKey, []byte("sealed"))

	if err := s.Delete(context.Background(), testKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := fake.Objects()["tenant/"+testKey]; ok {
		t.Fatalf("object still stored after Delete")
	}
}

func TestListPagesAndStripsPrefix(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.SetPageSize(2)
	s := newStore(t, testConfig(fake.URL()))
	want := map[string]int{
		"v1/refs/aa/01": 1,
		"v1/refs/aa/02": 22,
		"v1/refs/aa/03": 333,
	}
	for key, size := range want {
		put(t, s, key, make([]byte, size))
	}
	put(t, s, "v1/refs/bb/01", []byte("other repository"))
	fake.PutObject("v1/refs/aa/99", []byte("outside the store prefix"))
	before := len(fake.Requests())

	got := map[string]int{}
	for info, err := range s.List(context.Background(), "v1/refs/aa/") {
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if info.ModTime.IsZero() {
			t.Errorf("%s: zero ModTime", info.Key)
		}
		got[info.Key] = int(info.Size)
	}
	if len(got) != len(want) {
		t.Fatalf("List yielded %v, want %v", got, want)
	}
	for key, size := range want {
		if got[key] != size {
			t.Errorf("List %s: size %d, want %d", key, got[key], size)
		}
	}

	reqs := fake.Requests()[before:]
	if len(reqs) != 2 {
		t.Fatalf("List sent %d requests, want 2 pages", len(reqs))
	}
	if got := reqs[0].Query.Get("prefix"); got != "tenant/v1/refs/aa/" {
		t.Errorf("list prefix = %q, want the store prefix joined to the list prefix", got)
	}
	if reqs[0].Query.Get("continuation-token") != "" || reqs[1].Query.Get("continuation-token") == "" {
		t.Errorf("continuation tokens = %q, %q; want only the second page to carry one",
			reqs[0].Query.Get("continuation-token"), reqs[1].Query.Get("continuation-token"))
	}
}

func TestListWithoutStorePrefix(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	cfg := testConfig(fake.URL())
	cfg.Prefix = ""
	s := newStore(t, cfg)
	put(t, s, testKey, []byte("sealed"))

	var keys []string
	for info, err := range s.List(context.Background(), "") {
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		keys = append(keys, info.Key)
	}
	if len(keys) != 1 || keys[0] != testKey {
		t.Fatalf("List = %v, want [%s]", keys, testKey)
	}
}

func TestListStopsWhenConsumerStops(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	fake.SetPageSize(1)
	s := newStore(t, testConfig(fake.URL()))
	put(t, s, "v1/refs/aa/01", nil)
	put(t, s, "v1/refs/aa/02", nil)
	before := len(fake.Requests())

	for _, err := range s.List(context.Background(), "v1/") {
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		break
	}
	if n := len(fake.Requests()) - before; n != 1 {
		t.Fatalf("List sent %d requests after the consumer stopped at the first object, want 1", n)
	}
}

func TestListYieldsError(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return true
	})

	var errs []error
	for _, err := range s.List(context.Background(), "v1/") {
		errs = append(errs, err)
	}
	if len(errs) != 1 || errs[0] == nil || errs[0].Error() != "s3store: list v1/: AccessDenied (HTTP 403)" {
		t.Fatalf("List yielded %v, want one AccessDenied error", errs)
	}
}

func TestPutRejectsOversizeWithoutRequest(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))

	err := s.Put(context.Background(), testKey, bytes.NewReader(nil), 5<<30+1)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Put of 5 GiB + 1: err = %v, want ErrTooLarge", err)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Fatalf("Put of an oversize object sent %d requests", n)
	}
}

func TestPutRejectsInvalidSize(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))

	if err := s.Put(context.Background(), testKey, bytes.NewReader(nil), -1); err == nil {
		t.Errorf("Put with a negative size returned nil")
	}
	if err := s.Put(context.Background(), testKey, bytes.NewReader([]byte("abc")), 4); err == nil {
		t.Errorf("Put with a size larger than the body returned nil")
	}
	if n := len(fake.Requests()); n != 0 {
		t.Fatalf("invalid Puts sent %d requests", n)
	}
}

func TestPutRewindsBody(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	body := bytes.NewReader([]byte("sealed entry"))
	if _, err := body.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if err := s.Put(context.Background(), testKey, body, int64(body.Size())); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := string(fake.Objects()["tenant/"+testKey]); got != "sealed entry" {
		t.Fatalf("stored %q, want the whole body", got)
	}
}

func TestErrorOmitsSDKDetail(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	const sdkMessage = "detail-the-sdk-would-print"
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("X-Amz-Request-Id", "REQUESTID-MARKER")
		s3fake.WriteError(w, http.StatusForbidden, "AccessDenied", sdkMessage)
		return true
	})

	_, _, getErr := s.Get(context.Background(), testKey, 0)
	putErr := s.Put(context.Background(), testKey, bytes.NewReader([]byte("x")), 1)
	for _, tc := range []struct {
		err  error
		want string
	}{
		{getErr, "s3store: get " + testKey + ": AccessDenied (HTTP 403)"},
		{putErr, "s3store: put " + testKey + ": AccessDenied (HTTP 403)"},
	} {
		if tc.err == nil {
			t.Fatalf("want %q, got nil", tc.want)
		}
		msg := tc.err.Error()
		if msg != tc.want {
			t.Errorf("error = %q, want %q", msg, tc.want)
		}
		for _, leaked := range []string{sdkMessage, "REQUESTID-MARKER", "S3FAKEREQUEST", "operation error", "api error", "127.0.0.1", "s3fake-access-key"} {
			if strings.Contains(msg, leaked) {
				t.Errorf("error %q contains %q", msg, leaked)
			}
		}
		var e *Error
		if !errors.As(tc.err, &e) || e.Status != http.StatusForbidden || e.Code != "AccessDenied" {
			t.Errorf("errors.As(*Error) = %+v, want AccessDenied with status 403", e)
		}
		if errors.Is(tc.err, cache.ErrNotFound) {
			t.Errorf("AccessDenied matched cache.ErrNotFound")
		}
	}
}

func TestErrorWhenEndpointUnreachable(t *testing.T) {
	isolateAWSEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	s := newStore(t, testConfig("http://"+addr))

	_, err = s.Stat(context.Background(), testKey)
	var e *Error
	if !errors.As(err, &e) || e.Code != codeSendFailed || e.Status != 0 {
		t.Fatalf("Stat against a closed port: err = %v, want %s with no status", err, codeSendFailed)
	}
	if strings.Contains(err.Error(), "dial") || strings.Contains(err.Error(), addr) {
		t.Errorf("error %q carries transport detail", err)
	}
}

func TestCallerCancellation(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Stat(ctx, testKey); !errors.Is(err, context.Canceled) {
		t.Errorf("Stat with a cancelled context: err = %v, want context.Canceled", err)
	}
	if err := s.Put(ctx, testKey, bytes.NewReader(nil), 0); !errors.Is(err, context.Canceled) {
		t.Errorf("Put with a cancelled context: err = %v, want context.Canceled", err)
	}
}

// stallUntilCancelled holds a request without writing response headers
// until the client gives up.
func stallUntilCancelled(w http.ResponseWriter, r *http.Request) bool {
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
	return true
}

func TestHeaderTimeoutBeforeHeaders(t *testing.T) {
	const timeout = 150 * time.Millisecond
	ops := map[string]func(*Store) error{
		"stat": func(s *Store) error { _, err := s.Stat(context.Background(), testKey); return err },
		"get": func(s *Store) error {
			_, _, err := s.Get(context.Background(), testKey, 0)
			return err
		},
		"delete": func(s *Store) error { return s.Delete(context.Background(), testKey) },
		"list": func(s *Store) error {
			for _, err := range s.List(context.Background(), "v1/") {
				return err
			}
			return nil
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnv(t)
			fake := s3fake.New(t)
			cfg := testConfig(fake.URL())
			cfg.HeaderTimeout = timeout
			s := newStore(t, cfg)
			fake.Intercept(stallUntilCancelled)

			start := time.Now()
			err := op(s)
			elapsed := time.Since(start)
			var e *Error
			if !errors.As(err, &e) || e.Code != codeHeaderTimeout {
				t.Fatalf("err = %v, want a %s error", err, codeHeaderTimeout)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v does not match context.DeadlineExceeded", err)
			}
			if elapsed > 5*time.Second {
				t.Errorf("took %s, want close to the %s header timeout", elapsed, timeout)
			}
		})
	}
}

func TestHeaderTimeoutDoesNotBoundBody(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	cfg := testConfig(fake.URL())
	cfg.HeaderTimeout = 100 * time.Millisecond
	s := newStore(t, cfg)
	data := randomBytes(t, 64<<10)
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		half := len(data) / 2
		_, _ = w.Write(data[:half])
		if err := http.NewResponseController(w).Flush(); err != nil {
			return true
		}
		time.Sleep(4 * cfg.HeaderTimeout)
		_, _ = w.Write(data[half:])
		return true
	})

	rc, info, err := s.Get(context.Background(), testKey, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, data) {
		t.Fatalf("body: %d bytes, want %d", len(got), len(data))
	}
	if info.Size != int64(len(data)) {
		t.Errorf("info.Size = %d, want %d", info.Size, len(data))
	}
}

func TestEnvironmentEndpointIgnored(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	decoy := s3fake.New(t)
	t.Setenv("AWS_ENDPOINT_URL", decoy.URL())
	t.Setenv("AWS_ENDPOINT_URL_S3", decoy.URL())
	configFile := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(configFile, []byte("[default]\nendpoint_url = "+decoy.URL()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", configFile)

	s := newStore(t, testConfig(fake.URL()))
	put(t, s, testKey, []byte("sealed"))
	if _, err := s.Stat(context.Background(), testKey); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if n := len(decoy.Requests()); n != 0 {
		t.Fatalf("the environment's endpoint received %d requests", n)
	}
	if n := len(fake.Requests()); n != 2 {
		t.Fatalf("the configured endpoint received %d requests, want 2", n)
	}

	regional := newStore(t, Config{Bucket: "b", Region: "eu-west-2"})
	if got := regional.client.Options().BaseEndpoint; got == nil || *got != "https://s3.eu-west-2.amazonaws.com" {
		t.Fatalf("default BaseEndpoint = %v, want the explicit regional AWS endpoint", got)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	isolateAWSEnv(t)
	fake := s3fake.New(t)
	decoy := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	fake.Intercept(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Location", decoy.URL()+"/"+s3fake.Bucket+"/tenant/"+testKey)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	})

	if _, _, err := s.Get(context.Background(), testKey, 0); err == nil {
		t.Fatalf("Get answered by a redirect returned nil")
	}
	if n := len(decoy.Requests()); n != 0 {
		t.Fatalf("the redirect target received %d requests", n)
	}
}

func TestClientConfiguration(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	opts := s.client.Options()

	if !opts.UsePathStyle {
		t.Errorf("UsePathStyle = false with ForcePathStyle set")
	}
	if opts.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired || opts.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Errorf("checksum modes = %v, %v; want WhenRequired for both", opts.RequestChecksumCalculation, opts.ResponseChecksumValidation)
	}
	client, ok := opts.HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTPClient is %T, want *http.Client", opts.HTTPClient)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil || !transport.DisableCompression || transport.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Errorf("transport: proxy set %v, DisableCompression %v, TLSHandshakeTimeout %s",
			transport.Proxy != nil, transport.DisableCompression, transport.TLSHandshakeTimeout)
	}
	put(t, s, testKey, []byte("sealed"))
}

func TestNewValidatesConfig(t *testing.T) {
	base := Config{Bucket: "b", Region: "us-east-1"}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "aws default endpoint"},
		{name: "empty prefix", mutate: func(c *Config) { c.Prefix = "" }},
		{name: "prefix with trailing slash", mutate: func(c *Config) { c.Prefix = "haybale/" }},
		{name: "https endpoint", mutate: func(c *Config) { c.Endpoint = "https://account.r2.cloudflarestorage.com" }},
		{name: "http loopback ipv4", mutate: func(c *Config) { c.Endpoint = "http://127.0.0.2:9000" }},
		{name: "http loopback ipv6", mutate: func(c *Config) { c.Endpoint = "http://[::1]:9000" }},
		{name: "http localhost", mutate: func(c *Config) { c.Endpoint = "http://localhost:9000" }},
		{name: "sse s3", mutate: func(c *Config) { c.SSE = "AES256" }},
		{name: "sse kms with key", mutate: func(c *Config) { c.SSE, c.KMSKeyID = "aws:kms", "alias/haybale" }},
		{name: "missing bucket", mutate: func(c *Config) { c.Bucket = "" }, wantErr: "bucket is required"},
		{name: "missing region", mutate: func(c *Config) { c.Region = "" }, wantErr: "region is required"},
		{name: "region outside the host pattern", mutate: func(c *Config) { c.Region = "evil.example/x" }, wantErr: "not a valid AWS region"},
		{name: "prefix without trailing slash", mutate: func(c *Config) { c.Prefix = "haybale" }, wantErr: `must end with "/"`},
		{name: "http non-loopback endpoint", mutate: func(c *Config) { c.Endpoint = "http://s3.example.com" }, wantErr: "must use https"},
		{name: "http endpoint on a loopback-looking name", mutate: func(c *Config) { c.Endpoint = "http://127.0.0.1.example.com" }, wantErr: "must use https"},
		{name: "unsupported scheme", mutate: func(c *Config) { c.Endpoint = "ftp://127.0.0.1" }, wantErr: "must use https"},
		{name: "relative endpoint", mutate: func(c *Config) { c.Endpoint = "s3.example.com" }, wantErr: "absolute URL"},
		{name: "endpoint with userinfo", mutate: func(c *Config) { c.Endpoint = "https://user:pass@s3.example.com" }, wantErr: "must not carry userinfo"},
		{name: "endpoint with query", mutate: func(c *Config) { c.Endpoint = "https://s3.example.com/?x=1" }, wantErr: "must not carry userinfo"},
		{name: "negative header timeout", mutate: func(c *Config) { c.HeaderTimeout = -time.Second }, wantErr: "must not be negative"},
		{name: "unknown sse", mutate: func(c *Config) { c.SSE = "aws:kms:dsse" }, wantErr: "sse"},
		{name: "kms key without kms sse", mutate: func(c *Config) { c.SSE, c.KMSKeyID = "AES256", "alias/haybale" }, wantErr: "KMS key id requires"},
		{name: "kms key without sse", mutate: func(c *Config) { c.KMSKeyID = "alias/haybale" }, wantErr: "KMS key id requires"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAWSEnv(t)
			cfg := base
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			_, err := New(context.Background(), cfg)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("New: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("New: err = %v, want one containing %q", err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "pass") {
				t.Errorf("error %q echoes endpoint credentials", err)
			}
		})
	}
}

func TestStatAndGetMakeASingleAttempt(t *testing.T) {
	isolateAWSEnv(t)
	if err := os.Unsetenv("AWS_MAX_ATTEMPTS"); err != nil {
		t.Fatal(err)
	}
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))
	fake.Intercept(func(w http.ResponseWriter, _ *http.Request) bool {
		s3fake.WriteError(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
		return true
	})
	attempts := func(method string) int {
		n := 0
		for _, r := range fake.Requests() {
			if r.Method == method {
				n++
			}
		}
		return n
	}

	if _, err := s.Stat(context.Background(), testKey); err == nil {
		t.Fatal("Stat succeeded against a 503")
	}
	if _, _, err := s.Get(context.Background(), testKey, 0); err == nil {
		t.Fatal("Get succeeded against a 503")
	}
	if _, _, err := s.Get(context.Background(), testKey, 10); err == nil {
		t.Fatal("ranged Get succeeded against a 503")
	}
	if got := attempts(http.MethodHead); got != 1 {
		t.Errorf("HEAD attempts = %d, want 1", got)
	}
	if got := attempts(http.MethodGet); got != 2 {
		t.Errorf("GET attempts = %d, want one per Get", got)
	}
}

func TestNewRefusesACustomCABundle(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T)
		want  error
	}{
		"AWS_CA_BUNDLE": {
			setup: func(t *testing.T) { t.Setenv("AWS_CA_BUNDLE", filepath.Join(t.TempDir(), "ca.pem")) },
			want:  errCABundle,
		},
		"ca_bundle in the profile": {
			setup: func(t *testing.T) {
				bundle := filepath.Join(t.TempDir(), "ca.pem")
				writeFile(t, bundle, "")
				writeFile(t, os.Getenv("AWS_CONFIG_FILE"), "[default]\nca_bundle = "+bundle+"\n")
			},
			want: errProfileCABundle,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnv(t)
			tc.setup(t)
			_, err := New(context.Background(), testConfig("http://127.0.0.1:1"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("New: err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), "system trust store") || strings.Contains(err.Error(), "RootCAs") {
				t.Errorf("error %q does not give the remedy without SDK text", err)
			}
		})
	}
}

func TestNewReportsAMissingProfileWithoutSDKText(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_PROFILE", "no-such-profile")
	_, err := New(context.Background(), testConfig("http://127.0.0.1:1"))
	if !errors.Is(err, errNoProfile) {
		t.Fatalf("New: err = %v, want %v", err, errNoProfile)
	}
	if strings.Contains(err.Error(), "failed to get shared config profile") || strings.Contains(err.Error(), "no-such-profile") {
		t.Errorf("error %q carries SDK text", err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestErrorWhenTheCredentialChainIsEmpty(t *testing.T) {
	isolateAWSEnv(t)
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	fake := s3fake.New(t)
	s := newStore(t, testConfig(fake.URL()))

	_, _, err := s.Get(context.Background(), testKey, 0)
	var e *Error
	if !errors.As(err, &e) || e.Code != codeNoCredentials || e.Status != 0 {
		t.Fatalf("Get with no credentials: err = %v, want %s with no status", err, codeNoCredentials)
	}
	if got, want := err.Error(), "s3store: get "+testKey+": NoCredentials"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("the fake received %d requests without credentials", n)
	}
}

func TestErrorWhenTheServerCertificateIsUntrusted(t *testing.T) {
	isolateAWSEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := newStore(t, testConfig(srv.URL))

	_, _, err := s.Get(context.Background(), testKey, 0)
	var e *Error
	if !errors.As(err, &e) || e.Code != codeTLSFailed || e.Status != 0 {
		t.Fatalf("Get against an untrusted certificate: err = %v, want %s with no status", err, codeTLSFailed)
	}
	if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error %q carries TLS detail", err)
	}
}
