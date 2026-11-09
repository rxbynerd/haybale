// Package s3store is the S3-compatible remote tier of the response cache:
// a cache.BlobStore over one bucket prefix, built on the AWS SDK for Go
// v2. It moves opaque sealed entries and never interprets them.
//
// The service endpoint is always configured explicitly, so the SDK's
// AWS_ENDPOINT_URL and AWS_ENDPOINT_URL_S3 environment variables and
// shared-config endpoint settings never redirect the cache. Credentials
// come from the SDK's default chain (environment, shared files, web
// identity, container and instance metadata).
package s3store

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/rxbynerd/haybale/internal/cache"
)

const (
	// maxPutSize is the largest object a single PutObject may carry.
	maxPutSize = 5 << 30

	contentType = "application/octet-stream"

	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 30 * time.Second
	idleConnTimeout     = 90 * time.Second
	maxIdleConnsPerHost = 16
)

// Store is a cache.BlobStore backed by one prefix of an S3-compatible
// bucket. Keys passed to its methods are relative to the prefix. It is
// safe for concurrent use.
type Store struct {
	client        *s3.Client
	bucket        string
	prefix        string
	headerTimeout time.Duration
	sse           types.ServerSideEncryption
	kmsKeyID      *string
}

var _ cache.BlobStore = (*Store)(nil)

// New validates cfg and builds a Store. It sends no request; credentials
// are resolved on first use. ctx bounds loading the SDK's shared
// configuration.
func New(ctx context.Context, cfg Config) (*Store, error) {
	endpoint, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	httpClient := newHTTPClient()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(httpClient),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("s3store: loading AWS configuration: %w", err)
	}
	if awsCfg.Credentials != nil {
		awsCfg.Credentials = credentialsProvider{awsCfg.Credentials}
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		// Options functions run after the SDK resolves environment and
		// shared-config endpoints, so this assignment always wins.
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = cfg.ForcePathStyle
		o.HTTPClient = httpClient
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	s := &Store{
		client:        client,
		bucket:        cfg.Bucket,
		prefix:        cfg.Prefix,
		headerTimeout: cfg.HeaderTimeout,
		sse:           types.ServerSideEncryption(cfg.SSE),
	}
	if cfg.KMSKeyID != "" {
		s.kmsKeyID = aws.String(cfg.KMSKeyID)
	}
	return s, nil
}

// credentialsProvider marks every error of the provider it wraps as a
// credentialsError, so wrapError can tell a missing credential from a
// service failure.
type credentialsProvider struct{ aws.CredentialsProvider }

func (p credentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.CredentialsProvider.Retrieve(ctx)
	if err != nil {
		return creds, &credentialsError{err: err}
	}
	return creds, nil
}

// newHTTPClient returns the client every SDK request uses: no
// environment proxy, no transparent decompression, bounded dial and TLS
// handshake, and no redirect following, so a signed request is never
// re-sent to a host the configuration did not name.
func newHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: tlsHandshakeTimeout,
			DisableCompression:  true,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
			IdleConnTimeout:     idleConnTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Stat returns the size and modification time of key, or an error
// matching cache.ErrNotFound when it is absent.
func (s *Store) Stat(ctx context.Context, key string) (cache.ObjectInfo, error) {
	reqCtx, headersArrived, release := s.withHeaderTimeout(ctx)
	defer release()
	out, err := s.client.HeadObject(reqCtx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})
	headersArrived()
	if err != nil {
		return cache.ObjectInfo{}, wrapError(reqCtx, "stat", key, err)
	}
	return cache.ObjectInfo{
		Key:     key,
		Size:    aws.ToInt64(out.ContentLength),
		ModTime: aws.ToTime(out.LastModified),
	}, nil
}

// Get returns key's bytes from offset to its end, using a Range request
// when offset is positive. The returned ObjectInfo carries the whole
// object's size. Once the response headers arrive the body is governed by
// ctx alone; the caller must close it. A missing key returns an error
// matching cache.ErrNotFound.
func (s *Store) Get(ctx context.Context, key string, offset int64) (io.ReadCloser, cache.ObjectInfo, error) {
	if offset < 0 {
		return nil, cache.ObjectInfo{}, fmt.Errorf("s3store: get %s: negative offset %d", key, offset)
	}
	in := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	}
	if offset > 0 {
		in.Range = aws.String("bytes=" + strconv.FormatInt(offset, 10) + "-")
	}
	reqCtx, headersArrived, release := s.withHeaderTimeout(ctx)
	out, err := s.client.GetObject(reqCtx, in)
	inTime := headersArrived()
	if err != nil {
		err = wrapError(reqCtx, "get", key, err)
		release()
		return nil, cache.ObjectInfo{}, err
	}
	if !inTime {
		_ = out.Body.Close()
		err = wrapError(reqCtx, "get", key, context.Cause(reqCtx))
		release()
		return nil, cache.ObjectInfo{}, err
	}
	size, err := objectSize(out, offset)
	if err != nil {
		_ = out.Body.Close()
		release()
		return nil, cache.ObjectInfo{}, responseError("get", key, 0)
	}
	info := cache.ObjectInfo{Key: key, Size: size, ModTime: aws.ToTime(out.LastModified)}
	return &body{ReadCloser: out.Body, release: release}, info, nil
}

// objectSize returns the full object size from a GetObject response for
// a read from offset. A ranged read must be answered with a Content-Range
// starting at offset; a server that ignored the Range header would
// otherwise hand back the object from its first byte.
func objectSize(out *s3.GetObjectOutput, offset int64) (int64, error) {
	if out.ContentRange == nil {
		if offset > 0 {
			return 0, errors.New("range not honoured")
		}
		return aws.ToInt64(out.ContentLength), nil
	}
	spec, ok := strings.CutPrefix(*out.ContentRange, "bytes ")
	if !ok {
		return 0, errors.New("malformed Content-Range")
	}
	span, total, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, errors.New("malformed Content-Range")
	}
	first, _, ok := strings.Cut(span, "-")
	if !ok {
		return 0, errors.New("malformed Content-Range")
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start != offset {
		return 0, errors.New("Content-Range does not start at the requested offset")
	}
	size, err := strconv.ParseInt(total, 10, 64)
	if err != nil || size < offset {
		return 0, errors.New("malformed Content-Range size")
	}
	return size, nil
}

// body releases the request context of a Get once the caller closes it.
type body struct {
	io.ReadCloser
	release context.CancelFunc
}

func (b *body) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// Put uploads exactly size bytes of body, read from its start, under key
// in a single PutObject request. It returns an error matching ErrTooLarge,
// without sending a request, when size exceeds 5 GiB. Put is bounded by
// ctx only.
func (s *Store) Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	if size < 0 {
		return fmt.Errorf("s3store: put %s: negative size %d", key, size)
	}
	if size > maxPutSize {
		return fmt.Errorf("s3store: put %s (%d bytes, limit 5 GiB): %w", key, size, ErrTooLarge)
	}
	end, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("s3store: put %s: measuring body: %w", key, err)
	}
	if end != size {
		return fmt.Errorf("s3store: put %s: body holds %d bytes, want %d", key, end, size)
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("s3store: put %s: rewinding body: %w", key, err)
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.prefix + key),
		Body:          body,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(contentType),
	}
	if s.sse != "" {
		in.ServerSideEncryption = s.sse
		in.SSEKMSKeyId = s.kmsKeyID
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return wrapError(ctx, "put", key, err)
	}
	return nil
}

// Delete removes key. It returns nil when key is already absent.
func (s *Store) Delete(ctx context.Context, key string) error {
	reqCtx, headersArrived, release := s.withHeaderTimeout(ctx)
	defer release()
	_, err := s.client.DeleteObject(reqCtx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.prefix + key),
	})
	headersArrived()
	if err == nil {
		return nil
	}
	if err := wrapError(reqCtx, "delete", key, err); !errors.Is(err, cache.ErrNotFound) {
		return err
	}
	return nil
}

// List yields every object whose key begins with prefix, with keys
// relative to the store prefix, in the order the service returns them.
// It stops after yielding the first error.
func (s *Store) List(ctx context.Context, prefix string) iter.Seq2[cache.ObjectInfo, error] {
	return func(yield func(cache.ObjectInfo, error) bool) {
		pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
			Bucket: aws.String(s.bucket),
			Prefix: aws.String(s.prefix + prefix),
		})
		for pages.HasMorePages() {
			page, err := s.listPage(ctx, pages, prefix)
			if err != nil {
				yield(cache.ObjectInfo{}, err)
				return
			}
			for _, obj := range page.Contents {
				key, ok := strings.CutPrefix(aws.ToString(obj.Key), s.prefix)
				if !ok {
					continue
				}
				info := cache.ObjectInfo{
					Key:     key,
					Size:    aws.ToInt64(obj.Size),
					ModTime: aws.ToTime(obj.LastModified),
				}
				if !yield(info, nil) {
					return
				}
			}
		}
	}
}

// listPage fetches the next page of a List of prefix under the header
// timeout.
func (s *Store) listPage(ctx context.Context, pages *s3.ListObjectsV2Paginator, prefix string) (*s3.ListObjectsV2Output, error) {
	reqCtx, headersArrived, release := s.withHeaderTimeout(ctx)
	defer release()
	page, err := pages.NextPage(reqCtx)
	headersArrived()
	if err != nil {
		return nil, wrapError(reqCtx, "list", prefix, err)
	}
	return page, nil
}

// withHeaderTimeout derives the context for one request. Unless
// headersArrived is called within the store's header timeout, the
// context is cancelled with errHeaderTimeout. headersArrived reports
// whether it stopped the timer in time; release cancels the context and
// must be called once the response is no longer needed.
func (s *Store) withHeaderTimeout(ctx context.Context) (reqCtx context.Context, headersArrived func() bool, release context.CancelFunc) {
	reqCtx, cancel := context.WithCancelCause(ctx)
	release = func() { cancel(context.Canceled) }
	if s.headerTimeout <= 0 {
		return reqCtx, func() bool { return true }, release
	}
	timer := time.AfterFunc(s.headerTimeout, func() { cancel(errHeaderTimeout) })
	return reqCtx, timer.Stop, release
}
