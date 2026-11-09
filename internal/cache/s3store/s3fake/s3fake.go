// Package s3fake is an in-process S3-compatible HTTP server for tests. It
// serves one bucket with path-style addressing and implements the subset
// of the S3 API the s3store backend uses: PutObject, GetObject (with a
// Range header), HeadObject, DeleteObject and ListObjectsV2 (with prefix,
// max-keys and continuation tokens). It does not verify signatures; it
// records every request, including whether it carried an Authorization
// header, so tests can assert that requests were signed.
package s3fake

import (
	"bytes"
	"crypto/md5" //nolint:gosec // G501: S3 ETags are MD5 digests of the object body; not a security use
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Bucket is the only bucket the server holds. Requests naming any other
// bucket receive a NoSuchBucket error.
const Bucket = "haybale-cache"

// defaultMaxKeys is the page size ListObjectsV2 uses when a request sets
// no max-keys, matching S3.
const defaultMaxKeys = 1000

// Request records one request the server received.
type Request struct {
	Method string
	// Key is the object key, empty for bucket-level requests.
	Key   string
	Query url.Values
	// Header is a copy of the request headers.
	Header http.Header
	// Signed reports that the request carried an Authorization header.
	Signed bool
}

// Interceptor may answer a request in place of the fake's S3 handling.
// It returns true when it wrote a response. It runs after the request
// has been recorded and before the request body is read.
type Interceptor func(w http.ResponseWriter, r *http.Request) bool

type object struct {
	data    []byte
	modTime time.Time
}

// Server is a running fake. Its methods are safe for concurrent use.
type Server struct {
	srv *httptest.Server

	mu          sync.Mutex
	objects     map[string]object
	requests    []Request
	pageSize    int
	interceptor Interceptor
	now         func() time.Time
}

// New starts a fake on a loopback port and stops it when t's test ends.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		objects:  make(map[string]object),
		pageSize: defaultMaxKeys,
		now:      func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(s.srv.Close)
	return s
}

// URL returns the server's base URL, an http URL on a loopback address.
func (s *Server) URL() string { return s.srv.URL }

// Objects returns a copy of every stored object, keyed by object key.
func (s *Server) Objects() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.objects))
	for k, o := range s.objects {
		out[k] = bytes.Clone(o.data)
	}
	return out
}

// PutObject stores data under key directly, without a request.
func (s *Server) PutObject(key string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = object{data: bytes.Clone(data), modTime: s.now()}
}

// Requests returns a copy of the requests received so far, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// SetPageSize caps the number of keys one ListObjectsV2 response holds,
// whatever max-keys the request asks for.
func (s *Server) SetPageSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pageSize = n
}

// Intercept installs fn to run before the fake's own handling of every
// request; nil removes it.
func (s *Server) Intercept(fn Interceptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interceptor = fn
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")

	s.mu.Lock()
	s.requests = append(s.requests, Request{
		Method: r.Method,
		Key:    key,
		Query:  r.URL.Query(),
		Header: r.Header.Clone(),
		Signed: r.Header.Get("Authorization") != "",
	})
	intercept := s.interceptor
	s.mu.Unlock()

	if intercept != nil && intercept(w, r) {
		return
	}
	if bucket != Bucket {
		writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.", key)
		return
	}

	switch {
	case key == "" && r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		s.listObjectsV2(w, r)
	case key == "":
		writeError(w, http.StatusNotImplemented, "NotImplemented", "Bucket operation not implemented by s3fake.", "")
	case r.Method == http.MethodPut:
		s.putObject(w, r, key)
	case r.Method == http.MethodGet:
		s.getObject(w, r, key)
	case r.Method == http.MethodHead:
		s.headObject(w, key)
	case r.Method == http.MethodDelete:
		s.deleteObject(w, key)
	default:
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed.", key)
	}
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, key string) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IncompleteBody", "Could not read the request body.", key)
		return
	}
	if r.ContentLength >= 0 && int64(len(data)) != r.ContentLength {
		writeError(w, http.StatusBadRequest, "IncompleteBody", "Body length does not match Content-Length.", key)
		return
	}
	s.mu.Lock()
	s.objects[key] = object{data: data, modTime: s.now()}
	s.mu.Unlock()
	w.Header().Set("ETag", etag(data))
	if sse := r.Header.Get("X-Amz-Server-Side-Encryption"); sse != "" {
		w.Header().Set("X-Amz-Server-Side-Encryption", sse)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) lookup(key string) (object, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[key]
	return o, ok
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request, key string) {
	o, ok := s.lookup(key)
	if !ok {
		writeError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.", key)
		return
	}
	size := int64(len(o.data))
	writeObjectHeaders(w, o)

	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(o.data)
		return
	}
	start, end, ok := parseRange(rangeHeader, size)
	if !ok {
		w.Header().Del("Last-Modified")
		w.Header().Del("ETag")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		writeError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "The requested range is not satisfiable.", key)
		return
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(o.data[start : end+1])
}

func (s *Server) headObject(w http.ResponseWriter, key string) {
	o, ok := s.lookup(key)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeObjectHeaders(w, o)
	w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) deleteObject(w http.ResponseWriter, key string) {
	s.mu.Lock()
	delete(s.objects, key)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

type listContents struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type listBucketResult struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	KeyCount              int            `xml:"KeyCount"`
	MaxKeys               int            `xml:"MaxKeys"`
	IsTruncated           bool           `xml:"IsTruncated"`
	Contents              []listContents `xml:"Contents"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
}

func (s *Server) listObjectsV2(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix := q.Get("prefix")
	maxKeys := defaultMaxKeys
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "InvalidArgument", "Invalid max-keys.", "")
			return
		}
		maxKeys = n
	}
	after := ""
	token := q.Get("continuation-token")
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidArgument", "The continuation token provided is incorrect.", "")
			return
		}
		after = string(raw)
	}

	s.mu.Lock()
	maxKeys = min(maxKeys, s.pageSize)
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	result := listBucketResult{
		Name:              Bucket,
		Prefix:            prefix,
		MaxKeys:           maxKeys,
		ContinuationToken: token,
	}
	if len(keys) > maxKeys {
		keys = keys[:maxKeys]
		result.IsTruncated = true
		result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(keys[len(keys)-1]))
	}
	for _, k := range keys {
		o := s.objects[k]
		result.Contents = append(result.Contents, listContents{
			Key:          k,
			LastModified: o.modTime.Format("2006-01-02T15:04:05.000Z"),
			ETag:         etag(o.data),
			Size:         int64(len(o.data)),
			StorageClass: "STANDARD",
		})
	}
	s.mu.Unlock()
	result.KeyCount = len(result.Contents)

	writeXML(w, http.StatusOK, result)
}

// parseRange parses a single "bytes=start-" or "bytes=start-end" range
// against an object of size bytes and returns the inclusive byte span.
func parseRange(header string, size int64) (start, end int64, ok bool) {
	spec, found := strings.CutPrefix(header, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false
	}
	first, last, found := strings.Cut(spec, "-")
	if !found {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	end = size - 1
	if last != "" {
		end, err = strconv.ParseInt(last, 10, 64)
		if err != nil || end < start {
			return 0, 0, false
		}
		end = min(end, size-1)
	}
	return start, end, true
}

func writeObjectHeaders(w http.ResponseWriter, o object) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Last-Modified", o.modTime.Format(http.TimeFormat))
	h.Set("ETag", etag(o.data))
	h.Set("Accept-Ranges", "bytes")
}

func etag(data []byte) string {
	sum := md5.Sum(data) //nolint:gosec // G401: S3 ETags are MD5 digests of the object body; not a security use
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

type errorBody struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Key       string   `xml:"Key,omitempty"`
	RequestID string   `xml:"RequestId"`
}

func writeError(w http.ResponseWriter, status int, code, message, key string) {
	writeXML(w, status, errorBody{Code: code, Message: message, Key: key, RequestID: "S3FAKEREQUEST"})
}

// WriteError writes an S3 XML error response, for interceptors that
// simulate service failures.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	writeError(w, status, code, message, "")
}

func writeXML(w http.ResponseWriter, status int, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		http.Error(w, "s3fake: cannot encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(xml.Header)+len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_, _ = w.Write(body)
}
