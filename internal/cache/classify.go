package cache

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// Bypass reasons. classify reports exactly one of these when it bypasses
// a request.
const (
	bypassTooLarge            = "too_large"
	bypassContentEncoding     = "content_encoding"
	bypassDecodeError         = "decode_error"
	bypassFraming             = "framing"
	bypassTrailingBytes       = "trailing_bytes" //nolint:gosec // G101: a bypass reason, not a credential
	bypassMultipleCommands    = "multiple_commands"
	bypassDuplicateCapability = "duplicate_capability"
	bypassUnknownCapability   = "unknown_capability"
	bypassUnknownArgument     = "unknown_argument"
	bypassHasHave             = "has_have"
	bypassMissingDone         = "missing_done"
	bypassNoWant              = "no_want"
	bypassMissingProtocol     = "missing_protocol"
	bypassDuplicateProtocol   = "duplicate_protocol"
	bypassBadProtocol         = "bad_protocol"
	bypassBadFilter           = "bad_filter"
	bypassBadSideband         = "bad_sideband"
	bypassUnknownCommand      = "unknown_command"
	bypassNotAReadShape       = "not_a_read_shape"
)

const (
	endpointAdvertisement = "info/refs?service=git-upload-pack"
	endpointUploadPack    = "git-upload-pack"
	contentTypeRequest    = "application/x-git-upload-pack-request"
	contentTypeResult     = "application/x-git-upload-pack-result"
	acceptAny             = "*/*"

	// maxProtocolLength bounds the Git-Protocol header value; git sends
	// "version=2".
	maxProtocolLength = 256
)

// classify decides whether r, a read of repo, is cacheable. It must only
// be called after authentication and policy have allowed the request,
// because it reads the request body.
//
// A POST body is read in full, bounded by maxBody on both its raw and its
// decoded size, gzip-decoded when Content-Encoding is gzip, and parsed
// strictly as an upload-pack request. A GET is the advertisement and has
// no body. Any shape outside the allowlists in the design is a bypass,
// reported with bypass=true and one of the Bypass reasons.
//
// Whatever the result, r.Body is left replaying the raw bytes already
// read ahead of any unread remainder, with r.Header unchanged, so the
// caller can pass the request through as received. err is non-nil only
// for a misuse (a write request, a repo that does not match r, a
// non-positive maxBody) or a failure reading the body from the client.
func classify(r *http.Request, repo gitproto.Repo, maxBody int64) (req Request, bypass bool, reason string, err error) {
	if maxBody <= 0 {
		return Request{}, false, "", errors.New("cache: classify: maxBody must be positive")
	}
	parsed, verb, err := gitproto.ParseRequest(r)
	if err != nil {
		return Request{}, false, "", fmt.Errorf("cache: classify: %w", err)
	}
	if verb != gitproto.Read {
		return Request{}, false, "", errors.New("cache: classify: called for a write request")
	}
	if parsed != repo {
		return Request{}, false, "", errors.New("cache: classify: repo does not match the request path")
	}

	protocol, version, reason := parseProtocol(r.Header)
	if reason != "" {
		return bypassed(reason)
	}
	if r.Method == http.MethodGet {
		return classifyAdvertisement(r, repo, protocol)
	}
	return classifyUploadPack(r, repo, protocol, version, maxBody)
}

func bypassed(reason string) (Request, bool, string, error) {
	return Request{}, true, reason, nil
}

func classifyAdvertisement(r *http.Request, repo gitproto.Repo, protocol string) (Request, bool, string, error) {
	if r.URL.RawQuery != "service=git-upload-pack" || r.ContentLength != 0 {
		return bypassed(bypassNotAReadShape)
	}
	req := Request{
		Repo:     repo,
		Class:    classAdvertisement,
		Protocol: protocol,
		Method:   http.MethodGet,
		Endpoint: endpointAdvertisement,
		Accept:   acceptAny,
	}
	req.KeyHash = keyHash(req.Class, req.Protocol, nil)
	return req, false, "", nil
}

func classifyUploadPack(r *http.Request, repo gitproto.Repo, protocol string, version int, maxBody int64) (Request, bool, string, error) {
	if r.URL.RawQuery != "" {
		return bypassed(bypassNotAReadShape)
	}
	if ct := r.Header.Values("Content-Type"); len(ct) != 1 || ct[0] != contentTypeRequest {
		return bypassed(bypassNotAReadShape)
	}
	gzipped, ok := gzipEncoded(r.Header)
	if !ok {
		return bypassed(bypassContentEncoding)
	}
	decoded, reason, err := readBody(r, gzipped, maxBody)
	if err != nil {
		return Request{}, false, "", err
	}
	if reason != "" {
		return bypassed(reason)
	}
	canonical, class, v2, reason := canonicalize(decoded)
	if reason != "" {
		return bypassed(reason)
	}
	switch {
	case v2 && protocol == "":
		return bypassed(bypassMissingProtocol)
	case v2 != (version == 2):
		return bypassed(bypassBadProtocol)
	}
	req := Request{
		Repo:        repo,
		Class:       class,
		Protocol:    protocol,
		Method:      http.MethodPost,
		Endpoint:    endpointUploadPack,
		Body:        canonical,
		ContentType: contentTypeRequest,
		Accept:      contentTypeResult,
	}
	req.KeyHash = keyHash(req.Class, req.Protocol, req.Body)
	return req, false, "", nil
}

// keyHash is SHA-256 over class, protocol and body separated by
// newlines. Neither class nor a validated protocol value can contain a
// newline, so the encoding is unambiguous.
func keyHash(class Class, protocol string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(string(class) + "\n" + protocol + "\n"))
	h.Write(body)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// parseProtocol validates the Git-Protocol header, which must appear at
// most once and match version=N(:key=value)* for N in 0, 1 or 2. version
// is -1 when the header is absent.
func parseProtocol(h http.Header) (value string, version int, reason string) {
	values := h.Values("Git-Protocol")
	switch len(values) {
	case 0:
		return "", -1, ""
	case 1:
	default:
		return "", 0, bypassDuplicateProtocol
	}
	value = values[0]
	if len(value) > maxProtocolLength {
		return "", 0, bypassBadProtocol
	}
	params := strings.Split(value, ":")
	switch params[0] {
	case "version=0":
		version = 0
	case "version=1":
		version = 1
	case "version=2":
		version = 2
	default:
		return "", 0, bypassBadProtocol
	}
	seen := map[string]bool{"version": true}
	for _, param := range params[1:] {
		k, v, ok := strings.Cut(param, "=")
		if !ok || !isToken(k) || !isToken(v) || seen[k] {
			return "", 0, bypassBadProtocol
		}
		seen[k] = true
	}
	return value, version, ""
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// gzipEncoded reports whether the body is gzip-encoded; ok is false for
// any Content-Encoding other than a single gzip or identity coding.
func gzipEncoded(h http.Header) (gzipped, ok bool) {
	values := h.Values("Content-Encoding")
	switch {
	case len(values) == 0:
		return false, true
	case len(values) > 1:
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(values[0])) {
	case "gzip":
		return true, true
	case "identity":
		return false, true
	default:
		return false, false
	}
}

// captureReader records every byte read through it, and the first read
// error other than io.EOF, so the body can be replayed and a client read
// failure told apart from a decode failure.
type captureReader struct {
	r   io.Reader
	buf bytes.Buffer
	err error
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	if err != nil && !errors.Is(err, io.EOF) && c.err == nil {
		c.err = err
	}
	return n, err
}

// replayBody serves the captured bytes and then the unread remainder of
// the original body, and closes the original. The captured bytes are
// dropped once they have been replayed or the body is closed, whichever
// comes first.
type replayBody struct {
	captured []byte
	rest     io.ReadCloser
}

func (b *replayBody) Read(p []byte) (int, error) {
	if len(b.captured) > 0 {
		n := copy(p, b.captured)
		b.captured = b.captured[n:]
		if len(b.captured) == 0 {
			b.captured = nil
		}
		return n, nil
	}
	return b.rest.Read(p)
}

func (b *replayBody) Close() error {
	b.captured = nil
	return b.rest.Close()
}

// readBody reads and decodes r's body, bounded by maxBody, and replaces
// r.Body with a replay of the raw bytes it consumed followed by the
// remainder.
func readBody(r *http.Request, gzipped bool, maxBody int64) (decoded []byte, reason string, err error) {
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	limit := maxBody
	if limit < math.MaxInt64 {
		limit++
	}
	capture := &captureReader{r: io.LimitReader(body, limit)}
	defer func() {
		r.Body = &replayBody{captured: capture.buf.Bytes(), rest: body}
	}()

	decoded, decodeFailed := decodeBody(capture, gzipped, limit)
	switch {
	case capture.err != nil:
		return nil, "", fmt.Errorf("cache: reading request body: %w", capture.err)
	case int64(capture.buf.Len()) > maxBody, int64(len(decoded)) > maxBody:
		return nil, bypassTooLarge, nil
	case decodeFailed:
		return nil, bypassDecodeError, nil
	}
	return decoded, "", nil
}

// decodeBody reads src to its end, gunzipping when gzipped, and returns
// at most limit decoded bytes. A gzip body must be exactly one member
// with nothing after it.
func decodeBody(src io.Reader, gzipped bool, limit int64) (decoded []byte, failed bool) {
	if !gzipped {
		data, err := io.ReadAll(src)
		return data, err != nil
	}
	// gzip reads src directly through this io.ByteReader, so whatever
	// follows the member is still visible here.
	br := bufio.NewReader(src)
	z, err := gzip.NewReader(br)
	if err != nil {
		return nil, true
	}
	z.Multistream(false)
	data, err := io.ReadAll(io.LimitReader(z, limit))
	if err != nil {
		return data, true
	}
	if int64(len(data)) >= limit {
		return data, false
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		return data, true
	}
	return data, false
}
