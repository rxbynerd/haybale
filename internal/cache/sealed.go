package cache

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Sealed entry format, version 1. All integers are big-endian.
//
//	preamble (37 bytes, clear text)
//	  magic        4 bytes  "HBCE"
//	  version      2 bytes  formatVersion
//	  key id       8 bytes  lowercase hex, see Keyring.activeID
//	  salt        16 bytes  random per entry; derives the entry key
//	  nonce prefix 7 bytes  random per entry
//	header (4096 bytes)
//	  AES-256-GCM seal of a 4080-byte header record (entryHeader fields, then
//	  zero padding); nonce = prefix || counter 0 || flag 0x02; associated
//	  data = the preamble
//	body segments, counters 1, 2, ..., each framed as
//	  length       4 bytes  ciphertext length, 17 to segmentSize+16
//	  ciphertext            AES-256-GCM seal of 1 to segmentSize body
//	                        bytes; nonce = prefix || counter || flag 0x00;
//	                        associated data = SHA-256(preamble || header
//	                        record)
//	trailer, the next counter, framed like a segment
//	  length       4 bytes  24
//	  ciphertext            seal of the 8-byte total body length; nonce =
//	                        prefix || counter || flag 0x01 (final); same
//	                        associated data
//
// Every segment of an entry is sealed under a key derived from the cache
// key and the entry's salt (see Keyring.aead), so no two entries share an
// AES key and a repeated nonce prefix across entries reuses no nonce. The
// salt is authenticated as part of the preamble. The header is encrypted,
// so repository names and base URLs are not readable without the key. The
// trailer is the only segment sealed with the
// final flag and nothing may follow it, so truncation at any offset,
// reordering, duplication, and splicing segments or headers between
// entries all fail authentication, and the trailer's length cross-checks
// the bytes released. Binding the header digest into every segment ties the
// body to the Group, RepoHash and KeyHash in the header; a reader that
// checks those against the path it asked for detects relocation.
const (
	// formatVersion is the sealed entry format version this package writes.
	formatVersion = 1
	// segmentSize is the largest plaintext a body segment holds.
	segmentSize = 64 << 10

	magic             = "HBCE"
	saltLen           = 16
	noncePrefixLen    = 7
	preambleLen       = len(magic) + 2 + keyIDLen + saltLen + noncePrefixLen
	tagLen            = 16
	frameLen          = 4
	headerSealedLen   = 4096
	headerRecordLen   = headerSealedLen - tagLen
	headerFixedPrefix = preambleLen + headerSealedLen
	maxSegmentCTLen   = segmentSize + tagLen
	trailerPlainLen   = 8
	trailerCTLen      = trailerPlainLen + tagLen
	segmentOverhead   = frameLen + tagLen

	flagBody   = 0x00
	flagFinal  = 0x01
	flagHeader = 0x02
)

// Bounds on the variable-length entryHeader fields. Their encoded total always
// fits headerRecordLen.
const (
	maxLabelLen       = 32
	maxRepoLen        = 1024
	maxBaseURLLen     = 2048
	maxContentTypeLen = 256
	maxProtocolLen    = 256
)

// entryHeader is the authenticated metadata sealed at the front of every entry.
// It holds only what is known when a response starts; the body length is
// in the trailer.
type entryHeader struct {
	// Version is the format version. newSealedWriter sets it; a caller
	// value other than zero or formatVersion is rejected.
	Version uint16
	// KeyID is the id of the key the entry is sealed under. newSealedWriter
	// sets it; a caller value other than "" or the active id is rejected.
	KeyID    string
	Group    Group
	Class    Class
	RepoHash [32]byte
	KeyHash  [32]byte
	// Repo is "host/owner/name", for operators.
	Repo string
	// BaseURL is the upstream base URL the entry was fetched from.
	BaseURL     string
	CreatedAt   time.Time
	ContentType string
	// Protocol is the Git-Protocol request header value, "" when absent.
	Protocol string
}

// sealedSize returns the sealed size of an entry whose body is bodyLen
// bytes written without Flush, so that every segment but the last is full.
// It is the reservation a fill makes for a body of known length. Each
// Flush that seals a partial segment adds up to 20 bytes beyond it, which
// the fill must reserve as it goes. A negative bodyLen returns -1.
func sealedSize(bodyLen int64) int64 {
	if bodyLen < 0 {
		return -1
	}
	segments := (bodyLen + segmentSize - 1) / segmentSize
	return int64(headerFixedPrefix) + bodyLen + segments*segmentOverhead + frameLen + trailerCTLen
}

// sealedWriter seals a body into an entry written to an underlying
// io.Writer. It buffers at most one segment and writes each sealed segment
// with a single Write call. It is not safe for concurrent use. After any
// error the writer is unusable and returns that error.
type sealedWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix [noncePrefixLen]byte
	aad    [sha256.Size]byte

	buf     []byte
	out     []byte
	counter uint32
	total   int64
	closed  bool
	err     error
}

// newSealedWriter writes the preamble and sealed header for h, under a
// key derived from kr's active key and a fresh salt, to w and returns a
// writer for the body. Close must be called to write the trailer; without
// it the entry fails verification.
func newSealedWriter(w io.Writer, kr Keyring, h entryHeader) (*sealedWriter, error) {
	id := kr.activeID()
	if !kr.holds(id) {
		return nil, errors.New("cache: keyring has no active key")
	}
	if h.Version != 0 && h.Version != formatVersion {
		return nil, fmt.Errorf("cache: header version %d is not %d", h.Version, formatVersion)
	}
	if h.KeyID != "" && h.KeyID != id {
		return nil, fmt.Errorf("cache: header key id %q is not the active key id %q", h.KeyID, id)
	}
	h.Version = formatVersion
	h.KeyID = id
	record, err := encodeHeader(h)
	if err != nil {
		return nil, err
	}

	sw := &sealedWriter{
		w:       w,
		buf:     make([]byte, 0, segmentSize),
		out:     make([]byte, 0, frameLen+maxSegmentCTLen),
		counter: 1,
	}
	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("cache: generate entry salt: %w", err)
	}
	if _, err := rand.Read(sw.prefix[:]); err != nil {
		return nil, fmt.Errorf("cache: generate nonce prefix: %w", err)
	}
	gcm, ok := kr.aead(id, salt[:])
	if !ok {
		return nil, errors.New("cache: keyring has no active key")
	}
	sw.aead = gcm

	out := make([]byte, 0, headerFixedPrefix)
	out = appendPreamble(out, id, salt, sw.prefix)
	preamble := out[:preambleLen]
	nonce := segmentNonce(sw.prefix, 0, flagHeader)
	out = gcm.Seal(out, nonce[:], record, preamble)
	sw.aad = headerDigest(preamble, record)
	if _, err := w.Write(out); err != nil {
		return nil, err
	}
	return sw, nil
}

// Write buffers p and seals a segment each time segmentSize bytes are
// buffered.
func (sw *sealedWriter) Write(p []byte) (int, error) {
	if err := sw.usable(); err != nil {
		return 0, err
	}
	n := 0
	for len(p) > 0 {
		c := copy(sw.buf[len(sw.buf):segmentSize], p)
		sw.buf = sw.buf[:len(sw.buf)+c]
		p = p[c:]
		n += c
		sw.total += int64(c)
		if len(sw.buf) == segmentSize {
			if err := sw.flush(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// Flush seals any buffered bytes as a segment so that readers can release
// them. It is a no-op when nothing is buffered.
func (sw *sealedWriter) Flush() error {
	if err := sw.usable(); err != nil {
		return err
	}
	return sw.flush()
}

// Close seals any buffered bytes and writes the trailer. It does not close
// the underlying writer. Calling Close again returns nil.
func (sw *sealedWriter) Close() error {
	if sw.err != nil {
		return sw.err
	}
	if sw.closed {
		return nil
	}
	if err := sw.flush(); err != nil {
		return err
	}
	var trailer [trailerPlainLen]byte
	binary.BigEndian.PutUint64(trailer[:], uint64(sw.total)) //nolint:gosec // total is a non-negative byte count
	if err := sw.seal(trailer[:], flagFinal); err != nil {
		return err
	}
	sw.closed = true
	return nil
}

// Written returns the number of body bytes accepted so far.
func (sw *sealedWriter) written() int64 { return sw.total }

func (sw *sealedWriter) usable() error {
	if sw.err != nil {
		return sw.err
	}
	if sw.closed {
		return errors.New("cache: sealed writer is closed")
	}
	return nil
}

func (sw *sealedWriter) flush() error {
	if len(sw.buf) == 0 {
		return nil
	}
	if err := sw.seal(sw.buf, flagBody); err != nil {
		return err
	}
	sw.buf = sw.buf[:0]
	return nil
}

// seal seals plain as the next segment and writes it with its frame.
func (sw *sealedWriter) seal(plain []byte, flag byte) error {
	if sw.counter == 0 {
		sw.err = errors.New("cache: entry exceeds the maximum segment count")
		return sw.err
	}
	nonce := segmentNonce(sw.prefix, sw.counter, flag)
	out := binary.BigEndian.AppendUint32(sw.out[:0], uint32(len(plain)+tagLen)) //nolint:gosec // at most segmentSize+tagLen
	out = sw.aead.Seal(out, nonce[:], plain, sw.aad[:])
	if _, err := sw.w.Write(out); err != nil {
		sw.err = err
		return err
	}
	sw.out = out
	sw.counter++
	return nil
}

// sealedReader verifies and decrypts an entry. Each segment is
// authenticated before any of its plaintext is returned. It reads one
// framed segment at a time, so it can follow a source that is still being
// written as long as reads block until data is available. It is not safe
// for concurrent use.
type sealedReader struct {
	r      io.Reader
	aead   cipher.AEAD
	prefix [noncePrefixLen]byte
	aad    [sha256.Size]byte
	header entryHeader

	frame   [frameLen]byte
	ct      []byte
	pt      []byte
	off     int
	counter uint32
	total   int64
	done    bool
	err     error
}

// newSealedReader reads and verifies the preamble and header from r using
// the key named in the preamble. An unknown magic, version or key id, or a
// header that fails authentication or decoding, is ErrIntegrity. Errors
// from r other than a premature EOF are returned unchanged.
func newSealedReader(r io.Reader, kr Keyring) (*sealedReader, error) {
	buf := make([]byte, headerFixedPrefix)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, truncated(err, "header")
	}
	preamble := buf[:preambleLen]
	if string(preamble[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: unknown magic", ErrIntegrity)
	}
	if v := binary.BigEndian.Uint16(preamble[len(magic):]); v != formatVersion {
		return nil, fmt.Errorf("%w: unknown format version %d", ErrIntegrity, v)
	}
	id, _ := preambleKeyID(preamble)
	if !kr.holds(id) {
		return nil, fmt.Errorf("%w: unknown key id", ErrIntegrity)
	}
	salt := preamble[len(magic)+2+keyIDLen : len(magic)+2+keyIDLen+saltLen]
	gcm, _ := kr.aead(id, salt)
	sr := &sealedReader{
		r:       r,
		aead:    gcm,
		ct:      make([]byte, maxSegmentCTLen),
		pt:      make([]byte, 0, segmentSize),
		counter: 1,
	}
	copy(sr.prefix[:], preamble[len(magic)+2+keyIDLen+saltLen:])

	nonce := segmentNonce(sr.prefix, 0, flagHeader)
	record, err := gcm.Open(nil, nonce[:], buf[preambleLen:], preamble)
	if err != nil {
		return nil, fmt.Errorf("%w: header authentication failed", ErrIntegrity)
	}
	h, err := decodeHeader(record)
	if err != nil {
		return nil, err
	}
	if h.Version != formatVersion || h.KeyID != id {
		return nil, fmt.Errorf("%w: header does not match preamble", ErrIntegrity)
	}
	sr.header = h
	sr.aad = headerDigest(preamble, record)
	return sr, nil
}

// Header returns the verified entry header.
func (sr *sealedReader) Header() entryHeader { return sr.header }

// BodyLength returns the body length recorded in the trailer and true once
// Read has verified the trailer, and false before.
func (sr *sealedReader) bodyLength() (int64, bool) {
	if !sr.done {
		return 0, false
	}
	return sr.total, true
}

// Read returns verified plaintext. It returns io.EOF only after the
// trailer has been verified against the bytes released and the source has
// ended, and ErrIntegrity for a truncated, reordered or modified entry.
func (sr *sealedReader) Read(p []byte) (int, error) {
	for sr.off == len(sr.pt) {
		if sr.err != nil {
			return 0, sr.err
		}
		if sr.done {
			return 0, io.EOF
		}
		sr.err = sr.next()
	}
	n := copy(p, sr.pt[sr.off:])
	sr.off += n
	return n, nil
}

// next reads and verifies the next segment, leaving body plaintext in
// sr.pt or, for the trailer, checking the length and the end of the source.
func (sr *sealedReader) next() error {
	if _, err := io.ReadFull(sr.r, sr.frame[:]); err != nil {
		return truncated(err, "before the trailer")
	}
	n := binary.BigEndian.Uint32(sr.frame[:])
	if n <= tagLen || n > maxSegmentCTLen {
		return fmt.Errorf("%w: segment %d has invalid length %d", ErrIntegrity, sr.counter, n)
	}
	ct := sr.ct[:n]
	if _, err := io.ReadFull(sr.r, ct); err != nil {
		return truncated(err, "inside a segment")
	}
	if sr.counter == 0 {
		return fmt.Errorf("%w: segment count exceeded", ErrIntegrity)
	}

	nonce := segmentNonce(sr.prefix, sr.counter, flagBody)
	pt, err := sr.aead.Open(sr.pt[:0], nonce[:], ct, sr.aad[:])
	if err == nil {
		sr.pt, sr.off = pt, 0
		sr.total += int64(len(pt))
		sr.counter++
		return nil
	}
	if n != trailerCTLen {
		return fmt.Errorf("%w: segment %d authentication failed", ErrIntegrity, sr.counter)
	}
	nonce = segmentNonce(sr.prefix, sr.counter, flagFinal)
	var trailer [trailerPlainLen]byte
	if _, err := sr.aead.Open(trailer[:0], nonce[:], ct, sr.aad[:]); err != nil {
		return fmt.Errorf("%w: segment %d authentication failed", ErrIntegrity, sr.counter)
	}
	if binary.BigEndian.Uint64(trailer[:]) != uint64(sr.total) { //nolint:gosec // total is a non-negative byte count
		return fmt.Errorf("%w: body length does not match trailer", ErrIntegrity)
	}
	var extra [1]byte
	switch k, err := io.ReadFull(sr.r, extra[:]); {
	case k > 0:
		return fmt.Errorf("%w: data after the trailer", ErrIntegrity)
	case !errors.Is(err, io.EOF):
		return err
	}
	sr.pt, sr.off = sr.pt[:0], 0
	sr.done = true
	return nil
}

// truncated reports a premature EOF from the source as ErrIntegrity and
// returns any other error unchanged.
func truncated(err error, where string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: truncated %s", ErrIntegrity, where)
	}
	return err
}

// preambleKeyID returns the key id named by a preamble, and false when the
// bytes are not a preamble of this format version.
func preambleKeyID(preamble []byte) (string, bool) {
	if len(preamble) < preambleLen || string(preamble[:len(magic)]) != magic {
		return "", false
	}
	if binary.BigEndian.Uint16(preamble[len(magic):]) != formatVersion {
		return "", false
	}
	return string(preamble[len(magic)+2 : len(magic)+2+keyIDLen]), true
}

func appendPreamble(dst []byte, keyID string, salt [saltLen]byte, prefix [noncePrefixLen]byte) []byte {
	dst = append(dst, magic...)
	dst = binary.BigEndian.AppendUint16(dst, formatVersion)
	dst = append(dst, keyID...)
	dst = append(dst, salt[:]...)
	return append(dst, prefix[:]...)
}

func segmentNonce(prefix [noncePrefixLen]byte, counter uint32, flag byte) [noncePrefixLen + 5]byte {
	var nonce [noncePrefixLen + 5]byte
	copy(nonce[:], prefix[:])
	binary.BigEndian.PutUint32(nonce[noncePrefixLen:], counter)
	nonce[noncePrefixLen+4] = flag
	return nonce
}

func headerDigest(preamble, record []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write(preamble)
	h.Write(record)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// encodeHeader encodes h as a headerRecordLen-byte record: the fields in
// declaration order, strings as a 2-byte length then bytes, CreatedAt as
// 8-byte Unix seconds then 4-byte nanoseconds, then zero padding.
func encodeHeader(h entryHeader) ([]byte, error) {
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{"key id", h.KeyID, keyIDLen},
		{"group", string(h.Group), maxLabelLen},
		{"class", string(h.Class), maxLabelLen},
		{"repo", h.Repo, maxRepoLen},
		{"base URL", h.BaseURL, maxBaseURLLen},
		{"content type", h.ContentType, maxContentTypeLen},
		{"protocol", h.Protocol, maxProtocolLen},
	}
	for _, f := range fields {
		if len(f.value) > f.max {
			return nil, fmt.Errorf("cache: header %s is %d bytes, limit %d", f.name, len(f.value), f.max)
		}
	}
	b := make([]byte, 0, headerRecordLen)
	b = binary.BigEndian.AppendUint16(b, h.Version)
	b = appendString(b, h.KeyID)
	b = appendString(b, string(h.Group))
	b = appendString(b, string(h.Class))
	b = append(b, h.RepoHash[:]...)
	b = append(b, h.KeyHash[:]...)
	b = appendString(b, h.Repo)
	b = appendString(b, h.BaseURL)
	b = binary.BigEndian.AppendUint64(b, uint64(h.CreatedAt.Unix()))       //nolint:gosec // two's-complement round trip, decoded as int64
	b = binary.BigEndian.AppendUint32(b, uint32(h.CreatedAt.Nanosecond())) //nolint:gosec // Nanosecond is in [0, 1e9)
	b = appendString(b, h.ContentType)
	b = appendString(b, h.Protocol)
	// The capacity is zeroed by make, so extending to it pads with zeros.
	return b[:headerRecordLen], nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s))) //nolint:gosec // lengths are bounded by the max*Len constants
	return append(b, s...)
}

// decodeHeader decodes a record written by encodeHeader. Anything other
// than an exact encoding followed by zero padding is ErrIntegrity.
func decodeHeader(record []byte) (entryHeader, error) {
	d := headerDecoder{b: record}
	var h entryHeader
	h.Version = d.uint16()
	h.KeyID = d.string(keyIDLen)
	h.Group = Group(d.string(maxLabelLen))
	h.Class = Class(d.string(maxLabelLen))
	copy(h.RepoHash[:], d.bytes(32))
	copy(h.KeyHash[:], d.bytes(32))
	h.Repo = d.string(maxRepoLen)
	h.BaseURL = d.string(maxBaseURLLen)
	sec := int64(d.uint64()) //nolint:gosec // inverse of encodeHeader
	nsec := d.uint32()
	h.ContentType = d.string(maxContentTypeLen)
	h.Protocol = d.string(maxProtocolLen)
	if d.bad || nsec >= 1e9 {
		return entryHeader{}, fmt.Errorf("%w: malformed header", ErrIntegrity)
	}
	for _, c := range d.b {
		if c != 0 {
			return entryHeader{}, fmt.Errorf("%w: malformed header padding", ErrIntegrity)
		}
	}
	h.CreatedAt = time.Unix(sec, int64(nsec)).UTC()
	return h, nil
}

// headerDecoder consumes fields from b, setting bad instead of panicking
// when a field runs past the end or exceeds its bound.
type headerDecoder struct {
	b   []byte
	bad bool
}

func (d *headerDecoder) bytes(n int) []byte {
	if d.bad || len(d.b) < n {
		d.bad = true
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *headerDecoder) uint16() uint16 {
	if b := d.bytes(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (d *headerDecoder) uint32() uint32 {
	if b := d.bytes(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (d *headerDecoder) uint64() uint64 {
	if b := d.bytes(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (d *headerDecoder) string(limit int) string {
	n := int(d.uint16())
	if n > limit {
		d.bad = true
		return ""
	}
	return string(d.bytes(n))
}
