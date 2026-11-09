// Package pktline reads, encodes and scans git pkt-line streams
// (https://git-scm.com/docs/gitprotocol-common#_pkt_line_format).
//
// A pkt-line is a four-digit hex length, counting the prefix itself,
// followed by that many minus four bytes of payload. The lengths 0000
// (flush), 0001 (delim) and 0002 (response-end) are special packets with
// no payload; 0003, any other length below 4, and any length above
// MaxPacketLength are malformed. Only lowercase hex is accepted: git
// always writes lowercase, and a stricter decoder can only cause a
// request or response to be treated as unrecognised.
//
// The package is dependency-free so that the code deciding what the
// response cache stores remains easy to audit.
package pktline

import (
	"errors"
	"fmt"
	"io"
)

// MaxPacketLength is the largest total length of one pkt-line,
// including its four-byte length prefix.
const MaxPacketLength = 65520

// maxPayload is the largest payload a data packet can carry.
const maxPayload = MaxPacketLength - 4

// Kind distinguishes data packets from the special packets.
type Kind uint8

const (
	// Data is a packet carrying a payload (length 0004 or more).
	Data Kind = iota
	// Flush is the 0000 packet.
	Flush
	// Delim is the 0001 packet, separating sections in protocol v2.
	Delim
	// ResponseEnd is the 0002 packet, ending a stateless protocol v2
	// response.
	ResponseEnd
)

// String renders k for logs and test failures.
func (k Kind) String() string {
	switch k {
	case Data:
		return "data"
	case Flush:
		return "flush"
	case Delim:
		return "delim"
	case ResponseEnd:
		return "response-end"
	default:
		return "unknown"
	}
}

// Packet is one decoded pkt-line. Data is set only when Kind is Data,
// and may be empty for a 0004 packet.
type Packet struct {
	Kind Kind
	Data []byte
}

var (
	// ErrMalformed is returned (wrapped) for an invalid length prefix, a
	// packet truncated by the end of the stream, or a payload too long to
	// encode.
	ErrMalformed = errors.New("pktline: malformed packet")
	// ErrTooLarge is returned when a stream exceeds the Reader's limit.
	ErrTooLarge = errors.New("pktline: stream exceeds limit")
)

// decodeLength interprets a four-byte length prefix. size is the payload
// length for a Data packet and zero otherwise; ok is false for any
// prefix that is not lowercase hex or does not name a valid packet.
func decodeLength(prefix []byte) (kind Kind, size int, ok bool) {
	n := 0
	for _, c := range prefix[:4] {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		default:
			return 0, 0, false
		}
		n = n<<4 | v
	}
	switch {
	case n == 0:
		return Flush, 0, true
	case n == 1:
		return Delim, 0, true
	case n == 2:
		return ResponseEnd, 0, true
	case n < 4 || n > MaxPacketLength:
		return 0, 0, false
	default:
		return Data, n - 4, true
	}
}

// Reader decodes a pkt-line stream whose total size is bounded.
type Reader struct {
	r     io.Reader
	limit int64
	read  int64
	err   error
}

// NewReader returns a Reader that decodes packets from r and fails with
// ErrTooLarge once the packets it has consumed would exceed limit bytes.
// A payload is allocated only after its length has been checked against
// the remaining limit.
func NewReader(r io.Reader, limit int64) *Reader {
	return &Reader{r: r, limit: limit}
}

// Next returns the next packet. It returns io.EOF when the stream ends
// exactly on a packet boundary. Any other error is sticky: every later
// call returns it again. The returned Data is owned by the caller.
func (r *Reader) Next() (Packet, error) {
	if r.err != nil {
		return Packet{}, r.err
	}
	p, err := r.next()
	if err != nil {
		r.err = err
	}
	return p, err
}

func (r *Reader) next() (Packet, error) {
	var prefix [4]byte
	n, err := io.ReadFull(r.r, prefix[:])
	r.read += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		return Packet{}, io.EOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		return Packet{}, fmt.Errorf("%w: truncated length prefix", ErrMalformed)
	case err != nil:
		return Packet{}, err
	}
	if r.read > r.limit {
		return Packet{}, ErrTooLarge
	}
	kind, size, ok := decodeLength(prefix[:])
	if !ok {
		return Packet{}, fmt.Errorf("%w: invalid length prefix %q", ErrMalformed, prefix[:])
	}
	if kind != Data {
		return Packet{Kind: kind}, nil
	}
	if int64(size) > r.limit-r.read {
		return Packet{}, ErrTooLarge
	}
	data := make([]byte, size)
	n, err = io.ReadFull(r.r, data)
	r.read += int64(n)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return Packet{}, fmt.Errorf("%w: truncated payload", ErrMalformed)
	case err != nil:
		return Packet{}, err
	}
	return Packet{Kind: Data, Data: data}, nil
}

const hexDigits = "0123456789abcdef"

func appendLength(dst []byte, n int) []byte {
	return append(dst, hexDigits[n>>12&0xf], hexDigits[n>>8&0xf], hexDigits[n>>4&0xf], hexDigits[n&0xf])
}

// AppendPacket appends the encoding of p to dst. It fails with
// ErrMalformed for an unknown Kind, a special packet carrying Data, or a
// payload longer than MaxPacketLength allows.
func AppendPacket(dst []byte, p Packet) ([]byte, error) {
	if p.Kind != Data && len(p.Data) > 0 {
		return dst, fmt.Errorf("%w: %s packet with payload", ErrMalformed, p.Kind)
	}
	switch p.Kind {
	case Data:
		return AppendData(dst, p.Data)
	case Flush:
		return AppendFlush(dst), nil
	case Delim:
		return AppendDelim(dst), nil
	case ResponseEnd:
		return appendLength(dst, 2), nil
	default:
		return dst, fmt.Errorf("%w: unknown packet kind %d", ErrMalformed, p.Kind)
	}
}

// AppendData appends a data packet carrying data to dst.
func AppendData(dst []byte, data []byte) ([]byte, error) {
	if len(data) > maxPayload {
		return dst, fmt.Errorf("%w: payload of %d bytes exceeds %d", ErrMalformed, len(data), maxPayload)
	}
	dst = appendLength(dst, len(data)+4)
	return append(dst, data...), nil
}

// AppendFlush appends a flush packet to dst.
func AppendFlush(dst []byte) []byte {
	return appendLength(dst, 0)
}

// AppendDelim appends a delim packet to dst.
func AppendDelim(dst []byte) []byte {
	return appendLength(dst, 1)
}
