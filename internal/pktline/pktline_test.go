package pktline

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestAppendEncodesPackets(t *testing.T) {
	tests := []struct {
		name string
		p    Packet
		want string
	}{
		{"data", Packet{Kind: Data, Data: []byte("version 2\n")}, "000eversion 2\n"},
		{"empty data", Packet{Kind: Data}, "0004"},
		{"flush", Packet{Kind: Flush}, "0000"},
		{"delim", Packet{Kind: Delim}, "0001"},
		{"response-end", Packet{Kind: ResponseEnd}, "0002"},
		{"maximum payload", Packet{Kind: Data, Data: bytes.Repeat([]byte("x"), maxPayload)}, "fff0" + strings.Repeat("x", maxPayload)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AppendPacket([]byte("pre"), tt.p)
			if err != nil {
				t.Fatalf("AppendPacket() error = %v", err)
			}
			if string(got) != "pre"+tt.want {
				t.Errorf("AppendPacket() = %q, want %q", got, "pre"+tt.want)
			}
		})
	}
}

func TestAppendRejectsUnencodablePackets(t *testing.T) {
	tests := []struct {
		name string
		p    Packet
	}{
		{"payload too long", Packet{Kind: Data, Data: make([]byte, maxPayload+1)}},
		{"flush with payload", Packet{Kind: Flush, Data: []byte("x")}},
		{"unknown kind", Packet{Kind: Kind(9)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AppendPacket([]byte("pre"), tt.p)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("AppendPacket() error = %v, want ErrMalformed", err)
			}
			if string(got) != "pre" {
				t.Errorf("AppendPacket() modified dst to %q", got)
			}
		})
	}
}

func TestReaderDecodesStream(t *testing.T) {
	in := stream(t, "command=fetch\n", Delim, raw("0004"), "done\n", Flush, ResponseEnd)
	r := NewReader(bytes.NewReader(in), int64(len(in)))
	want := []Packet{
		{Kind: Data, Data: []byte("command=fetch\n")},
		{Kind: Delim},
		{Kind: Data, Data: []byte{}},
		{Kind: Data, Data: []byte("done\n")},
		{Kind: Flush},
		{Kind: ResponseEnd},
	}
	for i, w := range want {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("Next() #%d error = %v", i, err)
		}
		if got.Kind != w.Kind || !bytes.Equal(got.Data, w.Data) {
			t.Fatalf("Next() #%d = %v %q, want %v %q", i, got.Kind, got.Data, w.Kind, w.Data)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next() at end error = %v, want io.EOF", err)
	}
}

func TestReaderRejectsMalformedStreams(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"length 0003", "0003"},
		{"uppercase hex", "000Aabcdef"},
		{"non-hex", "zzzz"},
		{"above maximum", "fff1"},
		{"truncated prefix", "00"},
		{"truncated payload", "0009do"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(strings.NewReader(tt.in), 1<<20)
			_, err := r.Next()
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Next() error = %v, want ErrMalformed", err)
			}
			if _, again := r.Next(); !errors.Is(again, ErrMalformed) {
				t.Errorf("second Next() error = %v, want the sticky ErrMalformed", again)
			}
		})
	}
}

// failingReader serves prefix and then fails, so a test can prove the
// Reader never reads past a point.
type failingReader struct {
	prefix []byte
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.prefix) == 0 {
		return 0, errors.New("read past the permitted point")
	}
	n := copy(p, f.prefix)
	f.prefix = f.prefix[n:]
	return n, nil
}

func TestReaderEnforcesLimit(t *testing.T) {
	t.Run("payload beyond limit is not read", func(t *testing.T) {
		r := NewReader(&failingReader{prefix: []byte("fff0")}, 100)
		if _, err := r.Next(); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Next() error = %v, want ErrTooLarge", err)
		}
	})
	t.Run("prefix beyond limit", func(t *testing.T) {
		in := stream(t, "abc", Flush)
		r := NewReader(bytes.NewReader(in), int64(len(in))-1)
		if _, err := r.Next(); err != nil {
			t.Fatalf("first Next() error = %v", err)
		}
		if _, err := r.Next(); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("second Next() error = %v, want ErrTooLarge", err)
		}
	})
	t.Run("stream exactly at limit", func(t *testing.T) {
		in := stream(t, "abc", Flush)
		r := NewReader(bytes.NewReader(in), int64(len(in)))
		for range 2 {
			if _, err := r.Next(); err != nil {
				t.Fatalf("Next() error = %v", err)
			}
		}
		if _, err := r.Next(); !errors.Is(err, io.EOF) {
			t.Fatalf("Next() at end error = %v, want io.EOF", err)
		}
	})
}

func TestReaderPassesThroughReadErrors(t *testing.T) {
	r := NewReader(&failingReader{prefix: []byte("0009")}, 100)
	_, err := r.Next()
	if err == nil || errors.Is(err, ErrMalformed) || errors.Is(err, ErrTooLarge) {
		t.Fatalf("Next() error = %v, want the underlying read error", err)
	}
}

// FuzzReader checks that decoding never panics, never consumes more than
// the limit, and that re-encoding the decoded packets reproduces the
// bytes consumed.
func FuzzReader(f *testing.F) {
	for _, fx := range scanFixtures(f) {
		f.Add(fx.body, int64(len(fx.body)))
	}
	f.Add([]byte("0003"), int64(10))
	f.Add([]byte("fff0"), int64(8))
	f.Add([]byte("0000"), int64(-1))
	f.Fuzz(func(t *testing.T, in []byte, limit int64) {
		r := NewReader(bytes.NewReader(in), limit)
		var encoded []byte
		var err error
		for {
			var p Packet
			p, err = r.Next()
			if err != nil {
				break
			}
			if encoded, err = AppendPacket(encoded, p); err != nil {
				t.Fatalf("AppendPacket(decoded packet) error = %v", err)
			}
		}
		if len(encoded) > 0 && int64(len(encoded)) > limit {
			t.Fatalf("decoded %d bytes past limit %d", len(encoded), limit)
		}
		if !bytes.HasPrefix(in, encoded) {
			t.Fatalf("re-encoded packets %q are not a prefix of the input %q", encoded, in)
		}
		switch {
		case errors.Is(err, io.EOF):
			if len(encoded) != len(in) {
				t.Fatalf("io.EOF after consuming %d of %d bytes", len(encoded), len(in))
			}
		case errors.Is(err, ErrMalformed), errors.Is(err, ErrTooLarge):
		default:
			t.Fatalf("Next() error = %v, want io.EOF, ErrMalformed or ErrTooLarge", err)
		}
	})
}
