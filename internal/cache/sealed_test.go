package cache

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func testKeyring(t testing.TB) Keyring {
	t.Helper()
	kr, err := NewKeyring(testKey(0x42))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func testHeader() Header {
	h := Header{
		Group:       GroupPack,
		Class:       ClassFetch,
		Repo:        "github.com/rxbynerd/haybale",
		BaseURL:     "https://github.com",
		CreatedAt:   time.Date(2026, 11, 9, 12, 0, 0, 123456789, time.UTC),
		ContentType: "application/x-git-upload-pack-result",
		Protocol:    "version=2",
	}
	for i := range h.RepoHash {
		h.RepoHash[i] = byte(i)
		h.KeyHash[i] = byte(255 - i)
	}
	return h
}

func sealBytes(t testing.TB, kr Keyring, h Header, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openBytes(t testing.TB, kr Keyring, entry []byte) []byte {
	t.Helper()
	got, err := readEntry(kr, entry)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	return got
}

// readEntry opens and fully reads entry, returning the bytes released
// before the first error.
func readEntry(kr Keyring, entry []byte) ([]byte, error) {
	r, err := NewSealedReader(bytes.NewReader(entry), kr)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func randomBody(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// segmentStarts returns the offset of every framed segment in entry,
// including the trailer, followed by len(entry).
func segmentStarts(t testing.TB, entry []byte) []int {
	t.Helper()
	var starts []int
	for off := headerFixedPrefix; off < len(entry); {
		starts = append(starts, off)
		off += frameLen + int(binary.BigEndian.Uint32(entry[off:]))
	}
	return append(starts, len(entry))
}

func TestSealedRoundTrip(t *testing.T) {
	kr := testKeyring(t)
	sizes := []int{0, 1, SegmentSize - 1, SegmentSize, SegmentSize + 1, 2 * SegmentSize, 5<<20 + 12345}
	for _, n := range sizes {
		body := randomBody(t, n)
		h := testHeader()
		entry := sealBytes(t, kr, h, body)
		if int64(len(entry)) != SealedSize(int64(n)) {
			t.Errorf("size %d: sealed length %d, SealedSize %d", n, len(entry), SealedSize(int64(n)))
		}
		r, err := NewSealedReader(bytes.NewReader(entry), kr)
		if err != nil {
			t.Fatalf("size %d: NewSealedReader: %v", n, err)
		}
		got := r.Header()
		want := h
		want.Version = FormatVersion
		want.KeyID = kr.ActiveID()
		if !got.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("size %d: CreatedAt = %v, want %v", n, got.CreatedAt, want.CreatedAt)
		}
		got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
		if got != want {
			t.Errorf("size %d: Header() = %+v, want %+v", n, got, want)
		}
		if _, ok := r.BodyLength(); ok {
			t.Errorf("size %d: BodyLength known before EOF", n)
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size %d: ReadAll: %v", n, err)
		}
		if !bytes.Equal(plain, body) {
			t.Fatalf("size %d: body mismatch", n)
		}
		if length, ok := r.BodyLength(); !ok || length != int64(n) {
			t.Errorf("size %d: BodyLength() = %d, %v", n, length, ok)
		}
	}
}

func TestSealedWriterSmallWritesAndFlush(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 3*SegmentSize+17)
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	flushes := 0
	for p := body; len(p) > 0; {
		n := min(len(p), 1000)
		if _, err := w.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
		if len(p)%7 == 0 {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			flushes++
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Written() != int64(len(body)) {
		t.Fatalf("Written() = %d, want %d", w.Written(), len(body))
	}
	if flushes == 0 {
		t.Fatal("test did not flush")
	}
	if got := openBytes(t, kr, buf.Bytes()); !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
	if int64(buf.Len()) <= SealedSize(int64(len(body))) {
		t.Fatal("flushed entry is not larger than the unflushed size")
	}
}

func TestSealedFlushOnEmptyBufferIsNoop(t *testing.T) {
	kr := testKeyring(t)
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	before := buf.Len()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != before {
		t.Fatal("Flush with nothing buffered wrote a segment")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close succeeded")
	}
	if err := w.Flush(); err == nil {
		t.Fatal("Flush after Close succeeded")
	}
}

// TestSealedFlushReleasesPendingBytes models a keepalive: a few bytes
// flushed mid-stream reach a reader before the writer sends anything else.
func TestSealedFlushReleasesPendingBytes(t *testing.T) {
	kr := testKeyring(t)
	pr, pw := io.Pipe()
	w, errc := make(chan *SealedWriter, 1), make(chan error, 1)
	go func() {
		sw, err := NewSealedWriter(pw, kr, testHeader())
		if err != nil {
			errc <- err
			return
		}
		w <- sw
	}()
	r, err := NewSealedReader(pr, kr)
	if err != nil {
		t.Fatal(err)
	}
	var sw *SealedWriter
	select {
	case sw = <-w:
	case err := <-errc:
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		if _, err := sw.Write([]byte("0005\x02")); err != nil {
			done <- err
			return
		}
		done <- sw.Flush()
	}()
	got := make([]byte, 5)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(got) != "0005\x02" {
		t.Fatalf("read %q", got)
	}
	go func() {
		err := sw.Close()
		if err == nil {
			err = pw.Close()
		}
		done <- err
	}()
	if rest, err := io.ReadAll(r); err != nil || len(rest) != 0 {
		t.Fatalf("after Close: %q, %v", rest, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSealedSize(t *testing.T) {
	if SealedSize(-1) != -1 {
		t.Fatal("SealedSize(-1) != -1")
	}
	if got, want := SealedSize(0), int64(preambleLen+headerSealedLen+frameLen+trailerCTLen); got != want {
		t.Fatalf("SealedSize(0) = %d, want %d", got, want)
	}
	if SealedSize(SegmentSize+1)-SealedSize(SegmentSize) != 1+segmentOverhead {
		t.Fatal("starting a segment does not add one frame and tag")
	}
}

func TestSealedWriterRejectsBadHeader(t *testing.T) {
	kr := testKeyring(t)
	cases := map[string]func(*Header){
		"version":      func(h *Header) { h.Version = 2 },
		"key id":       func(h *Header) { h.KeyID = "deadbeef" },
		"repo":         func(h *Header) { h.Repo = string(make([]byte, maxRepoLen+1)) },
		"base URL":     func(h *Header) { h.BaseURL = string(make([]byte, maxBaseURLLen+1)) },
		"group":        func(h *Header) { h.Group = Group(make([]byte, maxLabelLen+1)) },
		"content type": func(h *Header) { h.ContentType = string(make([]byte, maxContentTypeLen+1)) },
	}
	for name, mutate := range cases {
		h := testHeader()
		mutate(&h)
		if _, err := NewSealedWriter(io.Discard, kr, h); err == nil {
			t.Errorf("%s: NewSealedWriter error = nil", name)
		}
	}
	if _, err := NewSealedWriter(io.Discard, Keyring{}, testHeader()); err == nil {
		t.Error("zero Keyring: NewSealedWriter error = nil")
	}
}

func TestSealedHeaderLimitsFitRecord(t *testing.T) {
	kr := testKeyring(t)
	h := testHeader()
	h.Group = Group(bytes.Repeat([]byte("g"), maxLabelLen))
	h.Class = Class(bytes.Repeat([]byte("c"), maxLabelLen))
	h.Repo = string(bytes.Repeat([]byte("r"), maxRepoLen))
	h.BaseURL = string(bytes.Repeat([]byte("u"), maxBaseURLLen))
	h.ContentType = string(bytes.Repeat([]byte("t"), maxContentTypeLen))
	h.Protocol = string(bytes.Repeat([]byte("p"), maxProtocolLen))
	entry := sealBytes(t, kr, h, []byte("x"))
	r, err := NewSealedReader(bytes.NewReader(entry), kr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Header().BaseURL != h.BaseURL || r.Header().Protocol != h.Protocol {
		t.Fatal("maximal header did not round trip")
	}
}

func TestSealedTruncation(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 3*SegmentSize+100)
	entry := sealBytes(t, kr, testHeader(), body)

	cuts := []int{0, 1, preambleLen - 1, preambleLen, preambleLen + 100, headerFixedPrefix - 1}
	for _, off := range segmentStarts(t, entry) {
		// At the boundary, inside the frame, inside the ciphertext and
		// inside the tag.
		cuts = append(cuts, off, off+1, off+frameLen, off+frameLen+5, off-1, off-tagLen+1)
	}
	for _, cut := range cuts {
		if cut < 0 || cut >= len(entry) {
			continue
		}
		_, err := readEntry(kr, entry[:cut])
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("truncated at %d of %d: err = %v, want ErrIntegrity", cut, len(entry), err)
		}
	}
}

func TestSealedTrailingBytesRejected(t *testing.T) {
	kr := testKeyring(t)
	entry := sealBytes(t, kr, testHeader(), randomBody(t, 100))
	if _, err := readEntry(kr, append(bytes.Clone(entry), 0)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("trailing byte: err = %v, want ErrIntegrity", err)
	}
}

func TestSealedTrailerLengthMismatch(t *testing.T) {
	kr := testKeyring(t)
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, testHeader())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("twelve bytes")); err != nil {
		t.Fatal(err)
	}
	w.total++ // a trailer recording one byte more than was sealed
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readEntry(kr, buf.Bytes())
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
	if string(got) != "twelve bytes" {
		t.Fatalf("released %q before the trailer check", got)
	}
}

func TestSealedBitFlips(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 2*SegmentSize+10)
	entry := sealBytes(t, kr, testHeader(), body)
	starts := segmentStarts(t, entry) // three body segments, trailer, end

	offsets := map[string]int{
		"magic":             0,
		"version":           len(magic) + 1,
		"key id":            len(magic) + 2,
		"nonce prefix":      preambleLen - 1,
		"header ciphertext": preambleLen + 10,
		"header tag":        headerFixedPrefix - 1,
	}
	names := []string{"segment 1", "segment 2", "segment 3", "trailer"}
	for i, name := range names {
		offsets[name+" frame high byte"] = starts[i]
		offsets[name+" frame low byte"] = starts[i] + frameLen - 1
		offsets[name+" ciphertext"] = starts[i] + frameLen
		offsets[name+" tag"] = starts[i+1] - 1
	}
	for name, off := range offsets {
		mutated := bytes.Clone(entry)
		mutated[off] ^= 0x01
		got, err := readEntry(kr, mutated)
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s (offset %d): err = %v, want ErrIntegrity", name, off, err)
		}
		if !bytes.Equal(got, body[:len(got)]) {
			t.Errorf("%s: released altered plaintext", name)
		}
		// Only whole segments before the flipped one are released.
		for i := range names {
			if off >= starts[i] && off < starts[i+1] && len(got) > i*SegmentSize {
				t.Errorf("%s: released %d bytes from a corrupt segment", name, len(got))
			}
		}
	}
}

func TestSealedSegmentReorderAndDuplicate(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 3*SegmentSize+10)
	entry := sealBytes(t, kr, testHeader(), body)
	starts := segmentStarts(t, entry)
	head := entry[:headerFixedPrefix]
	seg := func(i int) []byte { return entry[starts[i-1]:starts[i]] } // 1..4 body, 5 trailer
	trailer := seg(5)

	cases := map[string][][]byte{
		"swap 1 and 2":       {head, seg(2), seg(1), seg(3), seg(4), trailer},
		"duplicate 1":        {head, seg(1), seg(1), seg(2), seg(3), seg(4), trailer},
		"drop 2":             {head, seg(1), seg(3), seg(4), trailer},
		"drop last body":     {head, seg(1), seg(2), seg(3), trailer},
		"trailer moved up":   {head, seg(1), trailer},
		"trailer duplicated": {head, seg(1), seg(2), seg(3), seg(4), trailer, trailer},
		"no trailer":         {head, seg(1), seg(2), seg(3), seg(4)},
	}
	for name, parts := range cases {
		if _, err := readEntry(kr, bytes.Join(parts, nil)); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: err = %v, want ErrIntegrity", name, err)
		}
	}
}

func TestSealedRejectsInvalidFrameLength(t *testing.T) {
	kr := testKeyring(t)
	entry := sealBytes(t, kr, testHeader(), randomBody(t, 10))
	for _, n := range []uint32{0, tagLen, maxSegmentCTLen + 1, 1 << 31} {
		mutated := bytes.Clone(entry)
		binary.BigEndian.PutUint32(mutated[headerFixedPrefix:], n)
		if _, err := readEntry(kr, mutated); !errors.Is(err, ErrIntegrity) {
			t.Errorf("frame length %d: err = %v, want ErrIntegrity", n, err)
		}
	}
}

func TestSealedRelocationFails(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, SegmentSize+10)
	a := sealBytes(t, kr, testHeader(), body)
	other := testHeader()
	other.KeyHash[0] ^= 0xff
	b := sealBytes(t, kr, other, body)

	spliced := append(bytes.Clone(b[:headerFixedPrefix]), a[headerFixedPrefix:]...)
	if _, err := readEntry(kr, spliced); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("body under another entry's header: err = %v, want ErrIntegrity", err)
	}

	relabelled := bytes.Clone(a)
	copy(relabelled[preambleLen:], b[preambleLen:headerFixedPrefix])
	if _, err := readEntry(kr, relabelled); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("header ciphertext swapped: err = %v, want ErrIntegrity", err)
	}
}

func TestSealedWrongKey(t *testing.T) {
	kr := testKeyring(t)
	entry := sealBytes(t, kr, testHeader(), []byte("payload"))

	other, err := NewKeyring(testKey(0x43))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSealedReader(bytes.NewReader(entry), other); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unknown key id: err = %v, want ErrIntegrity", err)
	}

	// A different key presented under the entry's key id fails the header
	// tag.
	forged := Keyring{active: kr.ActiveID(), sealing: map[string][KeySize]byte{kr.ActiveID(): other.sealing[other.ActiveID()]}}
	if _, err := NewSealedReader(bytes.NewReader(entry), forged); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong key under the right id: err = %v, want ErrIntegrity", err)
	}

	both, err := kr.WithPrevious(testKey(0x43))
	if err != nil {
		t.Fatal(err)
	}
	relabelled := bytes.Clone(entry)
	copy(relabelled[len(magic)+2:], other.ActiveID())
	if _, err := NewSealedReader(bytes.NewReader(relabelled), both); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("key id relabelled: err = %v, want ErrIntegrity", err)
	}
}

func TestSealedNonceDiffersPerEntry(t *testing.T) {
	kr := testKeyring(t)
	a := sealBytes(t, kr, testHeader(), []byte("same"))
	b := sealBytes(t, kr, testHeader(), []byte("same"))
	if bytes.Equal(a[:preambleLen], b[:preambleLen]) {
		t.Fatal("two entries share a nonce prefix")
	}
}

// errReader returns err after data.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestSealedReaderPassesThroughSourceErrors(t *testing.T) {
	kr := testKeyring(t)
	entry := sealBytes(t, kr, testHeader(), randomBody(t, 2*SegmentSize))
	sentinel := errors.New("source failed")
	starts := segmentStarts(t, entry)

	cuts := map[string]int{
		"header":        10,
		"segment":       starts[0] + 100,
		"frame":         starts[1] + 2,
		"after trailer": len(entry),
	}
	for name, cut := range cuts {
		r, err := NewSealedReader(&errReader{data: entry[:cut], err: sentinel}, kr)
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("%s: err = %v, want the source error", name, err)
		}
	}
}

func TestSealedReaderOnGrowingSource(t *testing.T) {
	kr := testKeyring(t)
	body := randomBody(t, 3*SegmentSize+7)
	entry := sealBytes(t, kr, testHeader(), body)
	pr, pw := io.Pipe()
	go func() {
		for p := entry; len(p) > 0; {
			n := min(len(p), 4093)
			if _, err := pw.Write(p[:n]); err != nil {
				return
			}
			p = p[n:]
		}
		_ = pw.Close()
	}()
	r, err := NewSealedReader(pr, kr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
}

func FuzzSealedReader(f *testing.F) {
	kr := testKeyring(f)
	// Seeds stay small so that the fuzzer can mutate and minimise them;
	// Flush gives multi-segment shapes without 64 KiB inputs.
	for _, n := range []int{0, 1, 8, 100} {
		f.Add(sealBytes(f, kr, testHeader(), make([]byte, n)))
	}
	var buf bytes.Buffer
	w, err := NewSealedWriter(&buf, kr, testHeader())
	if err != nil {
		f.Fatal(err)
	}
	for _, chunk := range []string{"0005\x02", "abc", "0000"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			f.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			f.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte(magic))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewSealedReader(bytes.NewReader(data), kr)
		if err != nil {
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("NewSealedReader error %v is not ErrIntegrity", err)
			}
			return
		}
		got, err := io.ReadAll(r)
		if err != nil {
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Read error %v is not ErrIntegrity", err)
			}
			return
		}
		if n, ok := r.BodyLength(); !ok || n != int64(len(got)) {
			t.Fatalf("BodyLength() = %d, %v after reading %d bytes", n, ok, len(got))
		}
		if int64(len(data)) < SealedSize(int64(len(got))) {
			t.Fatalf("accepted %d sealed bytes for a %d-byte body", len(data), len(got))
		}
	})
}
