package pktline

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// scan writes body to a new Scanner in chunks ending at each split
// offset and returns the verdict for a clean EOF.
func scan(mode Mode, body []byte, splits ...int) Verdict {
	s := NewScanner(mode)
	prev := 0
	for _, at := range append(splits, len(body)) {
		if n, err := s.Write(body[prev:at]); n != at-prev || err != nil {
			panic("Scanner.Write did not accept the whole chunk")
		}
		prev = at
	}
	return s.Verdict(true)
}

func wantVerdict(reason string) Verdict {
	return Verdict{Storable: reason == "", Reason: reason}
}

func TestScannerVerdicts(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			if got, want := scan(fx.mode, fx.body), wantVerdict(fx.reason); got != want {
				t.Fatalf("Verdict() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestScannerVerdictIndependentOfWriteBoundaries(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			want := wantVerdict(fx.reason)
			for i := 0; i <= len(fx.body); i++ {
				if got := scan(fx.mode, fx.body, i); got != want {
					t.Fatalf("split at %d: Verdict() = %+v, want %+v", i, got, want)
				}
			}
			bytewise := make([]int, len(fx.body))
			for i := range bytewise {
				bytewise[i] = i
			}
			if got := scan(fx.mode, fx.body, bytewise...); got != want {
				t.Fatalf("byte by byte: Verdict() = %+v, want %+v", got, want)
			}
			if len(fx.body) > 400 {
				return
			}
			for i := 0; i <= len(fx.body); i++ {
				for j := i; j <= len(fx.body); j++ {
					if got := scan(fx.mode, fx.body, i, j); got != want {
						t.Fatalf("splits at %d and %d: Verdict() = %+v, want %+v", i, j, got, want)
					}
				}
			}
		})
	}
}

func TestScannerTruncatedWithoutCleanEOF(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		if fx.reason != "" {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			s := NewScanner(fx.mode)
			_, _ = s.Write(fx.body)
			if got, want := s.Verdict(false), wantVerdict(ReasonTruncated); got != want {
				t.Fatalf("Verdict(false) = %+v, want %+v", got, want)
			}
		})
	}
}

func TestScannerTruncatedAtEveryPrefix(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		if fx.reason != "" {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			for i := 0; i < len(fx.body); i++ {
				if got := scan(fx.mode, fx.body[:i]); got.Storable {
					t.Fatalf("prefix of %d of %d bytes is storable", i, len(fx.body))
				}
			}
		})
	}
}

func TestScannerFirstFailureWins(t *testing.T) {
	body := stream(t, "packfile\n", "\x03fatal\n", "ERR later\n", raw("0003"))
	if got, want := scan(ModeV2Fetch, body), wantVerdict(ReasonSidebandError); got != want {
		t.Fatalf("Verdict() = %+v, want %+v", got, want)
	}
}

func TestScannerDoesNotAllocateOnWrite(t *testing.T) {
	body := stream(t, "packfile\n", "\x01"+string(make([]byte, maxPayload-1)), Flush)
	s := NewScanner(ModeV2Fetch)
	allocs := testing.AllocsPerRun(100, func() {
		*s = *NewScanner(ModeV2Fetch)
		_, _ = s.Write(body)
	})
	// NewScanner itself allocates the Scanner; Write must add nothing.
	if allocs > 1 {
		t.Fatalf("scanning allocated %.0f times per run, want at most 1", allocs)
	}
}

// FuzzScanner checks that a verdict does not depend on how the stream is
// split across writes, that a stream the reference parser finds an ERR
// packet or sideband channel 3 frame in is never storable, and that a
// storable stream is well-formed and ends in a flush.
func FuzzScanner(f *testing.F) {
	modes := []Mode{ModeAdvertisement, ModeV2Result, ModeV2Fetch, ModeV0UploadPack}
	for _, fx := range scanFixtures(f) {
		for _, mode := range modes {
			f.Add(fx.body, uint8(mode), len(fx.body)/2)
		}
	}
	for _, c := range oracleCases(f) {
		f.Add(c.body, uint8(c.mode), len(c.body)/2)
	}
	f.Fuzz(func(t *testing.T, body []byte, mode uint8, split int) {
		m := Mode(mode % 5)
		checkOracle(t, m, body, split)
		if !scanVerdicts(m, body, nil).clean.Storable {
			return
		}
		r := NewReader(bytes.NewReader(body), int64(len(body)))
		var last Packet
		for {
			p, err := r.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("storable stream fails to decode: %v", err)
			}
			last = p
		}
		if last.Kind != Flush {
			t.Fatalf("storable stream ends with %v, want flush", last.Kind)
		}
	})
}
