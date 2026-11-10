package pktline

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The reference parser below decides, for a complete buffer, whether a
// response contains an ERR packet or a sideband channel 3 frame, and
// whether the response matches its mode's grammar. It shares no code with
// the Scanner: it splits the whole buffer into packets first and then
// matches the packet list against the grammar from the Mode documentation.
// Where that documentation does not say whether a shape is allowed (for
// example a packfile section with no frames), the reference accepts it, so
// that a Scanner verdict of storable implies the reference's well-formed
// verdict but not the converse.

// refPacket is one packet of a split buffer. length is the value of the
// four-digit prefix; payload is set for data packets only.
type refPacket struct {
	length  int
	payload []byte
}

func (p refPacket) isFlush() bool    { return p.length == 0 }
func (p refPacket) isDelim() bool    { return p.length == 1 }
func (p refPacket) isData() bool     { return p.length >= 4 }
func (p refPacket) hasPayload() bool { return p.isData() && len(p.payload) > 0 }

// isLine reports whether the payload is text, optionally followed by one
// newline.
func (p refPacket) isLine(text string) bool {
	return p.isData() && (string(p.payload) == text || string(p.payload) == text+"\n")
}

func (p refPacket) hasPrefix(prefix string) bool {
	return p.isData() && strings.HasPrefix(string(p.payload), prefix)
}

func (p refPacket) isAck() bool { return p.isLine("NAK") || p.hasPrefix("ACK ") }

// refSplit cuts body into packets. whole is true when body is nothing but
// complete, valid packets; otherwise the packets before the first
// incomplete or malformed one are returned.
func refSplit(body []byte) (pkts []refPacket, whole bool) {
	const maxLength = 65520
	for len(body) > 0 {
		if len(body) < 4 {
			return pkts, false
		}
		n := 0
		for _, c := range body[:4] {
			var digit int
			switch {
			case c >= '0' && c <= '9':
				digit = int(c - '0')
			case c >= 'a' && c <= 'f':
				digit = int(c-'a') + 10
			default:
				return pkts, false
			}
			n = n*16 + digit
		}
		if n == 3 || n > maxLength {
			return pkts, false
		}
		if n < 4 {
			pkts = append(pkts, refPacket{length: n})
			body = body[4:]
			continue
		}
		if len(body) < n {
			return pkts, false
		}
		pkts = append(pkts, refPacket{length: n, payload: body[4:n]})
		body = body[n:]
	}
	return pkts, true
}

// refResult is the reference parser's report on one buffer.
type refResult struct {
	// hasErr is set when any complete data packet's payload begins with
	// "ERR ".
	hasErr bool
	// hasChan3 is set when a sideband frame in the mode's sideband
	// section has channel 3 and every packet before it fits the
	// grammar.
	hasChan3 bool
	// wellFormed is set when the whole buffer is one complete response
	// of the mode with no ERR packet and no channel 3 frame.
	wellFormed bool
}

func refScan(mode Mode, body []byte) refResult {
	pkts, whole := refSplit(body)
	var res refResult
	for _, p := range pkts {
		if p.hasPrefix("ERR ") {
			res.hasErr = true
		}
	}
	var consumed int
	var grammarOK bool
	switch mode {
	case ModeAdvertisement:
		consumed, grammarOK = refAdvertisement(pkts)
	case ModeV2Result:
		consumed, grammarOK = refV2Result(pkts)
	case ModeV2Fetch:
		consumed, grammarOK, res.hasChan3 = refV2Fetch(pkts)
	case ModeV0UploadPack:
		consumed, grammarOK, res.hasChan3 = refV0UploadPack(pkts)
	}
	res.wellFormed = whole && grammarOK && consumed == len(pkts) && !res.hasErr && !res.hasChan3
	return res
}

// refLines returns the index after the run of non-empty data packets
// starting at i.
func refLines(pkts []refPacket, i int) int {
	for i < len(pkts) && pkts[i].hasPayload() {
		i++
	}
	return i
}

func refAdvertisement(pkts []refPacket) (consumed int, ok bool) {
	i := 0
	service := false
	if i < len(pkts) && pkts[i].isLine("# service=git-upload-pack") {
		service = true
		i++
		if i >= len(pkts) || !pkts[i].isFlush() {
			return i, false
		}
		i++
	}
	end := refLines(pkts, i)
	if end == i || (!service && pkts[i].hasPrefix("#")) {
		return i, false
	}
	if end >= len(pkts) || !pkts[end].isFlush() {
		return end, false
	}
	return end + 1, true
}

func refV2Result(pkts []refPacket) (consumed int, ok bool) {
	end := refLines(pkts, 0)
	if end >= len(pkts) || !pkts[end].isFlush() {
		return end, false
	}
	return end + 1, true
}

func refV2Fetch(pkts []refPacket) (consumed int, ok, chan3 bool) {
	i := 0
	stage := 0 // 0 nothing yet, 1 after shallow-info, 2 after wanted-refs
	for i < len(pkts) {
		header := pkts[i]
		switch {
		case header.isLine("shallow-info") && stage < 1:
			stage = 1
		case header.isLine("wanted-refs") && stage < 2:
			stage = 2
		case header.isLine("packfile"):
			end, chan3, ok := refFrames(pkts, i+1)
			return end, ok, chan3
		default:
			return i, false, false
		}
		i = refLines(pkts, i+1)
		if i >= len(pkts) || !pkts[i].isDelim() {
			return i, false, false
		}
		i++
	}
	return i, false, false
}

// refFrames matches sideband frames of channel 1 or 2 followed by a flush,
// starting at i, and reports whether it met a channel 3 frame.
func refFrames(pkts []refPacket, i int) (end int, chan3, ok bool) {
	for ; i < len(pkts) && pkts[i].isData(); i++ {
		if !pkts[i].hasPayload() {
			return i, false, false
		}
		switch pkts[i].payload[0] {
		case 1, 2:
		case 3:
			return i, true, false
		default:
			return i, false, false
		}
	}
	if i >= len(pkts) || !pkts[i].isFlush() {
		return i, false, false
	}
	return i + 1, false, true
}

func refV0UploadPack(pkts []refPacket) (consumed int, ok, chan3 bool) {
	i := 0
	shallow := i
	for shallow < len(pkts) && (pkts[shallow].hasPrefix("shallow ") || pkts[shallow].hasPrefix("unshallow ")) {
		shallow++
	}
	switch {
	case shallow < len(pkts) && pkts[shallow].isFlush():
		i = shallow + 1
	case shallow > i:
		return shallow, false, false
	}
	acks := i
	for acks < len(pkts) && pkts[acks].isAck() {
		acks++
	}
	if acks == i {
		return i, false, false
	}
	end, chan3, ok := refFrames(pkts, acks)
	return end, ok, chan3
}

// oracleCase is one response and what the reference parser must report
// for it. When the response holds an ERR packet or channel 3 frame,
// wantReason is the Scanner's reason for it; otherwise the Scanner's
// verdict is unconstrained here beyond the properties checked for all
// inputs.
type oracleCase struct {
	name       string
	mode       Mode
	body       []byte
	wantErr    bool
	wantChan3  bool
	wantReason string
}

func oracleCases(t testing.TB) []oracleCase {
	s := func(parts ...any) []byte { return stream(t, parts...) }
	longErr := "ERR " + strings.Repeat("x", 3*captureSize)
	const (
		errPkt  = ReasonErrorPacket
		sideErr = ReasonSidebandError
	)
	return []oracleCase{
		{"advertisement ERR first", ModeAdvertisement, s("ERR access denied\n", Flush), true, false, errPkt},
		{"advertisement ERR after service line", ModeAdvertisement, s("# service=git-upload-pack\n", Flush, "ERR no repository\n"), true, false, errPkt},
		{"advertisement ERR among lines", ModeAdvertisement, s("version 2\n", "ERR later\n", "agent=git/2.54.0\n", Flush), true, false, errPkt},
		{"advertisement ERR with empty message", ModeAdvertisement, s("ERR ", Flush), true, false, errPkt},
		{"advertisement ERR without newline", ModeAdvertisement, s("ERR denied", Flush), true, false, errPkt},
		{"advertisement ERR longer than the capture", ModeAdvertisement, s(longErr, Flush), true, false, errPkt},
		{"advertisement ERR and no flush", ModeAdvertisement, s("ERR x\n"), true, false, errPkt},
		{"advertisement ERR after the final flush", ModeAdvertisement, s("version 2\n", Flush, "ERR late\n"), true, false, ReasonFraming},
		{"advertisement ERR before a malformed length", ModeAdvertisement, s("version 2\n", "ERR x\n", raw("zzzz")), true, false, errPkt},
		{"advertisement ERR without the space", ModeAdvertisement, s("ERR\n", Flush), false, false, ""},
		{"advertisement lowercase err", ModeAdvertisement, s("err x\n", Flush), false, false, ""},
		{"advertisement ERR not at the start of a line", ModeAdvertisement, s(" ERR x\n", Flush), false, false, ""},
		{"advertisement channel 3 byte is a plain line", ModeAdvertisement, s("version 2\n", "\x03fatal\n", Flush), false, false, ""},

		{"result ERR first", ModeV2Result, s("ERR denied\n", Flush), true, false, errPkt},
		{"result ERR among refs", ModeV2Result, s(oidA+" HEAD\n", "ERR broke\n", oidB+" refs/heads/x\n", Flush), true, false, errPkt},
		{"result ERR after the flush", ModeV2Result, s(Flush, "ERR late\n"), true, false, ReasonFraming},
		{"result ERR longer than the capture", ModeV2Result, s(longErr, Flush), true, false, errPkt},
		{"result ERR without the space", ModeV2Result, s("ERRx\n", Flush), false, false, ""},
		{"result channel 3 byte is a plain line", ModeV2Result, s("\x03fatal\n", Flush), false, false, ""},

		{"fetch ERR instead of a section", ModeV2Fetch, s("ERR not our ref\n"), true, false, errPkt},
		{"fetch ERR in shallow-info", ModeV2Fetch, s("shallow-info\n", "ERR bad\n", Delim, "packfile\n", Flush), true, false, errPkt},
		{"fetch ERR in wanted-refs", ModeV2Fetch, s("wanted-refs\n", "ERR bad\n", Delim, "packfile\n", Flush), true, false, errPkt},
		{"fetch ERR right after the packfile header", ModeV2Fetch, s("packfile\n", "ERR bad\n", Flush), true, false, errPkt},
		{"fetch ERR between frames", ModeV2Fetch, s("packfile\n", "\x01PACK", "ERR mid-pack\n", "\x01more", Flush), true, false, errPkt},
		{"fetch ERR after the last frame", ModeV2Fetch, s("packfile\n", "\x01PACK", "ERR end\n"), true, false, errPkt},
		{"fetch ERR longer than the capture", ModeV2Fetch, s("packfile\n", longErr, Flush), true, false, errPkt},
		{"fetch ERR after the final flush", ModeV2Fetch, s("packfile\n", "\x01PACK", Flush, "ERR late\n"), true, false, ReasonFraming},
		{"fetch ERR text inside pack data", ModeV2Fetch, s("packfile\n", "\x01ERR inside pack data\n", "\x02ERR inside progress\n", Flush), false, false, ""},

		{"fetch channel 3 first frame", ModeV2Fetch, s("packfile\n", "\x03fatal: out of memory\n", Flush), false, true, sideErr},
		{"fetch channel 3 after frames", ModeV2Fetch, s("packfile\n", "\x02progress\n", "\x01PACK", "\x03fatal\n", Flush), false, true, sideErr},
		{"fetch channel 3 with no message", ModeV2Fetch, s("packfile\n", "\x03", Flush), false, true, sideErr},
		{"fetch channel 3 with a maximum length message", ModeV2Fetch, s("packfile\n", "\x03"+strings.Repeat("m", maxPayload-1), Flush), false, true, sideErr},
		{"fetch channel 3 after shallow-info and wanted-refs", ModeV2Fetch, s("shallow-info\n", "shallow "+oidA+"\n", Delim, "wanted-refs\n", oidB+" refs/heads/x\n", Delim, "packfile\n", "\x01PACK", "\x03fatal\n", Flush), false, true, sideErr},
		{"fetch channel 3 and no flush", ModeV2Fetch, s("packfile\n", "\x01PACK", "\x03fatal\n"), false, true, sideErr},
		{"fetch channel 3 before a malformed length", ModeV2Fetch, s("packfile\n", "\x03fatal\n", raw("zzzz")), false, true, sideErr},
		{"fetch channel 3 then ERR", ModeV2Fetch, s("packfile\n", "\x03fatal\n", "ERR later\n", Flush), true, true, sideErr},
		{"fetch ERR then channel 3", ModeV2Fetch, s("packfile\n", "ERR first\n", "\x03fatal\n", Flush), true, false, errPkt},
		{"fetch channel 3 after the final flush", ModeV2Fetch, s("packfile\n", "\x01PACK", Flush, "\x03late\n"), false, false, ""},
		{"fetch channel 3 byte in shallow-info is a plain line", ModeV2Fetch, s("shallow-info\n", "\x03line\n", Delim, "packfile\n", "\x01PACK", Flush), false, false, ""},
		{"fetch packfile line inside shallow-info is a plain line", ModeV2Fetch, s("shallow-info\n", "packfile\n", "\x03line\n", Delim, "packfile\n", "\x01PACK", Flush), false, false, ""},
		{"fetch channel 3 byte as a section header", ModeV2Fetch, s("\x03fatal\n", Flush), false, false, ""},
		{"fetch channel 4 is not channel 3", ModeV2Fetch, s("packfile\n", "\x04fatal\n", Flush), false, false, ""},

		{"upload-pack ERR first", ModeV0UploadPack, s("ERR not our ref\n"), true, false, errPkt},
		{"upload-pack ERR in the shallow list", ModeV0UploadPack, s("shallow "+oidA+"\n", "ERR bad\n", Flush, "NAK\n", "\x01PACK", Flush), true, false, errPkt},
		{"upload-pack ERR after NAK", ModeV0UploadPack, s("NAK\n", "ERR oops\n", Flush), true, false, errPkt},
		{"upload-pack ERR between frames", ModeV0UploadPack, s("NAK\n", "\x01PACK", "ERR oops\n", "\x01more", Flush), true, false, errPkt},
		{"upload-pack ERR longer than the capture", ModeV0UploadPack, s("NAK\n", longErr, Flush), true, false, errPkt},
		{"upload-pack ERR after the final flush", ModeV0UploadPack, s("NAK\n", "\x01PACK", Flush, "ERR late\n"), true, false, ReasonFraming},
		{"upload-pack ERR text inside progress", ModeV0UploadPack, s("NAK\n", "\x02ERR inside progress\n", "\x01PACK", Flush), false, false, ""},

		{"upload-pack channel 3 right after NAK", ModeV0UploadPack, s("NAK\n", "\x03fatal\n", Flush), false, true, sideErr},
		{"upload-pack channel 3 after ACK lines", ModeV0UploadPack, s("ACK "+oidA+" common\n", "ACK "+oidB+" ready\n", "\x03fatal\n", Flush), false, true, sideErr},
		{"upload-pack channel 3 after frames", ModeV0UploadPack, s("NAK\n", "\x02progress\n", "\x01PACK", "\x03fatal\n", Flush), false, true, sideErr},
		{"upload-pack channel 3 after a shallow list", ModeV0UploadPack, s("shallow "+oidA+"\n", Flush, "NAK\n", "\x03fatal\n", Flush), false, true, sideErr},
		{"upload-pack channel 3 after an empty shallow list", ModeV0UploadPack, s(Flush, "NAK\n", "\x03fatal\n", Flush), false, true, sideErr},
		{"upload-pack channel 3 with no message", ModeV0UploadPack, s("NAK\n", "\x03", Flush), false, true, sideErr},
		{"upload-pack channel 3 and no flush", ModeV0UploadPack, s("NAK\n", "\x01PACK", "\x03fatal\n"), false, true, sideErr},
		{"upload-pack channel 3 before a malformed length", ModeV0UploadPack, s("NAK\n", "\x03fatal\n", raw("zzzz")), false, true, sideErr},
		{"upload-pack channel 3 then ERR", ModeV0UploadPack, s("NAK\n", "\x03fatal\n", "ERR later\n", Flush), true, true, sideErr},
		{"upload-pack ERR then channel 3", ModeV0UploadPack, s("NAK\n", "ERR first\n", "\x03fatal\n", Flush), true, false, errPkt},
		{"upload-pack channel 3 byte before any ACK", ModeV0UploadPack, s("\x03fatal\n", Flush), false, false, ""},
		{"upload-pack channel 3 byte in the shallow list", ModeV0UploadPack, s("shallow "+oidA+"\n", "\x03fatal\n", Flush), false, false, ""},

		{"unknown mode ERR", Mode(0), s("ERR x\n", Flush), true, false, ReasonUnexpectedSection},
	}
}

func TestReferenceParserFindsErrAndChannel3(t *testing.T) {
	for _, c := range oracleCases(t) {
		t.Run(c.name, func(t *testing.T) {
			got := refScan(c.mode, c.body)
			if got.hasErr != c.wantErr || got.hasChan3 != c.wantChan3 {
				t.Fatalf("refScan() = {hasErr %v, hasChan3 %v}, want {hasErr %v, hasChan3 %v}",
					got.hasErr, got.hasChan3, c.wantErr, c.wantChan3)
			}
			if (c.wantErr || c.wantChan3) && got.wellFormed {
				t.Fatal("refScan() reports a stream with an ERR packet or channel 3 frame as well-formed")
			}
		})
	}
}

func TestReferenceParserAcceptsStorableFixtures(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		if fx.reason != "" {
			continue
		}
		t.Run(fx.name, func(t *testing.T) {
			if got := refScan(fx.mode, fx.body); !got.wellFormed || got.hasErr || got.hasChan3 {
				t.Fatalf("refScan() = %+v, want a well-formed stream", got)
			}
		})
	}
}

func TestScannerRefusesErrAndChannel3(t *testing.T) {
	for _, c := range oracleCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if c.wantErr || c.wantChan3 {
				if got, want := scan(c.mode, c.body), wantVerdict(c.wantReason); got != want {
					t.Fatalf("Verdict() = %+v, want %+v", got, want)
				}
			}
			checkOracle(t, c.mode, c.body, len(c.body)/2)
		})
	}
}

func TestScannerFixturesAgreeWithReferenceParser(t *testing.T) {
	for _, fx := range scanFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			checkOracle(t, fx.mode, fx.body, len(fx.body)/2)
		})
	}
}

// verdicts holds a Scanner's verdict for a body that ended cleanly and for
// one that was cut short.
type verdicts struct {
	clean, truncated Verdict
}

// scanVerdicts feeds body to a new Scanner in chunks ending at each
// ascending split offset.
func scanVerdicts(mode Mode, body []byte, splits []int) verdicts {
	s := NewScanner(mode)
	prev := 0
	for _, at := range slices.Concat(splits, []int{len(body)}) {
		if n, err := s.Write(body[prev:at]); n != at-prev || err != nil {
			panic("Scanner.Write did not accept the whole chunk")
		}
		prev = at
	}
	return verdicts{clean: s.Verdict(true), truncated: s.Verdict(false)}
}

// splitOffset maps any int onto an offset within body.
func splitOffset(body []byte, split int) int {
	at := split % (len(body) + 1)
	if at < 0 {
		at = -at
	}
	return at
}

// checkOracle checks the Scanner against the reference parser for body and
// for a prefix of it, and checks that the verdicts do not depend on how
// body is split across writes.
func checkOracle(t *testing.T, mode Mode, body []byte, split int) {
	t.Helper()
	at := splitOffset(body, split)
	checkChunkings(t, mode, body, at, split)
	checkAgainstReference(t, mode, body)
	checkAgainstReference(t, mode, body[:at])
}

// randomOffsets returns one to four ascending offsets into body derived
// deterministically from seed.
func randomOffsets(body []byte, seed int) []int {
	state := seed ^ len(body)
	next := func() int {
		state = state*1103515245 + 12345
		return state >> 16 & 0x7fff
	}
	offsets := make([]int, 1+next()%4)
	for i := range offsets {
		offsets[i] = next() % (len(body) + 1)
	}
	slices.Sort(offsets)
	return offsets
}

func checkChunkings(t *testing.T, mode Mode, body []byte, at, seed int) {
	t.Helper()
	bytewise := make([]int, len(body))
	for i := range bytewise {
		bytewise[i] = i
	}
	random := randomOffsets(body, seed)

	whole := scanVerdicts(mode, body, nil)
	for _, c := range []struct {
		name   string
		splits []int
	}{
		{fmt.Sprintf("split at %d", at), []int{at}},
		{"byte by byte", bytewise},
		{"random splits", random},
	} {
		if got := scanVerdicts(mode, body, c.splits); got != whole {
			t.Fatalf("%s: verdicts = %+v, whole write = %+v", c.name, got, whole)
		}
	}
}

// checkAgainstReference requires that a stream the reference parser finds
// an ERR packet or channel 3 frame in is never storable, that a storable
// stream is well-formed for the mode, and that a body cut short is never
// storable.
func checkAgainstReference(t *testing.T, mode Mode, body []byte) {
	t.Helper()
	ref := refScan(mode, body)
	got := scanVerdicts(mode, body, nil)
	for name, v := range map[string]Verdict{"clean EOF": got.clean, "truncated": got.truncated} {
		if v.Storable != (v.Reason == "") {
			t.Fatalf("%s: inconsistent verdict %+v", name, v)
		}
		if v.Storable && (ref.hasErr || ref.hasChan3) {
			t.Fatalf("%s: storable, but the reference parser found hasErr=%v hasChan3=%v in %q",
				name, ref.hasErr, ref.hasChan3, body)
		}
	}
	if got.truncated.Storable {
		t.Fatalf("truncated verdict is storable for %q", body)
	}
	if got.clean.Storable && !ref.wellFormed {
		t.Fatalf("storable, but the reference parser finds %q malformed for mode %d", body, mode)
	}
}
