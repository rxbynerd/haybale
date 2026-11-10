package pktline

// Mode selects the response grammar a Scanner checks.
type Mode uint8

const (
	// ModeAdvertisement is a GET info/refs response: an optional
	// "# service=git-upload-pack" line and flush, then at least one data
	// packet (v0 ref lines or v2 capability lines), then a flush.
	ModeAdvertisement Mode = iota + 1
	// ModeV2Result is a protocol v2 command result such as ls-refs: data
	// packets, possibly none, then a flush.
	ModeV2Result
	// ModeV2Fetch is a protocol v2 fetch result for a request that sent
	// done: optional shallow-info and wanted-refs sections, each closed by
	// a delim, then a packfile section of sideband frames and a flush.
	ModeV2Fetch
	// ModeV0UploadPack is a protocol v0 upload-pack result for a request
	// that sent done with side-band: an optional shallow list closed by a
	// flush, ACK and NAK lines, then sideband frames and a flush.
	ModeV0UploadPack
)

// Verdict reasons. Reason is empty exactly when Storable is true.
const (
	ReasonErrorPacket       = "error_packet"
	ReasonSidebandError     = "sideband_error"
	ReasonFraming           = "framing"
	ReasonTruncated         = "truncated"
	ReasonUnexpectedSection = "unexpected_section"
)

// Verdict is the result of a Scanner.
type Verdict struct {
	Storable bool
	Reason   string
}

// captureSize bounds how much of each payload a Scanner keeps. It covers
// the longest line the grammars compare in full, the service line.
const captureSize = 32

type scanState uint8

const (
	stAdvStart scanState = iota
	stAdvServiceFlush
	stAdvBody
	stResultBody
	stFetchSection
	stFetchShallowInfo
	stFetchWantedRefs
	stFetchPackfile
	stV0Start
	stV0Shallow
	stV0AfterShallow
	stV0Acks
	stV0Pack
	stDone
)

// Fetch result sections in the order protocol v2 requires them.
const (
	sectionNone = iota
	sectionShallowInfo
	sectionWantedRefs
)

// Scanner is a streaming storability check over a response body. It is
// an io.Writer that never returns an error, never delays or alters the
// bytes, and retains at most captureSize bytes of the current packet; it
// tracks state across writes split at any byte offset. Lengths are skip
// counts, and nothing is allocated from a length. Inside a sideband
// stream only a frame's first byte (its channel) is examined.
//
// Any packet sequence the mode's grammar does not describe makes the
// stream not storable, and the first failure is the one reported.
type Scanner struct {
	state   scanState
	reason  string
	section int
	lines   int

	prefix  [4]byte
	prefixN int

	inPayload bool
	remaining int
	size      int
	capture   [captureSize]byte
	captureN  int
	captureAt int
}

// NewScanner returns a Scanner for mode. A Scanner for an unknown mode
// never reports a stream storable.
func NewScanner(mode Mode) *Scanner {
	s := &Scanner{}
	switch mode {
	case ModeAdvertisement:
		s.state = stAdvStart
	case ModeV2Result:
		s.state = stResultBody
	case ModeV2Fetch:
		s.state = stFetchSection
	case ModeV0UploadPack:
		s.state = stV0Start
	default:
		s.reason = ReasonUnexpectedSection
	}
	return s
}

// Write consumes p and always returns len(p), nil.
func (s *Scanner) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && s.reason == "" {
		if s.state == stDone {
			s.fail(ReasonFraming)
			break
		}
		if !s.inPayload {
			k := copy(s.prefix[s.prefixN:], p)
			s.prefixN += k
			p = p[k:]
			if s.prefixN == len(s.prefix) {
				s.prefixN = 0
				s.startPacket()
			}
			continue
		}
		k := min(s.remaining, len(p))
		if s.captureN < s.captureAt {
			s.captureN += copy(s.capture[s.captureN:s.captureAt], p[:k])
			if s.captureN > 0 && s.isFrame() {
				s.captureAt = 1
			}
		}
		s.remaining -= k
		p = p[k:]
		if s.remaining == 0 {
			s.inPayload = false
			s.dataPacket()
		}
	}
	return n, nil
}

// Verdict reports whether the stream written so far is storable.
// cleanEOF reports whether the body ended without a transport error and
// at its declared length; without it the stream is always truncated.
func (s *Scanner) Verdict(cleanEOF bool) Verdict {
	switch {
	case s.reason != "":
		return Verdict{Reason: s.reason}
	case !cleanEOF || s.state != stDone:
		return Verdict{Reason: ReasonTruncated}
	default:
		return Verdict{Storable: true}
	}
}

func (s *Scanner) fail(reason string) {
	if s.reason == "" {
		s.reason = reason
	}
}

func (s *Scanner) startPacket() {
	kind, size, ok := decodeLength(s.prefix[:])
	if !ok {
		s.fail(ReasonFraming)
		return
	}
	if kind != Data {
		s.specialPacket(kind)
		return
	}
	s.size = size
	s.captureN = 0
	s.captureAt = min(size, captureSize)
	if size == 0 {
		s.dataPacket()
		return
	}
	s.inPayload = true
	s.remaining = size
}

// isFrame reports whether the current packet is a sideband frame: one in
// a state where frames may appear whose first byte is a channel number.
// Such a packet's capture stops after that byte.
func (s *Scanner) isFrame() bool {
	switch s.state {
	case stFetchPackfile, stV0Acks, stV0Pack:
		return s.capture[0] <= 3
	default:
		return false
	}
}

// captured returns the retained bytes of the current packet's payload.
func (s *Scanner) captured() []byte {
	return s.capture[:s.captureN]
}

// isLine reports whether the current payload is exactly text, with or
// without a trailing newline.
func (s *Scanner) isLine(text string) bool {
	c := s.captured()
	switch s.size {
	case len(text):
		return string(c) == text
	case len(text) + 1:
		return string(c) == text+"\n"
	default:
		return false
	}
}

// hasPrefix reports whether the current payload begins with text, which
// must be no longer than captureSize.
func (s *Scanner) hasPrefix(text string) bool {
	c := s.captured()
	return len(c) >= len(text) && string(c[:len(text)]) == text
}

func (s *Scanner) specialPacket(kind Kind) {
	switch {
	case kind == Flush && s.state == stAdvServiceFlush:
		s.state = stAdvBody
	case kind == Flush && s.state == stAdvBody && s.lines > 0:
		s.state = stDone
	case kind == Flush && s.state == stResultBody:
		s.state = stDone
	case kind == Delim && (s.state == stFetchShallowInfo || s.state == stFetchWantedRefs):
		s.state = stFetchSection
	case kind == Flush && s.state == stFetchPackfile:
		s.state = stDone
	case kind == Flush && (s.state == stV0Start || s.state == stV0Shallow):
		s.state = stV0AfterShallow
	case kind == Flush && s.state == stV0Pack:
		s.state = stDone
	default:
		s.fail(ReasonUnexpectedSection)
	}
}

func (s *Scanner) dataPacket() {
	if s.size == 0 {
		s.fail(ReasonFraming)
		return
	}
	if s.isFrame() {
		s.frame()
		return
	}
	if s.hasPrefix("ERR ") {
		s.fail(ReasonErrorPacket)
		return
	}
	switch s.state {
	case stAdvStart:
		switch {
		case s.isLine("# service=git-upload-pack"):
			s.state = stAdvServiceFlush
		case s.hasPrefix("#"):
			s.fail(ReasonUnexpectedSection)
		default:
			s.state = stAdvBody
			s.lines++
		}
	case stAdvBody:
		s.lines++
	case stResultBody, stFetchShallowInfo, stFetchWantedRefs:
	case stFetchSection:
		switch {
		case s.isLine("shallow-info") && s.section < sectionShallowInfo:
			s.state, s.section = stFetchShallowInfo, sectionShallowInfo
		case s.isLine("wanted-refs") && s.section < sectionWantedRefs:
			s.state, s.section = stFetchWantedRefs, sectionWantedRefs
		case s.isLine("packfile"):
			s.state = stFetchPackfile
		default:
			s.fail(ReasonUnexpectedSection)
		}
	case stV0Start, stV0Shallow:
		switch {
		case s.hasPrefix("shallow ") || s.hasPrefix("unshallow "):
			s.state = stV0Shallow
		case s.state == stV0Start && s.isAck():
			s.state = stV0Acks
		default:
			s.fail(ReasonUnexpectedSection)
		}
	case stV0AfterShallow, stV0Acks:
		if !s.isAck() {
			s.fail(ReasonUnexpectedSection)
			return
		}
		s.state = stV0Acks
	case stFetchPackfile, stV0Pack:
		s.fail(ReasonFraming)
	default:
		s.fail(ReasonUnexpectedSection)
	}
}

func (s *Scanner) isAck() bool {
	return s.isLine("NAK") || s.hasPrefix("ACK ")
}

// frame checks one sideband frame's channel: 1 is pack data, 2 is
// progress, 3 is a fatal error, and anything else is invalid.
func (s *Scanner) frame() {
	switch s.capture[0] {
	case 1, 2:
		if s.state == stV0Acks {
			s.state = stV0Pack
		}
	case 3:
		s.fail(ReasonSidebandError)
	default:
		s.fail(ReasonFraming)
	}
}
