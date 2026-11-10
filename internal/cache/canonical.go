package cache

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/rxbynerd/haybale/internal/pktline"
)

// v0Capabilities are the protocol v0 client capabilities that carry no
// value and may appear on the first want line.
var v0Capabilities = map[string]bool{
	"multi_ack":          true,
	"multi_ack_detailed": true,
	"no-done":            true,
	"side-band":          true,
	"side-band-64k":      true,
	"thin-pack":          true,
	"no-progress":        true,
	"include-tag":        true,
	"ofs-delta":          true,
	"shallow":            true,
	"deepen-since":       true,
	"deepen-not":         true,
	"deepen-relative":    true,
	"filter":             true,
}

// canonicalize parses a decoded upload-pack request body strictly and
// returns its canonical form: the same packets in the same order,
// duplicates included, with the agent= and session-id= capabilities
// removed. v2 reports whether the body is protocol v2 shaped.
func canonicalize(body []byte) (canonical []byte, class Class, v2 bool, reason string) {
	p := &bodyParser{rd: pktline.NewReader(bytes.NewReader(body), int64(len(body)))}
	first, eof, reason := p.next()
	switch {
	case reason != "":
		return nil, "", false, reason
	case eof || first.Kind != pktline.Data:
		return nil, "", false, bypassNotAReadShape
	}
	text := chomp(first.Data)
	switch {
	case strings.HasPrefix(text, "command="):
		class, reason = p.v2(first, strings.TrimPrefix(text, "command="))
		v2 = true
	case strings.HasPrefix(text, "want "):
		class, reason = classFetch, p.v0(first)
	default:
		return nil, "", false, bypassNotAReadShape
	}
	if reason != "" {
		return nil, "", false, reason
	}
	return p.out, class, v2, ""
}

type bodyParser struct {
	rd  *pktline.Reader
	out []byte
}

// next returns the next packet, or eof at a clean end of the body.
// Packets no upload-pack request contains are framing errors.
func (p *bodyParser) next() (pkt pktline.Packet, eof bool, reason string) {
	pkt, err := p.rd.Next()
	switch {
	case errors.Is(err, io.EOF):
		return pkt, true, ""
	case err != nil:
		return pkt, false, bypassFraming
	case pkt.Kind == pktline.ResponseEnd, pkt.Kind == pktline.Data && len(pkt.Data) == 0:
		return pkt, false, bypassFraming
	}
	return pkt, false, ""
}

func (p *bodyParser) emit(pkt pktline.Packet) string {
	out, err := pktline.AppendPacket(p.out, pkt)
	if err != nil {
		return bypassFraming
	}
	p.out = out
	return ""
}

// end requires the body to end exactly here.
func (p *bodyParser) end() string {
	if _, eof, _ := p.next(); !eof {
		return bypassTrailingBytes
	}
	return ""
}

// v2 parses a protocol v2 request: the command line, capability lines,
// an optional delim and command arguments, and a terminating flush.
func (p *bodyParser) v2(first pktline.Packet, command string) (Class, string) {
	var class Class
	switch command {
	case "ls-refs":
		class = classLsRefs
	case "fetch":
		class = classFetch
	default:
		return "", bypassUnknownCommand
	}
	if reason := p.emit(first); reason != "" {
		return "", reason
	}

	seen := map[string]bool{}
	hasArgs := false
capabilities:
	for {
		pkt, eof, reason := p.next()
		switch {
		case reason != "":
			return "", reason
		case eof:
			return "", bypassFraming
		case pkt.Kind == pktline.Delim:
			hasArgs = true
			if reason := p.emit(pkt); reason != "" {
				return "", reason
			}
			break capabilities
		case pkt.Kind == pktline.Flush:
			if reason := p.emit(pkt); reason != "" {
				return "", reason
			}
			break capabilities
		}
		name, value, hasValue := strings.Cut(chomp(pkt.Data), "=")
		switch {
		case !hasValue:
			return "", bypassUnknownCapability
		case name == "command":
			return "", bypassMultipleCommands
		case seen[name]:
			return "", bypassDuplicateCapability
		}
		seen[name] = true
		switch {
		case name == "agent", name == "session-id":
		case name == "object-format" && validObjectFormat(value):
			if reason := p.emit(pkt); reason != "" {
				return "", reason
			}
		default:
			return "", bypassUnknownCapability
		}
	}

	var args fetchArgs
	for hasArgs {
		pkt, eof, reason := p.next()
		switch {
		case reason != "":
			return "", reason
		case eof, pkt.Kind == pktline.Delim:
			return "", bypassFraming
		}
		if reason := p.emit(pkt); reason != "" {
			return "", reason
		}
		if pkt.Kind == pktline.Flush {
			break
		}
		line := chomp(pkt.Data)
		if class == classLsRefs {
			reason = lsRefsArg(line)
		} else {
			reason = args.v2(line)
		}
		if reason != "" {
			return "", reason
		}
	}

	if reason := p.end(); reason != "" {
		return "", reason
	}
	if class == classFetch {
		return class, args.complete()
	}
	return class, ""
}

// v0 parses a protocol v0 upload-pack request: want lines (the first
// carrying the capability list), shallow and deepen lines, a flush, and
// done.
func (p *bodyParser) v0(first pktline.Packet) string {
	want, reason := v0FirstWant(first.Data)
	if reason != "" {
		return reason
	}
	if reason := p.emit(pktline.Packet{Kind: pktline.Data, Data: want}); reason != "" {
		return reason
	}

	args := fetchArgs{wants: 1}
	for {
		pkt, eof, reason := p.next()
		switch {
		case reason != "":
			return reason
		case eof, pkt.Kind == pktline.Delim:
			return bypassFraming
		}
		if reason := p.emit(pkt); reason != "" {
			return reason
		}
		if pkt.Kind == pktline.Flush {
			break
		}
		if reason := args.common(chomp(pkt.Data)); reason != "" {
			return reason
		}
	}

	pkt, eof, reason := p.next()
	switch {
	case reason != "":
		return reason
	case eof:
		return bypassMissingDone
	case pkt.Kind != pktline.Data:
		return bypassFraming
	}
	line := chomp(pkt.Data)
	switch {
	case line == "done":
	case strings.HasPrefix(line, "have "):
		return bypassHasHave
	default:
		return bypassUnknownArgument
	}
	if reason := p.emit(pkt); reason != "" {
		return reason
	}
	return p.end()
}

// v0FirstWant validates the first v0 want line and returns it with the
// agent= and session-id= capabilities removed. The capability list must
// request a sideband, since the response scanner only recognises a
// multiplexed pack stream.
func v0FirstWant(data []byte) ([]byte, string) {
	text := chomp(data)
	newline := ""
	if len(text) < len(data) {
		newline = "\n"
	}
	oid, caps, hasCaps := strings.Cut(strings.TrimPrefix(text, "want "), " ")
	switch {
	case !isOID(oid):
		return nil, bypassUnknownArgument
	case !hasCaps:
		return nil, bypassBadSideband
	}

	seen := map[string]bool{}
	kept := make([]string, 0, strings.Count(caps, " ")+1)
	sideband := false
	for c := range strings.SplitSeq(caps, " ") {
		name, value, hasValue := strings.Cut(c, "=")
		if seen[name] {
			return nil, bypassDuplicateCapability
		}
		seen[name] = true
		switch {
		case !hasValue && v0Capabilities[name]:
			kept = append(kept, c)
			sideband = sideband || name == "side-band" || name == "side-band-64k"
		case hasValue && (name == "agent" || name == "session-id"):
		case hasValue && name == "object-format" && validObjectFormat(value):
			kept = append(kept, c)
		default:
			return nil, bypassUnknownCapability
		}
	}
	if !sideband {
		return nil, bypassBadSideband
	}
	return []byte("want " + oid + " " + strings.Join(kept, " ") + newline), ""
}

// fetchArgs tracks the fetch arguments that decide whether a request is
// complete and content-addressed.
type fetchArgs struct {
	wants   int
	done    bool
	filters int
}

// v2 checks one protocol v2 fetch argument against the allowlist.
func (a *fetchArgs) v2(line string) string {
	switch line {
	case "done":
		a.done = true
		return ""
	case "thin-pack", "no-progress", "include-tag", "ofs-delta", "deepen-relative":
		return ""
	}
	return a.common(line)
}

// common checks the arguments shared by both protocol versions; in v0
// these are the only lines allowed between the first want and the flush.
func (a *fetchArgs) common(line string) string {
	keyword, value, hasValue := strings.Cut(line, " ")
	switch {
	case keyword == "have":
		return bypassHasHave
	case keyword == "filter":
		a.filters++
		if a.filters > 1 || !hasValue || !validFilter(value) {
			return bypassBadFilter
		}
		return ""
	case !hasValue:
		return bypassUnknownArgument
	}
	switch {
	case keyword == "want" && isOID(value):
		a.wants++
	case keyword == "shallow" && isOID(value):
	case keyword == "deepen" && isDecimal(value) && value[0] != '0':
	case keyword == "deepen-since" && isDecimal(value):
	default:
		return bypassUnknownArgument
	}
	return ""
}

// complete reports whether the arguments form a cacheable fetch.
func (a *fetchArgs) complete() string {
	switch {
	case a.wants == 0:
		return bypassNoWant
	case !a.done:
		return bypassMissingDone
	}
	return ""
}

// lsRefsArg checks one ls-refs argument against the allowlist.
func lsRefsArg(line string) string {
	switch {
	case line == "symrefs", line == "peel", line == "unborn":
	case strings.HasPrefix(line, "ref-prefix ") && len(line) > len("ref-prefix "):
	default:
		return bypassUnknownArgument
	}
	return ""
}

// validFilter reports whether spec is an allowlisted partial-clone
// filter.
func validFilter(spec string) bool {
	switch {
	case spec == "blob:none":
		return true
	case strings.HasPrefix(spec, "blob:limit="):
		n := strings.TrimPrefix(spec, "blob:limit=")
		if strings.HasSuffix(n, "k") || strings.HasSuffix(n, "m") || strings.HasSuffix(n, "g") {
			n = n[:len(n)-1]
		}
		return isDecimal(n)
	case strings.HasPrefix(spec, "tree:"):
		return isDecimal(strings.TrimPrefix(spec, "tree:"))
	case strings.HasPrefix(spec, "object:type="):
		switch strings.TrimPrefix(spec, "object:type=") {
		case "blob", "tree", "commit", "tag":
			return true
		}
		return false
	case strings.HasPrefix(spec, "sparse:oid="):
		return isOID(strings.TrimPrefix(spec, "sparse:oid="))
	default:
		return false
	}
}

func validObjectFormat(name string) bool {
	return name == "sha1" || name == "sha256"
}

// isOID reports whether s is a full lowercase hex SHA-1 or SHA-256
// object id.
func isOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isDecimal reports whether s is a non-empty run of at most 20 decimal
// digits.
func isDecimal(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// chomp returns b as a string without one trailing newline.
func chomp(b []byte) string {
	return string(bytes.TrimSuffix(b, []byte("\n")))
}
