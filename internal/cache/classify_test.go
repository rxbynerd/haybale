package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/pktline"
)

var testRepo = gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}

const (
	uploadPackURL = "/github.com/acme/widgets.git/git-upload-pack"
	infoRefsURL   = "/github.com/acme/widgets.git/info/refs?service=git-upload-pack"
	testMaxBody   = 1 << 20

	oidA   = "1f1e5c8e3a0b9d2c4e6f8a0b1c2d3e4f5a6b7c8d"
	oidB   = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
	oid256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	agent  = "agent=git/2.54.0-Darwin\n"
	v0Caps = "multi_ack_detailed no-done side-band-64k thin-pack include-tag ofs-delta deepen-since deepen-not"
)

// raw marks a body part appended verbatim instead of as a data packet.
type raw string

// pkts encodes parts: a string becomes a data packet, a pktline.Kind
// that special packet, and a raw is appended as is.
func pkts(t testing.TB, parts ...any) []byte {
	t.Helper()
	var out []byte
	for _, part := range parts {
		var err error
		switch v := part.(type) {
		case string:
			out, err = pktline.AppendData(out, []byte(v))
		case pktline.Kind:
			out, err = pktline.AppendPacket(out, pktline.Packet{Kind: v})
		case raw:
			out = append(out, v...)
		default:
			t.Fatalf("pkts: unsupported part %T", part)
		}
		if err != nil {
			t.Fatalf("pkts: %v", err)
		}
	}
	return out
}

func gzipped(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	if _, err := z.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := z.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// post builds an upload-pack POST carrying body, with headers given as
// name, value pairs added after the standard Content-Type.
func post(body []byte, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, uploadPackURL, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func postV2(body []byte, headers ...string) *http.Request {
	return post(body, append([]string{"Git-Protocol", "version=2"}, headers...)...)
}

func get(headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, infoRefsURL, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func lsRefsBody(t testing.TB, caps ...string) []byte {
	parts := []any{"command=ls-refs\n"}
	for _, c := range caps {
		parts = append(parts, c)
	}
	parts = append(parts, "object-format=sha1\n", pktline.Delim,
		"peel\n", "symrefs\n", "unborn\n",
		"ref-prefix HEAD\n", "ref-prefix refs/heads/\n", "ref-prefix refs/tags/\n",
		pktline.Flush)
	return pkts(t, parts...)
}

// fetchBody builds a v2 fetch request with an agent capability and args.
func fetchBody(t testing.TB, args ...any) []byte {
	parts := append([]any{"command=fetch\n", agent, "object-format=sha1\n", pktline.Delim}, args...)
	return pkts(t, append(parts, pktline.Flush)...)
}

func cloneFetchBody(t testing.TB) []byte {
	return fetchBody(t, "thin-pack\n", "no-progress\n", "ofs-delta\n", "want "+oidA+"\n", "want "+oidB+"\n", "done\n")
}

// largeFetchBody returns a valid v2 fetch body longer than n bytes.
func largeFetchBody(t testing.TB, n int) []byte {
	line := "want " + oidA + "\n"
	var args []any
	for size := 0; size <= n; size += len(line) + 4 {
		args = append(args, line)
	}
	return fetchBody(t, append(args, "done\n")...)
}

func v0Body(t testing.TB, caps string) []byte {
	return pkts(t, "want "+oidA+" "+caps+"\n", pktline.Flush, "done\n")
}

func wantKeyHash(class Class, protocol string, body []byte) [32]byte {
	return sha256.Sum256(append([]byte(string(class)+"\n"+protocol+"\n"), body...))
}

func classify(t *testing.T, r *http.Request) (Request, bool, string) {
	t.Helper()
	req, bypass, reason, err := Classify(r, testRepo, testMaxBody)
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if bypass != (reason != "") {
		t.Fatalf("Classify() bypass = %v with reason %q", bypass, reason)
	}
	return req, bypass, reason
}

func TestClassifyCapturedRequests(t *testing.T) {
	tests := []struct {
		name      string
		r         *http.Request
		class     Class
		protocol  string
		canonical []byte
	}{
		{
			name:     "v2 ls-refs",
			r:        postV2(lsRefsBody(t, agent)),
			class:    ClassLsRefs,
			protocol: "version=2",
			canonical: pkts(t, "command=ls-refs\n", "object-format=sha1\n", pktline.Delim,
				"peel\n", "symrefs\n", "unborn\n",
				"ref-prefix HEAD\n", "ref-prefix refs/heads/\n", "ref-prefix refs/tags/\n",
				pktline.Flush),
		},
		{
			name:     "v2 fetch",
			r:        postV2(cloneFetchBody(t)),
			class:    ClassFetch,
			protocol: "version=2",
			canonical: pkts(t, "command=fetch\n", "object-format=sha1\n", pktline.Delim,
				"thin-pack\n", "no-progress\n", "ofs-delta\n", "want "+oidA+"\n", "want "+oidB+"\n", "done\n",
				pktline.Flush),
		},
		{
			name: "v2 fetch with depth 1",
			r: postV2(fetchBody(t, "thin-pack\n", "no-progress\n", "include-tag\n", "ofs-delta\n",
				"deepen 1\n", "want "+oidA+"\n", "want "+oidB+"\n", "done\n")),
			class:    ClassFetch,
			protocol: "version=2",
			canonical: pkts(t, "command=fetch\n", "object-format=sha1\n", pktline.Delim,
				"thin-pack\n", "no-progress\n", "include-tag\n", "ofs-delta\n",
				"deepen 1\n", "want "+oidA+"\n", "want "+oidB+"\n", "done\n",
				pktline.Flush),
		},
		{
			name:      "v0 fetch",
			r:         post(v0Body(t, v0Caps+" agent=git/2.54.0-Darwin")),
			class:     ClassFetch,
			canonical: pkts(t, "want "+oidA+" "+v0Caps+"\n", pktline.Flush, "done\n"),
		},
		{
			name:      "v0 fetch with explicit version 0",
			r:         post(v0Body(t, v0Caps+" agent=git/2.54.0-Darwin"), "Git-Protocol", "version=0"),
			class:     ClassFetch,
			protocol:  "version=0",
			canonical: pkts(t, "want "+oidA+" "+v0Caps+"\n", pktline.Flush, "done\n"),
		},
		{
			name:      "v0 fetch with depth",
			r:         post(pkts(t, "want "+oidA+" side-band-64k agent=git/2.54.0\n", "want "+oidB+"\n", "shallow "+oidB+"\n", "deepen 1\n", pktline.Flush, "done\n")),
			class:     ClassFetch,
			canonical: pkts(t, "want "+oidA+" side-band-64k\n", "want "+oidB+"\n", "shallow "+oidB+"\n", "deepen 1\n", pktline.Flush, "done\n"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, bypass, reason := classify(t, tt.r)
			if bypass {
				t.Fatalf("Classify() bypassed with reason %q", reason)
			}
			if req.Class != tt.class || req.Protocol != tt.protocol || req.Repo != testRepo {
				t.Errorf("Classify() class, protocol, repo = %q, %q, %v; want %q, %q, %v",
					req.Class, req.Protocol, req.Repo, tt.class, tt.protocol, testRepo)
			}
			if !bytes.Equal(req.Body, tt.canonical) {
				t.Errorf("canonical body = %q, want %q", req.Body, tt.canonical)
			}
			if req.Method != http.MethodPost || req.Endpoint != "git-upload-pack" ||
				req.ContentType != "application/x-git-upload-pack-request" ||
				req.Accept != "application/x-git-upload-pack-result" {
				t.Errorf("Classify() upstream request shape = %q %q %q %q",
					req.Method, req.Endpoint, req.ContentType, req.Accept)
			}
			if want := wantKeyHash(tt.class, tt.protocol, tt.canonical); req.KeyHash != want {
				t.Errorf("KeyHash = %x, want %x", req.KeyHash, want)
			}
		})
	}
}

func TestClassifyAdvertisement(t *testing.T) {
	v0, bypass, reason := classify(t, get())
	if bypass {
		t.Fatalf("v0 advertisement bypassed with reason %q", reason)
	}
	v2, bypass, reason := classify(t, get("Git-Protocol", "version=2"))
	if bypass {
		t.Fatalf("v2 advertisement bypassed with reason %q", reason)
	}
	for _, req := range []Request{v0, v2} {
		if req.Class != ClassAdvertisement || req.Method != http.MethodGet ||
			req.Endpoint != "info/refs?service=git-upload-pack" || req.Body != nil ||
			req.ContentType != "" || req.Accept != "*/*" {
			t.Errorf("advertisement request = %+v", req)
		}
		if want := wantKeyHash(ClassAdvertisement, req.Protocol, nil); req.KeyHash != want {
			t.Errorf("KeyHash = %x, want %x", req.KeyHash, want)
		}
	}
	if v0.Protocol != "" || v2.Protocol != "version=2" {
		t.Errorf("protocols = %q and %q", v0.Protocol, v2.Protocol)
	}
	if v0.KeyHash == v2.KeyHash {
		t.Error("v0 and v2 advertisements share a key")
	}
}

func TestClassifyAcceptsAllowlistedFetchArguments(t *testing.T) {
	tests := []struct {
		name string
		args []any
	}{
		{"deepen-since", []any{"deepen-since 1700000000\n"}},
		{"deepen-relative with shallow", []any{"shallow " + oidB + "\n", "deepen-relative\n", "deepen 2\n"}},
		{"filter blob:none", []any{"filter blob:none\n"}},
		{"filter blob:limit bytes", []any{"filter blob:limit=1024\n"}},
		{"filter blob:limit with unit", []any{"filter blob:limit=1k\n"}},
		{"filter tree depth", []any{"filter tree:0\n"}},
		{"filter object type", []any{"filter object:type=commit\n"}},
		{"filter sparse oid", []any{"filter sparse:oid=" + oidB + "\n"}},
		{"duplicate wants", []any{"want " + oidB + "\n"}},
		{"line without newline", []any{"thin-pack"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]any{"want " + oidA + "\n"}, tt.args...)
			args = append(args, "done\n")
			_, bypass, reason := classify(t, postV2(fetchBody(t, args...)))
			if bypass {
				t.Fatalf("Classify() bypassed with reason %q", reason)
			}
		})
	}

	t.Run("sha256 object format", func(t *testing.T) {
		body := pkts(t, "command=fetch\n", "object-format=sha256\n", pktline.Delim, "want "+oid256+"\n", "done\n", pktline.Flush)
		if _, bypass, reason := classify(t, postV2(body)); bypass {
			t.Fatalf("Classify() bypassed with reason %q", reason)
		}
	})
	t.Run("ls-refs without arguments", func(t *testing.T) {
		body := pkts(t, "command=ls-refs\n", agent, pktline.Flush)
		req, bypass, reason := classify(t, postV2(body))
		if bypass {
			t.Fatalf("Classify() bypassed with reason %q", reason)
		}
		if want := pkts(t, "command=ls-refs\n", pktline.Flush); !bytes.Equal(req.Body, want) {
			t.Errorf("canonical body = %q, want %q", req.Body, want)
		}
	})
}

// allBypassReasons is the closed set Classify reports from.
var allBypassReasons = []string{
	BypassTooLarge, BypassContentEncoding, BypassDecodeError, BypassFraming,
	BypassTrailingBytes, BypassMultipleCommands, BypassDuplicateCapability,
	BypassUnknownCapability, BypassUnknownArgument, BypassHasHave,
	BypassMissingDone, BypassNoWant, BypassMissingProtocol,
	BypassDuplicateProtocol, BypassBadProtocol, BypassBadFilter,
	BypassBadSideband, BypassUnknownCommand, BypassNotAReadShape,
}

func TestClassifyBypassReasons(t *testing.T) {
	want := func(args ...any) []byte {
		return fetchBody(t, append([]any{"want " + oidA + "\n"}, append(args, "done\n")...)...)
	}
	getWithBody := httptest.NewRequest(http.MethodGet, infoRefsURL, strings.NewReader("x"))
	getWithQuery := httptest.NewRequest(http.MethodGet, infoRefsURL+"&x=1", nil)
	postWithQuery := postV2(cloneFetchBody(t))
	postWithQuery.URL.RawQuery = "x=1"
	wrongType := postV2(cloneFetchBody(t))
	wrongType.Header.Set("Content-Type", "text/plain")
	bomb := gzipped(t, bytes.Repeat([]byte("0"), testMaxBody+1))
	trailingMember := append(gzipped(t, cloneFetchBody(t)), gzipped(t, []byte("0000"))...)
	truncatedGzip := gzipped(t, cloneFetchBody(t))
	truncatedGzip = truncatedGzip[:len(truncatedGzip)-4]

	tests := []struct {
		name   string
		r      *http.Request
		reason string
	}{
		{"body over the bound", postV2(largeFetchBody(t, testMaxBody)), BypassTooLarge},
		{"decoded body over the bound", postV2(bomb, "Content-Encoding", "gzip"), BypassTooLarge},
		{"brotli body", postV2(cloneFetchBody(t), "Content-Encoding", "br"), BypassContentEncoding},
		{"two content encodings", postV2(cloneFetchBody(t), "Content-Encoding", "gzip", "Content-Encoding", "gzip"), BypassContentEncoding},
		{"gzip header invalid", postV2(cloneFetchBody(t), "Content-Encoding", "gzip"), BypassDecodeError},
		{"gzip member truncated", postV2(truncatedGzip, "Content-Encoding", "gzip"), BypassDecodeError},
		{"bytes after gzip member", postV2(trailingMember, "Content-Encoding", "gzip"), BypassDecodeError},
		{"invalid length", postV2([]byte("zzzz")), BypassFraming},
		{"missing terminating flush", postV2(cloneFetchBody(t)[:len(cloneFetchBody(t))-4]), BypassFraming},
		{"truncated packet", postV2(append(pkts(t, "command=fetch\n"), "0010want"...)), BypassFraming},
		{"empty data packet", postV2(want(raw("0004"))), BypassFraming},
		{"response-end packet", postV2(pkts(t, "command=fetch\n", pktline.ResponseEnd)), BypassFraming},
		{"second delim", postV2(want(pktline.Delim)), BypassFraming},
		{"v0 delim", post(pkts(t, "want "+oidA+" side-band-64k\n", pktline.Delim, pktline.Flush, "done\n")), BypassFraming},
		{"v0 missing flush", post(pkts(t, "want "+oidA+" side-band-64k\n")), BypassFraming},
		{"byte after flush", postV2(append(cloneFetchBody(t), '0')), BypassTrailingBytes},
		{"second request after flush", postV2(append(cloneFetchBody(t), lsRefsBody(t)...)), BypassTrailingBytes},
		{"v0 bytes after done", post(append(v0Body(t, "side-band-64k"), "0000"...)), BypassTrailingBytes},
		{"two commands", postV2(pkts(t, "command=fetch\n", "command=ls-refs\n", pktline.Delim, "done\n", pktline.Flush)), BypassMultipleCommands},
		{"two agents", postV2(pkts(t, "command=fetch\n", agent, agent, pktline.Delim, "want "+oidA+"\n", "done\n", pktline.Flush)), BypassDuplicateCapability},
		{"two session ids", postV2(pkts(t, "command=ls-refs\n", "session-id=a\n", "session-id=b\n", pktline.Flush)), BypassDuplicateCapability},
		{"v0 repeated capability", post(v0Body(t, "side-band-64k thin-pack side-band-64k")), BypassDuplicateCapability},
		{"v0 two agents", post(v0Body(t, "side-band-64k agent=a agent=b")), BypassDuplicateCapability},
		{"server-option capability", postV2(pkts(t, "command=fetch\n", "server-option=x\n", pktline.Delim, "want "+oidA+"\n", "done\n", pktline.Flush)), BypassUnknownCapability},
		{"capability without value", postV2(pkts(t, "command=fetch\n", "thin-pack\n", pktline.Delim, "want "+oidA+"\n", "done\n", pktline.Flush)), BypassUnknownCapability},
		{"unknown object format", postV2(pkts(t, "command=fetch\n", "object-format=md5\n", pktline.Delim, "want "+oidA+"\n", "done\n", pktline.Flush)), BypassUnknownCapability},
		{"v0 unknown capability", post(v0Body(t, "side-band-64k report-status")), BypassUnknownCapability},
		{"v0 empty capability", post(v0Body(t, "side-band-64k  thin-pack")), BypassUnknownCapability},
		{"want-ref", postV2(want("want-ref refs/heads/main\n")), BypassUnknownArgument},
		{"deepen-not", postV2(want("deepen-not refs/heads/main\n")), BypassUnknownArgument},
		{"packfile-uris", postV2(want("packfile-uris https\n")), BypassUnknownArgument},
		{"sideband-all", postV2(want("sideband-all\n")), BypassUnknownArgument},
		{"wait-for-done", postV2(want("wait-for-done\n")), BypassUnknownArgument},
		{"short want oid", postV2(want("want abc\n")), BypassUnknownArgument},
		{"uppercase want oid", postV2(want("want " + strings.ToUpper(oidB) + "\n")), BypassUnknownArgument},
		{"deepen 0", postV2(want("deepen 0\n")), BypassUnknownArgument},
		{"unknown ls-refs argument", postV2(pkts(t, "command=ls-refs\n", pktline.Delim, "peel\n", "all-the-refs\n", pktline.Flush)), BypassUnknownArgument},
		{"empty ref-prefix", postV2(pkts(t, "command=ls-refs\n", pktline.Delim, "ref-prefix \n", pktline.Flush)), BypassUnknownArgument},
		{"v0 bad first oid", post(pkts(t, "want xyz side-band-64k\n", pktline.Flush, "done\n")), BypassUnknownArgument},
		{"v0 capability on later want", post(pkts(t, "want "+oidA+" side-band-64k\n", "want "+oidB+" thin-pack\n", pktline.Flush, "done\n")), BypassUnknownArgument},
		{"v0 done before flush", post(pkts(t, "want "+oidA+" side-band-64k\n", "done\n", pktline.Flush, "done\n")), BypassUnknownArgument},
		{"v0 deepen-not", post(pkts(t, "want "+oidA+" side-band-64k\n", "deepen-not main\n", pktline.Flush, "done\n")), BypassUnknownArgument},
		{"v0 unknown line after flush", post(pkts(t, "want "+oidA+" side-band-64k\n", pktline.Flush, "ready\n")), BypassUnknownArgument},
		{"v2 have", postV2(want("have " + oidB + "\n")), BypassHasHave},
		{"v0 have", post(pkts(t, "want "+oidA+" side-band-64k\n", pktline.Flush, "have "+oidB+"\n", "done\n")), BypassHasHave},
		{"v2 without done", postV2(fetchBody(t, "want "+oidA+"\n")), BypassMissingDone},
		{"v0 without done", post(pkts(t, "want "+oidA+" side-band-64k\n", "deepen 1\n", pktline.Flush)), BypassMissingDone},
		{"v2 without want", postV2(fetchBody(t, "thin-pack\n", "done\n")), BypassNoWant},
		{"v2 fetch without arguments", postV2(pkts(t, "command=fetch\n", pktline.Flush)), BypassNoWant},
		{"v2 body without Git-Protocol", post(cloneFetchBody(t)), BypassMissingProtocol},
		{"two Git-Protocol headers", postV2(cloneFetchBody(t), "Git-Protocol", "version=2"), BypassDuplicateProtocol},
		{"two Git-Protocol headers on GET", get("Git-Protocol", "version=2", "Git-Protocol", "version=2"), BypassDuplicateProtocol},
		{"unknown protocol version", post(cloneFetchBody(t), "Git-Protocol", "version=3"), BypassBadProtocol},
		{"empty protocol value", get("Git-Protocol", ""), BypassBadProtocol},
		{"protocol parameter without value", get("Git-Protocol", "version=2:object-format"), BypassBadProtocol},
		{"protocol parameter with space", get("Git-Protocol", "version=2:a=b c"), BypassBadProtocol},
		{"protocol version repeated", get("Git-Protocol", "version=2:version=0"), BypassBadProtocol},
		{"protocol value too long", get("Git-Protocol", "version=2:k="+strings.Repeat("v", 300)), BypassBadProtocol},
		{"v2 body declaring version 1", post(cloneFetchBody(t), "Git-Protocol", "version=1"), BypassBadProtocol},
		{"v0 body declaring version 2", postV2(v0Body(t, "side-band-64k")), BypassBadProtocol},
		{"combine filter", postV2(want("filter combine:blob:none+tree:0\n")), BypassBadFilter},
		{"two filters", postV2(want("filter blob:none\n", "filter tree:0\n")), BypassBadFilter},
		{"uppercase size unit", postV2(want("filter blob:limit=1K\n")), BypassBadFilter},
		{"filter without spec", postV2(want("filter\n")), BypassBadFilter},
		{"sparse path filter", postV2(want("filter sparse:path=/x\n")), BypassBadFilter},
		{"short sparse oid", postV2(want("filter sparse:oid=abc\n")), BypassBadFilter},
		{"unknown object type", postV2(want("filter object:type=any\n")), BypassBadFilter},
		{"v0 without sideband", post(v0Body(t, "thin-pack ofs-delta agent=git/2.54.0")), BypassBadSideband},
		{"v0 without capabilities", post(pkts(t, "want "+oidA+"\n", pktline.Flush, "done\n")), BypassBadSideband},
		{"object-info command", postV2(pkts(t, "command=object-info\n", pktline.Delim, "size\n", pktline.Flush)), BypassUnknownCommand},
		{"bundle-uri command", postV2(pkts(t, "command=bundle-uri\n", pktline.Flush)), BypassUnknownCommand},
		{"GET with body", getWithBody, BypassNotAReadShape},
		{"GET with extra query", getWithQuery, BypassNotAReadShape},
		{"POST with query", postWithQuery, BypassNotAReadShape},
		{"wrong content type", wrongType, BypassNotAReadShape},
		{"empty body", postV2(nil), BypassNotAReadShape},
		{"flush only", postV2(pkts(t, pktline.Flush)), BypassNotAReadShape},
		{"first line not a command or want", postV2(pkts(t, "have "+oidA+"\n", pktline.Flush)), BypassNotAReadShape},
	}

	covered := map[string]bool{}
	for _, tt := range tests {
		covered[tt.reason] = true
		t.Run(tt.name, func(t *testing.T) {
			req, bypass, reason := classify(t, tt.r)
			if !bypass || reason != tt.reason {
				t.Fatalf("Classify() = bypass %v reason %q, want reason %q", bypass, reason, tt.reason)
			}
			if req.Class != "" || req.Body != nil {
				t.Errorf("bypassed Classify() returned a request %+v", req)
			}
		})
	}
	for _, reason := range allBypassReasons {
		if !covered[reason] {
			t.Errorf("no test case for bypass reason %q", reason)
		}
	}
}

func TestClassifyGzipMatchesIdentity(t *testing.T) {
	identity := cloneFetchBody(t)
	plain, bypass, reason := classify(t, postV2(identity))
	if bypass {
		t.Fatalf("identity body bypassed with reason %q", reason)
	}
	for _, encoding := range []string{"gzip", "GZIP", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			body := identity
			if encoding != "identity" {
				body = gzipped(t, identity)
			}
			req, bypass, reason := classify(t, postV2(body, "Content-Encoding", encoding))
			if bypass {
				t.Fatalf("Classify() bypassed with reason %q", reason)
			}
			if req.Class != ClassFetch || req.KeyHash != plain.KeyHash || !bytes.Equal(req.Body, plain.Body) {
				t.Errorf("Classify() = %+v, want the identity twin %+v", req, plain)
			}
		})
	}
}

func TestClassifyIgnoresInformationalCapabilities(t *testing.T) {
	tests := []struct {
		name string
		a, b *http.Request
	}{
		{
			"v2 agent and session-id",
			postV2(fetchBody(t, "want "+oidA+"\n", "done\n")),
			postV2(pkts(t, "command=fetch\n", "agent=git/2.47.1\n", "session-id=abc123\n", "object-format=sha1\n", pktline.Delim, "want "+oidA+"\n", "done\n", pktline.Flush)),
		},
		{
			"v2 capabilities absent",
			postV2(lsRefsBody(t)),
			postV2(lsRefsBody(t, "session-id=xyz\n", agent)),
		},
		{
			"v0 agent and session-id",
			post(v0Body(t, v0Caps+" agent=git/2.54.0-Darwin")),
			post(v0Body(t, "agent=git/2.40.0 session-id=s1 "+v0Caps)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, bypassA, reasonA := classify(t, tt.a)
			b, bypassB, reasonB := classify(t, tt.b)
			if bypassA || bypassB {
				t.Fatalf("Classify() bypassed with reasons %q and %q", reasonA, reasonB)
			}
			if a.KeyHash != b.KeyHash || !bytes.Equal(a.Body, b.Body) {
				t.Errorf("keys differ:\n%q\n%q", a.Body, b.Body)
			}
			if bytes.Contains(a.Body, []byte("agent=")) || bytes.Contains(a.Body, []byte("session-id=")) {
				t.Errorf("canonical body keeps an informational capability: %q", a.Body)
			}
		})
	}
}

func TestClassifyKeyDistinguishesRequests(t *testing.T) {
	key := func(r *http.Request) [32]byte {
		t.Helper()
		req, bypass, reason := classify(t, r)
		if bypass {
			t.Fatalf("Classify() bypassed with reason %q", reason)
		}
		return req.KeyHash
	}
	base := key(postV2(fetchBody(t, "want "+oidA+"\n", "want "+oidB+"\n", "done\n")))
	others := map[string][32]byte{
		// Line order is part of the canonical form: clients built from
		// one image send the same order, and reordering would be a
		// semantic judgement the parser does not make.
		"reordered wants": key(postV2(fetchBody(t, "want "+oidB+"\n", "want "+oidA+"\n", "done\n"))),
		"duplicate want":  key(postV2(fetchBody(t, "want "+oidA+"\n", "want "+oidB+"\n", "want "+oidB+"\n", "done\n"))),
		"added option":    key(postV2(fetchBody(t, "want "+oidA+"\n", "want "+oidB+"\n", "include-tag\n", "done\n"))),
		"protocol param":  key(post(fetchBody(t, "want "+oidA+"\n", "want "+oidB+"\n", "done\n"), "Git-Protocol", "version=2:x=y")),
	}
	for name, k := range others {
		if k == base {
			t.Errorf("%s: shares the key of the base request", name)
		}
	}
}

func TestClassifyRestoresBody(t *testing.T) {
	big := largeFetchBody(t, 2*testMaxBody)
	tests := []struct {
		name     string
		body     []byte
		encoding string
		bypass   bool
	}{
		{"identity bypass", append(cloneFetchBody(t), '0'), "", true},
		{"gzip bypass", gzipped(t, fetchBody(t, "want "+oidA+"\n", "have "+oidB+"\n", "done\n")), "gzip", true},
		{"gzip with trailing bytes", append(gzipped(t, cloneFetchBody(t)), "trailing"...), "gzip", true},
		{"identity over the bound", big, "", true},
		{"gzip over the bound", gzipped(t, big), "gzip", true},
		{"invalid gzip", []byte("not gzip at all"), "gzip", true},
		{"cacheable identity", cloneFetchBody(t), "", false},
		{"cacheable gzip", gzipped(t, cloneFetchBody(t)), "gzip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := postV2(tt.body)
			if tt.encoding != "" {
				r.Header.Set("Content-Encoding", tt.encoding)
			}
			_, bypass, reason := classify(t, r)
			if bypass != tt.bypass {
				t.Fatalf("Classify() bypass = %v (%q), want %v", bypass, reason, tt.bypass)
			}
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading restored body: %v", err)
			}
			if !bytes.Equal(got, tt.body) {
				t.Fatalf("restored body differs from the original (%d bytes, want %d)", len(got), len(tt.body))
			}
			if r.Header.Get("Content-Encoding") != tt.encoding {
				t.Errorf("Content-Encoding = %q, want %q", r.Header.Get("Content-Encoding"), tt.encoding)
			}
			if err := r.Body.Close(); err != nil {
				t.Errorf("closing restored body: %v", err)
			}
		})
	}
}

type failingBody struct{ prefix []byte }

func (f *failingBody) Read(p []byte) (int, error) {
	if len(f.prefix) == 0 {
		return 0, errors.New("connection reset")
	}
	n := copy(p, f.prefix)
	f.prefix = f.prefix[n:]
	return n, nil
}

func TestClassifyErrors(t *testing.T) {
	readErr := postV2(nil)
	readErr.Body = io.NopCloser(&failingBody{prefix: cloneFetchBody(t)[:10]})
	readErr.ContentLength = -1

	tests := []struct {
		name    string
		r       *http.Request
		repo    gitproto.Repo
		maxBody int64
	}{
		{"receive-pack POST", httptest.NewRequest(http.MethodPost, "/github.com/acme/widgets.git/git-receive-pack", nil), testRepo, testMaxBody},
		{"receive-pack advertisement", httptest.NewRequest(http.MethodGet, "/github.com/acme/widgets.git/info/refs?service=git-receive-pack", nil), testRepo, testMaxBody},
		{"not a smart-HTTP request", httptest.NewRequest(http.MethodGet, "/github.com/acme/widgets.git/HEAD", nil), testRepo, testMaxBody},
		{"repo mismatch", postV2(cloneFetchBody(t)), gitproto.Repo{Host: "github.com", Owner: "acme", Name: "gadgets"}, testMaxBody},
		{"non-positive maxBody", postV2(cloneFetchBody(t)), testRepo, 0},
		{"client read error", readErr, testRepo, testMaxBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, bypass, reason, err := Classify(tt.r, tt.repo, tt.maxBody)
			if err == nil {
				t.Fatalf("Classify() error = nil (bypass %v, reason %q), want an error", bypass, reason)
			}
		})
	}
}
