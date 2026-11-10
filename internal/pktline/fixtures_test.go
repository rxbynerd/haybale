package pktline

import (
	"strings"
	"testing"
)

// raw marks a fixture part that is appended verbatim instead of being
// encoded as a data packet.
type raw string

// stream encodes parts into one pkt-line stream: a string becomes a data
// packet, a Kind becomes that special packet, and a raw is appended as is.
func stream(t testing.TB, parts ...any) []byte {
	t.Helper()
	var out []byte
	for _, part := range parts {
		var err error
		switch v := part.(type) {
		case string:
			out, err = AppendData(out, []byte(v))
		case Kind:
			out, err = AppendPacket(out, Packet{Kind: v})
		case raw:
			out = append(out, v...)
		default:
			t.Fatalf("stream: unsupported part %T", part)
		}
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
	}
	return out
}

const (
	oidA = "1f1e5c8e3a0b9d2c4e6f8a0b1c2d3e4f5a6b7c8d"
	oidB = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
)

type scanFixture struct {
	name   string
	mode   Mode
	body   []byte
	reason string // "" for storable
}

// scanFixtures returns response shapes git 2.54 produces, and variants
// the Scanner must refuse.
func scanFixtures(t testing.TB) []scanFixture {
	v2Caps := []any{
		"version 2\n",
		"agent=git/2.54.0-Darwin\n",
		"ls-refs=unborn\n",
		"fetch=shallow wait-for-done filter\n",
		"server-option\n",
		"object-format=sha1\n",
		Flush,
	}
	v0Refs := []any{
		"# service=git-upload-pack\n", Flush,
		oidA + " HEAD\x00multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed no-done symref=HEAD:refs/heads/main object-format=sha1 agent=git/2.54.0-Darwin\n",
		oidA + " refs/heads/main\n",
		oidB + " refs/tags/v1\n",
		oidA + " refs/tags/v1^{}\n",
		Flush,
	}
	frames := []any{
		"\x02Enumerating objects: 6, done.\n",
		"\x01PACK\x00\x00\x00\x02\x00\x00\x00\x06" + strings.Repeat("\x00", 40),
		"\x02Total 6 (delta 0), reused 0 (delta 0)\n",
		"\x01" + strings.Repeat("\xff", 20),
	}
	cat := func(parts ...[]any) []any {
		var out []any
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	s := func(parts ...any) []byte { return stream(t, parts...) }

	return []scanFixture{
		{"v2 capability advertisement", ModeAdvertisement, s(v2Caps...), ""},
		{"v2 capability advertisement after service line", ModeAdvertisement, s(cat([]any{"# service=git-upload-pack\n", Flush}, v2Caps)...), ""},
		{"v0 ref advertisement", ModeAdvertisement, s(v0Refs...), ""},
		{"service line without newline", ModeAdvertisement, s("# service=git-upload-pack", Flush, "version 2\n", Flush), ""},
		{"advertisement with no lines", ModeAdvertisement, s("# service=git-upload-pack\n", Flush, Flush), ReasonUnexpectedSection},
		{"advertisement of bare flush", ModeAdvertisement, s(Flush), ReasonUnexpectedSection},
		{"advertisement for receive-pack", ModeAdvertisement, s("# service=git-receive-pack\n", Flush, "version 2\n", Flush), ReasonUnexpectedSection},
		{"advertisement service line not followed by flush", ModeAdvertisement, s("# service=git-upload-pack\n", "version 2\n", Flush), ReasonUnexpectedSection},
		{"advertisement ERR", ModeAdvertisement, s("ERR access denied\n", Flush), ReasonErrorPacket},
		{"advertisement ERR after service line", ModeAdvertisement, s("# service=git-upload-pack\n", Flush, "ERR no such repository\n"), ReasonErrorPacket},
		{"advertisement without terminating flush", ModeAdvertisement, s("version 2\n", "agent=git/2.54.0\n"), ReasonTruncated},
		{"advertisement with delim", ModeAdvertisement, s("version 2\n", Delim, Flush), ReasonUnexpectedSection},

		{"ls-refs result", ModeV2Result, s(
			oidA+" HEAD symref-target:refs/heads/main\n",
			oidA+" refs/heads/main\n",
			oidB+" refs/tags/v1 peeled:"+oidA+"\n",
			Flush), ""},
		{"empty ls-refs result", ModeV2Result, s(Flush), ""},
		{"ls-refs ERR", ModeV2Result, s(oidA+" refs/heads/main\n", "ERR something broke\n", Flush), ReasonErrorPacket},
		{"ls-refs response-end", ModeV2Result, s(oidA+" refs/heads/main\n", Flush, ResponseEnd), ReasonFraming},
		{"ls-refs delim", ModeV2Result, s(oidA+" refs/heads/main\n", Delim, Flush), ReasonUnexpectedSection},
		{"ls-refs empty data packet", ModeV2Result, s(raw("0004"), Flush), ReasonFraming},
		{"ls-refs trailing byte after flush", ModeV2Result, s(oidA+" HEAD\n", Flush, raw("0")), ReasonFraming},
		{"ls-refs truncated payload", ModeV2Result, s(raw("0032" + oidA)), ReasonTruncated},
		{"ls-refs truncated length", ModeV2Result, s(oidA+" HEAD\n", raw("00")), ReasonTruncated},
		{"length 0003", ModeV2Result, s(raw("0003"), Flush), ReasonFraming},
		{"length above maximum", ModeV2Result, s(raw("fff1"), Flush), ReasonFraming},
		{"uppercase length", ModeV2Result, s(raw("000Aabcdef"), Flush), ReasonFraming},
		{"non-hex length", ModeV2Result, s(raw("00g0"), Flush), ReasonFraming},
		{"maximum length packet", ModeV2Result, s(strings.Repeat("r", maxPayload), Flush), ""},

		{"v2 fetch result", ModeV2Fetch, s(cat([]any{"packfile\n"}, frames, []any{Flush})...), ""},
		{"v2 fetch result with shallow-info", ModeV2Fetch, s(cat([]any{"shallow-info\n", "shallow " + oidA + "\n", Delim, "packfile\n"}, frames, []any{Flush})...), ""},
		{"v2 fetch result with empty shallow-info", ModeV2Fetch, s(cat([]any{"shallow-info\n", Delim, "packfile\n"}, frames, []any{Flush})...), ""},
		{"v2 fetch result with wanted-refs", ModeV2Fetch, s(cat([]any{"shallow-info\n", "unshallow " + oidB + "\n", Delim, "wanted-refs\n", oidA + " refs/heads/main\n", Delim, "packfile\n"}, frames, []any{Flush})...), ""},
		{"v2 fetch ERR instead of result", ModeV2Fetch, s("ERR upload-pack: not our ref " + oidA + "\n"), ReasonErrorPacket},
		{"v2 fetch ERR in shallow-info", ModeV2Fetch, s("shallow-info\n", "ERR bad\n", Delim, "packfile\n", Flush), ReasonErrorPacket},
		{"v2 fetch ERR in packfile", ModeV2Fetch, s("packfile\n", "\x01PACK", "ERR mid-pack\n", Flush), ReasonErrorPacket},
		{"v2 fetch channel 3", ModeV2Fetch, s("packfile\n", "\x01PACK", "\x03fatal: out of memory\n", Flush), ReasonSidebandError},
		{"v2 fetch channel 0", ModeV2Fetch, s("packfile\n", "\x00PACK", Flush), ReasonFraming},
		{"v2 fetch channel 4", ModeV2Fetch, s("packfile\n", "\x04PACK", Flush), ReasonFraming},
		{"v2 fetch text in packfile", ModeV2Fetch, s("packfile\n", "PACK", Flush), ReasonFraming},
		{"v2 fetch empty frame", ModeV2Fetch, s("packfile\n", raw("0004"), Flush), ReasonFraming},
		{"v2 fetch truncated", ModeV2Fetch, s(cat([]any{"packfile\n"}, frames)...), ReasonTruncated},
		{"v2 fetch acknowledgments", ModeV2Fetch, s("acknowledgments\n", "NAK\n", Delim, "packfile\n", "\x01PACK", Flush), ReasonUnexpectedSection},
		{"v2 fetch packfile-uris", ModeV2Fetch, s("packfile-uris\n", "x https://example.com\n", Delim, "packfile\n", "\x01PACK", Flush), ReasonUnexpectedSection},
		{"v2 fetch sections out of order", ModeV2Fetch, s("wanted-refs\n", Delim, "shallow-info\n", Delim, "packfile\n", "\x01PACK", Flush), ReasonUnexpectedSection},
		{"v2 fetch repeated section", ModeV2Fetch, s("shallow-info\n", Delim, "shallow-info\n", Delim, "packfile\n", "\x01PACK", Flush), ReasonUnexpectedSection},
		{"v2 fetch flush in shallow-info", ModeV2Fetch, s("shallow-info\n", "shallow "+oidA+"\n", Flush), ReasonUnexpectedSection},
		{"v2 fetch delim in packfile", ModeV2Fetch, s("packfile\n", "\x01PACK", Delim, Flush), ReasonUnexpectedSection},
		{"v2 fetch response-end", ModeV2Fetch, s("packfile\n", "\x01PACK", ResponseEnd), ReasonUnexpectedSection},
		{"v2 fetch bare flush", ModeV2Fetch, s(Flush), ReasonUnexpectedSection},
		{"v2 fetch trailing bytes", ModeV2Fetch, s("packfile\n", "\x01PACK", Flush, Flush), ReasonFraming},

		{"v0 upload-pack result", ModeV0UploadPack, s(cat([]any{"NAK\n"}, frames, []any{Flush})...), ""},
		{"v0 upload-pack result after ACK", ModeV0UploadPack, s(cat([]any{"ACK " + oidA + " common\n", "NAK\n"}, frames, []any{Flush})...), ""},
		{"v0 upload-pack result with shallow list", ModeV0UploadPack, s(cat([]any{"shallow " + oidA + "\n", Flush, "NAK\n"}, frames, []any{Flush})...), ""},
		{"v0 upload-pack result with empty shallow list", ModeV0UploadPack, s(cat([]any{Flush, "NAK\n"}, frames, []any{Flush})...), ""},
		{"v0 ERR", ModeV0UploadPack, s("ERR upload-pack: not our ref " + oidA + "\n"), ReasonErrorPacket},
		{"v0 ERR after NAK", ModeV0UploadPack, s("NAK\n", "ERR oops\n", Flush), ReasonErrorPacket},
		{"v0 channel 3", ModeV0UploadPack, s("NAK\n", "\x01PACK", "\x03fatal\n", Flush), ReasonSidebandError},
		{"v0 channel 5 before pack", ModeV0UploadPack, s("NAK\n", "\x05PACK", Flush), ReasonUnexpectedSection},
		{"v0 channel 5 in pack", ModeV0UploadPack, s("NAK\n", "\x01PACK", "\x05more", Flush), ReasonFraming},
		{"v0 frames before NAK", ModeV0UploadPack, s("\x01PACK", Flush), ReasonUnexpectedSection},
		{"v0 NAK only", ModeV0UploadPack, s("NAK\n", Flush), ReasonUnexpectedSection},
		{"v0 text after pack", ModeV0UploadPack, s("NAK\n", "\x01PACK", "NAK\n", Flush), ReasonFraming},
		{"v0 shallow after NAK", ModeV0UploadPack, s("NAK\n", "shallow "+oidA+"\n", Flush), ReasonUnexpectedSection},
		{"v0 second shallow flush", ModeV0UploadPack, s(Flush, Flush, "NAK\n", "\x01PACK", Flush), ReasonUnexpectedSection},
		{"v0 unknown line", ModeV0UploadPack, s("hello\n", Flush), ReasonUnexpectedSection},
		{"v0 truncated", ModeV0UploadPack, s("NAK\n", "\x01PACK"), ReasonTruncated},
		{"v0 delim", ModeV0UploadPack, s("NAK\n", "\x01PACK", Delim, Flush), ReasonUnexpectedSection},

		{"unknown mode", Mode(0), s(Flush), ReasonUnexpectedSection},
	}
}
