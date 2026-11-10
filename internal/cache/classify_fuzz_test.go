package cache

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/rxbynerd/haybale/internal/pktline"
)

// FuzzClassify checks the classifier's invariants on arbitrary request
// bodies: it never panics, a request it accepts is a fixed point (the
// canonical body with the same headers classifies to the same key), the
// canonical body carries no agent or session-id capability, a gzip body
// classifies like its identity twin, and the canonical body never exceeds
// the bound.
func FuzzClassify(f *testing.F) {
	f.Add(cloneFetchBody(f), "version=2")
	f.Add(lsRefsBody(f, agent), "version=2")
	f.Add(fetchBody(f, "thin-pack\n", "deepen 1\n", "want "+oidA+"\n", "done\n"), "version=2")
	f.Add(v0Body(f, v0Caps+" agent=git/2.54.0-Darwin"), "")
	f.Add(pkts(f, "want "+oidA+" side-band-64k agent=git/2.54.0\n", "want "+oidB+"\n", "shallow "+oidB+"\n", "deepen 1\n", pktline.Flush, "done\n"), "")
	f.Add(pkts(f, "command=fetch\n", pktline.Delim, "want "+oidA+"\n", "have "+oidB+"\n", "done\n", pktline.Flush), "version=2")
	f.Add(pkts(f, "command=ls-refs\n", "agent=git/2.54.0\n", pktline.Delim, "peel\n", pktline.Flush), "version=2")
	f.Add([]byte("0000"), "version=2")
	f.Add([]byte("00"), "")
	f.Add([]byte(""), "version=2")
	f.Fuzz(func(t *testing.T, body []byte, protocol string) {
		if len(body) > testMaxBody {
			return
		}
		req, bypass, reason, err := classify(withProtocol(post(body), protocol), testRepo, testMaxBody)
		if err != nil {
			t.Fatalf("classify returned an error for an in-bound body: %v", err)
		}
		if bypass {
			if reason == "" {
				t.Fatal("bypass without a reason")
			}
			return
		}
		if int64(len(req.Body)) > testMaxBody {
			t.Fatalf("canonical body is %d bytes, over the %d bound", len(req.Body), testMaxBody)
		}
		if bytes.Contains(req.Body, []byte("agent=")) || bytes.Contains(req.Body, []byte("session-id=")) {
			t.Fatalf("canonical body carries a client capability: %q", req.Body)
		}
		again, bypass, reason, err := classify(withProtocol(post(req.Body), protocol), testRepo, testMaxBody)
		if err != nil || bypass {
			t.Fatalf("canonical body did not reclassify: bypass %v reason %q err %v", bypass, reason, err)
		}
		if again.Digest != req.Digest || !bytes.Equal(again.Body, req.Body) || again.Class != req.Class {
			t.Fatalf("canonical body is not a fixed point: %+v vs %+v", again, req)
		}
		zipped, bypass, reason, err := classify(withProtocol(post(gzipped(t, body), "Content-Encoding", "gzip"), protocol), testRepo, testMaxBody)
		if err != nil || bypass {
			t.Fatalf("gzip twin bypassed: reason %q err %v", reason, err)
		}
		if zipped.Digest != req.Digest {
			t.Fatal("gzip twin has a different key")
		}
	})
}

// withProtocol sets the Git-Protocol header when protocol is not empty.
func withProtocol(r *http.Request, protocol string) *http.Request {
	if protocol != "" {
		r.Header.Set("Git-Protocol", protocol)
	}
	return r
}
