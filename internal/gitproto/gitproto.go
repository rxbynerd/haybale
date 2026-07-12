// Package gitproto parses inbound HTTP requests into the git smart-HTTP
// shape haybale proxies. Git smart-HTTP is exactly three endpoint shapes
// (https://git-scm.com/docs/gitprotocol-http):
//
//	GET  {repo}/info/refs?service=git-upload-pack   (read)
//	GET  {repo}/info/refs?service=git-receive-pack  (write)
//	POST {repo}/git-upload-pack                      (read)
//	POST {repo}/git-receive-pack                     (write)
//
// haybale's URL scheme is host-in-path: the upstream git host is encoded
// as the first path segment, so a request arrives shaped
// /{host}/{owner}/{repo}[.git]/<endpoint>. ParseRequest extracts the
// upstream Repo and the read/write Verb, and rejects everything that
// does not match one of the three shapes above — in particular the dumb
// protocol (raw object/ref fetches) and any attempt at path traversal.
//
// This package is intentionally dependency-free (stdlib only): it is the
// security-load-bearing seam that M2's policy engine and M3's credential
// injection build on, so its behaviour must stay easy to audit.
package gitproto

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Verb is the read/write classification of a parsed request. Per the
// git smart-HTTP spec, GET .../info/refs?service=git-receive-pack counts
// as a write even though the HTTP method is GET — it is the handshake
// that precedes a push, so it must be gated exactly like the POST that
// follows it.
type Verb int

const (
	// Read identifies a git-upload-pack exchange (fetch/clone).
	Read Verb = iota
	// Write identifies a git-receive-pack exchange (push).
	Write
)

// String renders v for logging.
func (v Verb) String() string {
	switch v {
	case Read:
		return "read"
	case Write:
		return "write"
	default:
		return "unknown"
	}
}

// Repo identifies the upstream repository a request targets.
type Repo struct {
	// Host is the first path segment: the upstream git host key (looked
	// up against the configured upstreams, never dialled directly).
	Host string
	// Owner is the second path segment.
	Owner string
	// Name is the third path segment with any trailing ".git" stripped.
	Name string
}

// ErrInvalidRequest is returned (wrapped) by ParseRequest for any request
// that is not one of the three valid smart-HTTP shapes. Callers — the
// proxy in particular — should map any non-nil ParseRequest error to a
// 404: policy-denied and doesn't-exist and malformed-request must be
// indistinguishable to the client (no existence oracle).
var ErrInvalidRequest = errors.New("gitproto: invalid smart-HTTP request")

// invalid wraps reason under ErrInvalidRequest so callers can use
// errors.Is(err, ErrInvalidRequest) while still getting a descriptive
// message for logs.
//
// This must produce a single-line .Error() string: errors.Join renders
// each joined error on its own line, which would split every rejection
// log entry in two and corrupt line-oriented log ingestion the moment a
// caller logs err.Error() (as the proxy's rejection logging does).
// fmt.Errorf's %w keeps errors.Is(_, ErrInvalidRequest) working while
// keeping the message on one line.
func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, reason)
}

// ParseRequest extracts the target Repo and Verb from r, or an error
// wrapping ErrInvalidRequest if r is not a valid smart-HTTP request.
//
// The inbound path must be exactly /{host}/{owner}/{repo}[.git]/<endpoint>
// where <endpoint> is one of "info/refs" (with a valid service= query
// parameter), "git-upload-pack", or "git-receive-pack". Every other shape
// — too few segments, empty segments, ".."/"." segments (path traversal),
// dumb-protocol paths (objects/, HEAD, info/packs, ...), or an
// unrecognised/missing service= — is rejected.
func ParseRequest(r *http.Request) (Repo, Verb, error) {
	segments, err := splitPath(r.URL.Path)
	if err != nil {
		return Repo{}, 0, err
	}
	// host, owner, repo, plus at least one endpoint segment.
	if len(segments) < 4 {
		return Repo{}, 0, invalid("too few path segments")
	}

	host, owner, rawName := segments[0], segments[1], segments[2]
	if host == "" || owner == "" || rawName == "" {
		return Repo{}, 0, invalid("empty host, owner, or repo segment")
	}
	name := strings.TrimSuffix(rawName, ".git")
	if name == "" {
		return Repo{}, 0, invalid("empty repo name")
	}
	repo := Repo{Host: host, Owner: owner, Name: name}

	endpoint := segments[3:]
	verb, err := parseEndpoint(r, endpoint)
	if err != nil {
		return Repo{}, 0, err
	}
	return repo, verb, nil
}

// splitPath splits a URL path into its non-leading-slash segments and
// rejects any "." or ".." segment, on the decoded (r.URL.Path) form —
// net/http already unescapes percent-encoded segments (e.g. "%2e%2e")
// into this field, so checking the decoded string catches both the raw
// and the encoded form of a traversal attempt.
func splitPath(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, invalid("path does not start with /")
	}
	segments := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for _, s := range segments {
		if s == "." || s == ".." {
			return nil, invalid("path traversal segment")
		}
	}
	return segments, nil
}

// parseEndpoint validates the trailing path segments (and, for
// info/refs, the service= query parameter and HTTP method) against the
// three valid smart-HTTP shapes, returning the resulting Verb.
func parseEndpoint(r *http.Request, endpoint []string) (Verb, error) {
	switch {
	case len(endpoint) == 2 && endpoint[0] == "info" && endpoint[1] == "refs":
		if r.Method != http.MethodGet {
			return 0, invalid("info/refs requires GET")
		}
		// url.Values.Get returns only the first value of a repeated
		// query parameter, but the full, unmodified query string
		// (including every repeated value) is what reaches upstream.
		// git-http-backend's own parser is not guaranteed to agree with
		// Get's "first value wins" behaviour, so a client sending
		// service=git-upload-pack&service=git-receive-pack could be
		// classified here as a read while upstream processes it as a
		// write. Requiring exactly one value keeps classification
		// unambiguous regardless of how upstream parses it.
		services := r.URL.Query()["service"]
		if len(services) != 1 {
			return 0, invalid("service= parameter must appear exactly once")
		}
		switch services[0] {
		case "git-upload-pack":
			return Read, nil
		case "git-receive-pack":
			// info/refs?service=git-receive-pack is the push handshake:
			// it counts as a write even though the method is GET.
			return Write, nil
		default:
			return 0, invalid("missing or unknown service= parameter")
		}

	case len(endpoint) == 1 && endpoint[0] == "git-upload-pack":
		if r.Method != http.MethodPost {
			return 0, invalid("git-upload-pack requires POST")
		}
		return Read, nil

	case len(endpoint) == 1 && endpoint[0] == "git-receive-pack":
		if r.Method != http.MethodPost {
			return 0, invalid("git-receive-pack requires POST")
		}
		return Write, nil

	default:
		// Anything else — dumb-protocol paths (objects/.., HEAD,
		// info/packs), unknown endpoints, extra segments — is rejected.
		return 0, invalid("not a smart-HTTP endpoint")
	}
}
