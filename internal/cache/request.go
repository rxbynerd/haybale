package cache

import "github.com/rxbynerd/haybale/internal/gitproto"

// Request is a classified, canonicalised cacheable read. Its fields are
// exactly the inputs the upstream request is built from, and KeyHash
// covers all of them that can vary between clients, so no client input
// outside the key can select the response other readers receive.
type Request struct {
	Repo  gitproto.Repo
	Class Class
	// Protocol is the validated Git-Protocol header value, "" when the
	// client sent none.
	Protocol string
	// Method is GET or POST.
	Method string
	// Endpoint is the path below the repository, with any query:
	// "info/refs?service=git-upload-pack" or "git-upload-pack".
	Endpoint string
	// Body is the canonical, identity-encoded request body; nil for GET.
	Body []byte
	// ContentType is the request Content-Type to send upstream; "" for
	// GET.
	ContentType string
	// Accept is the request Accept value to send upstream.
	Accept string
	// KeyHash is SHA-256 over Class, Protocol and Body.
	KeyHash [32]byte
}
