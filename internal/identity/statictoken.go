package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// digestPrefix is the required prefix on every tokenDigest value in
// identities.yaml, making the file self-describing about the hash
// algorithm it stores rather than a bare hex blob whose meaning depends
// on out-of-band knowledge.
const digestPrefix = "sha256:"

// tokenEntropyBytes is the amount of crypto/rand entropy NewToken mints
// per token: 32 bytes (256 bits) comfortably exceeds what's brute-forceable
// and matches the size of the SHA-256 digest it's ultimately compared
// against.
const tokenEntropyBytes = 32

// tokenEntry is one identities.yaml row: an identity ID and the SHA-256
// digest of its token, hex-encoded with the "sha256:" prefix. Only the
// digest is ever persisted to this file — the raw token exists solely at
// mint time (`haybale token new`) and in the sandbox's environment,
// which is what makes this file safe to store alongside policy.yaml
// rather than as credential material requiring its own protection.
type tokenEntry struct {
	ID          string `yaml:"id"`
	TokenDigest string `yaml:"tokenDigest"`
}

// identitiesFile is the top-level shape of identities.yaml.
type identitiesFile struct {
	Identities []tokenEntry `yaml:"identities"`
}

// StaticTokenAuthenticator authenticates requests against a fixed set of
// identity -> token-digest mappings. It never holds a raw token: only
// SHA-256 digests are stored, and Authenticate discards the presented
// token immediately after hashing it.
type StaticTokenAuthenticator struct {
	// digests maps identity ID to that identity's expected SHA-256
	// digest (32 raw bytes, not hex).
	digests map[string][]byte
}

// NewStaticTokenAuthenticator builds a StaticTokenAuthenticator from a
// map of identity ID to token digest, each digest in the same
// "sha256:<hex>" form identities.yaml stores. It validates every digest
// decodes to exactly a SHA-256-sized digest, failing fast on a
// malformed entry rather than deferring the error to the first
// authentication attempt that happens to reach it. It also rejects two
// identities sharing the same digest: Authenticate resolves a presented
// token by ranging over a map (randomized iteration order), so a
// duplicate digest would otherwise make identity resolution — and every
// policy/audit decision downstream of it — nondeterministic across
// requests for the same physical credential.
func NewStaticTokenAuthenticator(digestsByID map[string]string) (*StaticTokenAuthenticator, error) {
	if len(digestsByID) == 0 {
		return nil, fmt.Errorf("identity: at least one identity is required")
	}
	digests := make(map[string][]byte, len(digestsByID))
	// seenBy maps a digest's hex encoding to the first identity ID that
	// claimed it, so a later collision can name both sides in the error
	// without ever storing or logging the raw token that produced the
	// digest.
	seenBy := make(map[string]string, len(digestsByID))
	for id, raw := range digestsByID {
		if id == "" {
			return nil, fmt.Errorf("identity: id is required")
		}
		digest, err := decodeDigest(raw)
		if err != nil {
			return nil, fmt.Errorf("identity: id %q: %w", id, err)
		}
		digestHex := hex.EncodeToString(digest)
		if owner, dup := seenBy[digestHex]; dup {
			return nil, fmt.Errorf("identity: id %q: tokenDigest %s%s already used by identity %q", id, digestPrefix, digestHex, owner)
		}
		seenBy[digestHex] = id
		digests[id] = digest
	}
	return &StaticTokenAuthenticator{digests: digests}, nil
}

// LoadStaticTokenAuthenticator reads and parses the identities.yaml file
// at path, failing fast on a missing file, malformed YAML, an empty
// identity list, an empty or duplicate identity ID, or a tokenDigest
// that isn't a well-formed "sha256:<64 hex chars>" digest.
func LoadStaticTokenAuthenticator(path string) (*StaticTokenAuthenticator, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is the operator-supplied identities.yaml location from config, not attacker input
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}

	var f identitiesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if len(f.Identities) == 0 {
		return nil, fmt.Errorf("identity: %s: at least one identity is required", path)
	}

	digestsByID := make(map[string]string, len(f.Identities))
	for i, e := range f.Identities {
		if e.ID == "" {
			return nil, fmt.Errorf("identity: %s: identities[%d]: id is required", path, i)
		}
		if _, dup := digestsByID[e.ID]; dup {
			return nil, fmt.Errorf("identity: %s: identities[%d]: duplicate id %q", path, i, e.ID)
		}
		digestsByID[e.ID] = e.TokenDigest
	}

	auth, err := NewStaticTokenAuthenticator(digestsByID)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w", path, err)
	}
	return auth, nil
}

// decodeDigest parses a "sha256:<hex>" string into its 32 raw digest
// bytes, rejecting anything else — including a bare hex digest with no
// prefix, since the prefix is what makes the file self-describing.
func decodeDigest(s string) ([]byte, error) {
	if !strings.HasPrefix(s, digestPrefix) {
		return nil, fmt.Errorf("tokenDigest must be prefixed %q", digestPrefix)
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(s, digestPrefix))
	if err != nil {
		return nil, fmt.Errorf("tokenDigest is not valid hex: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("tokenDigest must be a sha256 digest (%d bytes), got %d", sha256.Size, len(digest))
	}
	return digest, nil
}

// Authenticate implements Authenticator. It extracts a token from r —
// preferring the HTTP Basic-auth password (the primary mechanism, since
// this is what git itself sends; the username is ignored), falling back
// to an `Authorization: Bearer <token>` header — hashes it with SHA-256,
// and compares the digest against every configured identity using
// crypto/subtle.ConstantTimeCompare so a timing side channel can't leak
// how close a guessed token is to a valid one. Neither the presented
// token nor any stored digest is ever logged.
func (a *StaticTokenAuthenticator) Authenticate(_ context.Context, r *http.Request) (*Identity, error) {
	token, ok := extractToken(r)
	if !ok || token == "" {
		return nil, ErrAuthenticationFailed
	}

	sum := sha256.Sum256([]byte(token))
	for id, digest := range a.digests {
		if subtle.ConstantTimeCompare(sum[:], digest) == 1 {
			return &Identity{ID: id}, nil
		}
	}
	return nil, ErrAuthenticationFailed
}

// bearerPrefix is the scheme prefix Authenticate recognises on an
// Authorization header when no Basic-auth password is present.
const bearerPrefix = "Bearer "

// extractToken pulls the presented token out of r: the Basic-auth
// password if present (git's primary mechanism — the username is
// arbitrary and ignored), otherwise the value of an `Authorization:
// Bearer <token>` header. It reports false if neither is present.
func extractToken(r *http.Request) (string, bool) {
	if _, password, ok := r.BasicAuth(); ok {
		return password, true
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, bearerPrefix) {
		return strings.TrimPrefix(auth, bearerPrefix), true
	}
	return "", false
}

// NewToken mints a new cryptographically-random identity token: 32
// bytes of crypto/rand entropy, base64url-encoded (no padding, so the
// result is safe to embed directly in a URL or HTTP header without
// percent-encoding) for use as the token itself, alongside the
// hex-encoded SHA-256 digest that should be persisted to
// identities.yaml in its place. Called by `haybale token new`; the raw
// token is the operator's responsibility to deliver to the sandbox
// (e.g. as HAYBALE_TOKEN) — NewToken itself never stores it anywhere.
func NewToken() (token, digestHex string, err error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("identity: generate token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}
