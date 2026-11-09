package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// Key addresses one entry on every storage tier.
type Key struct {
	Group    Group
	RepoHash [32]byte
	KeyHash  [32]byte
}

// Path returns "v1/<group>/<repoHash hex>/<keyHash hex>". Group must be
// GroupRefs or GroupPack; every other component is a hex digest, so no
// client-supplied string ever becomes part of a path.
func (k Key) Path() string {
	return "v1/" + string(k.Group) + "/" + hex.EncodeToString(k.RepoHash[:]) + "/" + hex.EncodeToString(k.KeyHash[:])
}

// RepoHash identifies repo on the upstream at baseURL, keyed by the
// deployment's cache key so that the hash reveals nothing about the
// repository without the key. Including baseURL keeps entries from
// different upstreams apart even when they share storage. Owner and name
// are used with their case unchanged, matching policy. baseURL must not
// be nil.
func RepoHash(cacheKey []byte, baseURL *url.URL, repo gitproto.Repo) [32]byte {
	mac := hmac.New(sha256.New, cacheKey)
	mac.Write([]byte(baseURL.String() + "\n" + repo.Owner + "/" + repo.Name))
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}
