package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// entryKey addresses one entry on every storage tier.
type entryKey struct {
	Group    Group
	RepoHash [32]byte
	KeyHash  [32]byte
}

// Path returns "v1/<group>/<repoHash hex>/<keyHash hex>". Group must be
// GroupRefs or GroupPack; every other component is a hex digest, so no
// client-supplied string ever becomes part of a path.
func (k entryKey) Path() string {
	return RepoPrefix(k.Group, k.RepoHash) + hex.EncodeToString(k.KeyHash[:])
}

// RepoPrefix returns the storage prefix "v1/<group>/<repoHash hex>/" that
// holds one repository's entries in group. It is the unit of push
// invalidation and of `haybale cache purge`.
func RepoPrefix(group Group, repoHash [32]byte) string {
	return layoutVersionDir + "/" + string(group) + "/" + hex.EncodeToString(repoHash[:]) + "/"
}

// ParseGroups maps a group name to the groups it selects: "" selects both
// groups, "refs" and "pack" select one, and anything else is an error.
func ParseGroups(name string) ([]Group, error) {
	switch Group(name) {
	case "":
		return []Group{GroupRefs, GroupPack}, nil
	case GroupRefs, GroupPack:
		return []Group{Group(name)}, nil
	default:
		return nil, fmt.Errorf("cache: unknown group %q (want %q or %q)", name, GroupRefs, GroupPack)
	}
}

// RepoHash identifies repo on the upstream at baseURL, keyed by the
// deployment's cache key so that the hash reveals nothing about the
// repository without the key. Including baseURL keeps entries from
// different upstreams apart even when they share storage. Owner and name
// are used with their case unchanged, matching policy. baseURL must not
// be nil.
func repoHash(cacheKey []byte, baseURL *url.URL, repo gitproto.Repo) [32]byte {
	mac := hmac.New(sha256.New, cacheKey)
	mac.Write([]byte(baseURL.String() + "\n" + repo.Owner + "/" + repo.Name))
	var sum [32]byte
	mac.Sum(sum[:0])
	return sum
}
