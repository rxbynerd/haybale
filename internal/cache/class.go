// Package cache is haybale's optional response cache for git smart-HTTP
// reads. The design of record is docs/design/response-cache.md.
//
// A policy-allowed read is classified into a cacheable Request with a
// canonical body and a key, or bypassed to the proxy's passthrough path.
// Classification guesses nothing: any request shape it does not
// recognise is a bypass.
package cache

// Class is the kind of cacheable request.
type Class string

const (
	// ClassAdvertisement is GET info/refs?service=git-upload-pack: a v0
	// ref advertisement or a v2 capability advertisement.
	ClassAdvertisement Class = "advertisement"
	// ClassLsRefs is a protocol v2 command=ls-refs request.
	ClassLsRefs Class = "ls-refs"
	// ClassFetch is a protocol v2 command=fetch or protocol v0
	// upload-pack request whose arguments are all content-addressed.
	ClassFetch Class = "fetch"
)

// Group is a freshness group; entries of one group share a storage
// prefix per repository.
type Group string

const (
	// GroupRefs holds responses that name current ref tips and are
	// subject to the refs freshness policy.
	GroupRefs Group = "refs"
	// GroupPack holds content-addressed fetch responses.
	GroupPack Group = "pack"
)

// Group returns the freshness group of c, or "" for an unknown class.
func (c Class) Group() Group {
	switch c {
	case ClassAdvertisement, ClassLsRefs:
		return GroupRefs
	case ClassFetch:
		return GroupPack
	default:
		return ""
	}
}
