//go:build !unix

package cache

// ownerCases is empty where the platform reports no file owner.
func ownerCases() []ownerCase { return nil }
