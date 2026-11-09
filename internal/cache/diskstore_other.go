//go:build !unix

package cache

import "io/fs"

// fileOwner reports that this platform does not expose file ownership as
// a uid, so the owner check is skipped.
func fileOwner(fs.FileInfo) (uint64, bool) { return 0, false }
