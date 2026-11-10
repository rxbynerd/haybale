//go:build unix

package cache

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the uid that owns the file info describes.
func fileOwner(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Uid), true
}
