//go:build unix

package cache

import "syscall"

// ownerCases are the owner-check cases for platforms whose Stat_t carries
// a uid.
func ownerCases() []ownerCase {
	return []ownerCase{
		{"same owner", &syscall.Stat_t{Uid: 1000}, 1000, false},
		{"other owner", &syscall.Stat_t{Uid: 0}, 1000, true},
		{"platform without uid", &syscall.Stat_t{Uid: 0}, -1, false},
	}
}
