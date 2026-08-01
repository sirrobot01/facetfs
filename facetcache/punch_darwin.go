//go:build darwin

package facetcache

import (
	"os"
	"syscall"
	"unsafe"
)

// punchSupported gates the janitor's punch-behind phase.
const punchSupported = true

// punchAlign is the F_PUNCHHOLE alignment requirement: offset and length
// must be multiples of the filesystem block size or the call fails with
// EINVAL. The janitor aligns punches inward, so sub-block edges stay cached
// instead of being served as zeros.
const punchAlign = 4096

// fPunchhole is F_PUNCHHOLE from sys/fcntl.h.
const fPunchhole = 99

// fpunchhole mirrors struct fpunchhole_t.
type fpunchhole struct {
	flags    uint32
	reserved uint32
	offset   int64
	length   int64
}

// punchHole releases the blocks backing [off, off+size) while keeping the
// file size. APFS supports it; a filesystem that does not reports ENOTSUP
// and the janitor falls back to whole-file eviction only.
func punchHole(f *os.File, off, size int64) error {
	arg := fpunchhole{offset: off, length: size}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fPunchhole, uintptr(unsafe.Pointer(&arg)))
	if errno != 0 {
		return errno
	}
	return nil
}

// markSparse is a no-op: unix filesystems create holes implicitly.
func markSparse(f *os.File) error { return nil }
