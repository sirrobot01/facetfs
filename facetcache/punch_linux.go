//go:build linux

package facetcache

import (
	"os"
	"syscall"
)

// punchSupported gates the janitor's punch-behind phase.
const punchSupported = true

const (
	fallocKeepSize  = 0x1
	fallocPunchHole = 0x2
)

// punchHole releases the blocks backing [off, off+size) while keeping the
// file size, so fixed per-offset writes stay valid and the region reads as
// zeros. The caller removes the range from the range set first; metadata
// claiming less than the disk holds is safe, the reverse is not.
func punchHole(f *os.File, off, size int64) error {
	return syscall.Fallocate(int(f.Fd()), fallocKeepSize|fallocPunchHole, off, size)
}
