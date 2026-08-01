//go:build windows

package facetcache

import (
	"os"
	"syscall"
	"unsafe"
)

// punchSupported gates the janitor's punch-behind phase.
const punchSupported = true

// punchAlign is 1: FSCTL_SET_ZERO_DATA takes arbitrary offsets and NTFS
// deallocates the aligned interior itself.
const punchAlign = 1

const (
	fsctlSetSparse   = 0x000900c4
	fsctlSetZeroData = 0x000980c8
)

// fileZeroDataInformation mirrors FILE_ZERO_DATA_INFORMATION.
type fileZeroDataInformation struct {
	FileOffset      int64
	BeyondFinalZero int64
}

// punchHole zeroes [off, off+size) and, on a sparse NTFS file, releases the
// backing clusters. On a filesystem without sparse support the range is
// zeroed without deallocating; the bytes were already removed from the range
// set, so the cost is a refetch, never wrong data.
func punchHole(f *os.File, off, size int64) error {
	info := fileZeroDataInformation{FileOffset: off, BeyondFinalZero: off + size}
	var ret uint32
	return syscall.DeviceIoControl(
		syscall.Handle(f.Fd()), fsctlSetZeroData,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)),
		nil, 0, &ret, nil)
}

// markSparse sets the sparse flag on a fresh cache file. Without it NTFS
// physically zero-fills everything below a far-offset write, so a
// pre-truncated multi-gigabyte cache file would allocate in full on the
// first tail read.
func markSparse(f *os.File) error {
	var ret uint32
	return syscall.DeviceIoControl(
		syscall.Handle(f.Fd()), fsctlSetSparse,
		nil, 0, nil, 0, &ret, nil)
}
