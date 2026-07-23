//go:build windows

package osfs

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"github.com/sirrobot01/facetfs"
)

const (
	hardLinks     = false
	symlinks      = false
	caseSensitive = false
	// modeOverlay is true because Windows cannot store arbitrary Unix
	// permission bits: os.Chmod only toggles the read-only attribute. The
	// backend keeps the requested mode in the record so GetAttr reports the
	// value callers set, the way an SMB/NFS server fakes Unix modes.
	modeOverlay = true
)

func platformError(err error) facetfs.ErrorCode {
	if errors.Is(err, syscall.ERROR_DIR_NOT_EMPTY) {
		return facetfs.ErrNotEmpty
	}
	return ""
}

func statFS(string) (facetfs.FSStat, error) {
	return facetfs.FSStat{NameMax: 255}, nil
}

// sysOpen opens path granting FILE_SHARE_DELETE in addition to the read and
// write sharing os.OpenFile requests. That share mode is what lets the backend
// rename or remove a file while a handle is still open, giving the POSIX
// delete-on-last-close behaviour the backend contract requires. Windows
// otherwise fails those operations with a sharing violation.
func sysOpen(path string, flag int, perm fs.FileMode) (*os.File, error) {
	if path == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ERROR_FILE_NOT_FOUND}
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = syscall.GENERIC_READ
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= syscall.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= syscall.GENERIC_WRITE
		access |= syscall.FILE_APPEND_DATA
	}
	const share = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = syscall.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = syscall.CREATE_ALWAYS
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = syscall.OPEN_ALWAYS
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = syscall.TRUNCATE_EXISTING
	default:
		createmode = syscall.OPEN_EXISTING
	}
	attrs := uint32(syscall.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attrs = syscall.FILE_ATTRIBUTE_READONLY
	}
	handle, err := syscall.CreateFile(pathp, access, share, nil, createmode, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
