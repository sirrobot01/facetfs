//go:build windows

package osfs

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"github.com/sirrobot01/facetfs"
	"golang.org/x/sys/windows"
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

// FILE_RENAME_INFO.Flags values for the FileRenameInfoEx class. POSIX semantics
// let a rename replace a destination that still has open handles, unlinking the
// old target the way rename(2) does; MoveFileEx (used by os.Rename) fails such a
// replace with ERROR_ACCESS_DENIED.
const (
	fileRenameReplaceIfExists = 0x1
	fileRenamePosixSemantics  = 0x2
)

// fileRenameInfoEx mirrors the fixed header of the Win32 FILE_RENAME_INFO
// structure. The variable-length FileName follows in the same buffer; using a
// struct here lets the compiler place RootDirectory at the correct alignment on
// both 32- and 64-bit builds.
type fileRenameInfoEx struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// sysRename renames oldPath to newPath. For a replacing rename it uses
// SetFileInformationByHandle with POSIX semantics so the destination can be
// replaced even while open, matching Unix rename(2). Non-replacing renames (the
// caller has already verified the destination is absent) and older systems fall
// back to os.Rename.
func sysRename(oldPath, newPath string, replace bool) error {
	if !replace {
		return os.Rename(oldPath, newPath)
	}
	err := posixRename(oldPath, newPath)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		// FileRenameInfoEx predates Windows 10 1607; fall back where absent.
		return os.Rename(oldPath, newPath)
	}
	return err
}

func posixRename(oldPath, newPath string) error {
	source, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	// A DELETE-access handle is what SetFileInformationByHandle renames through;
	// FILE_FLAG_BACKUP_SEMANTICS lets the same path work for directories too.
	handle, err := windows.CreateFile(source, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	target, err := windows.UTF16FromString(newPath)
	if err != nil {
		return err
	}
	nameLen := (len(target) - 1) * 2 // bytes, excluding the terminating NUL
	nameOffset := unsafe.Offsetof(fileRenameInfoEx{}.FileName)
	buf := make([]byte, nameOffset+uintptr(nameLen))
	info := (*fileRenameInfoEx)(unsafe.Pointer(&buf[0]))
	info.Flags = fileRenameReplaceIfExists | fileRenamePosixSemantics
	info.RootDirectory = 0
	info.FileNameLength = uint32(nameLen)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[nameOffset])), len(target)-1), target[:len(target)-1])
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buf[0], uint32(len(buf)))
}
