//go:build !windows

package osfs

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"

	"github.com/sirrobot01/facetfs"
)

const (
	hardLinks = true
	symlinks  = true
	// modeOverlay is false: Unix filesystems store permission bits natively,
	// so GetAttr reads them straight back from the host and no overlay is kept.
	modeOverlay = false
)

// sysOpen opens path with the host's default sharing semantics, which already
// allow renaming and removing open files. It exists so file.go can share one
// call site with the Windows build, where a wider share mode is required.
func sysOpen(path string, flag int, perm fs.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

var caseSensitive = runtime.GOOS != "darwin"

func platformError(err error) facetfs.ErrorCode {
	switch {
	case errors.Is(err, syscall.ENOTDIR):
		return facetfs.ErrNotDirectory
	case errors.Is(err, syscall.EISDIR):
		return facetfs.ErrIsDirectory
	case errors.Is(err, syscall.ENOTEMPTY):
		return facetfs.ErrNotEmpty
	case errors.Is(err, syscall.EROFS):
		return facetfs.ErrReadOnly
	case errors.Is(err, syscall.ENOSPC):
		return facetfs.ErrNoSpace
	case errors.Is(err, syscall.EXDEV):
		return facetfs.ErrCrossDevice
	case errors.Is(err, syscall.EBUSY):
		return facetfs.ErrBusy
	case errors.Is(err, syscall.ENAMETOOLONG):
		return facetfs.ErrNameTooLong
	default:
		return ""
	}
}

func statFS(path string) (facetfs.FSStat, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return facetfs.FSStat{}, mapError(err)
	}
	return facetfs.FSStat{
		TotalBytes: uint64(stat.Blocks) * uint64(stat.Bsize),
		FreeBytes:  uint64(stat.Bfree) * uint64(stat.Bsize),
		AvailBytes: uint64(stat.Bavail) * uint64(stat.Bsize),
		TotalFiles: uint64(stat.Files),
		FreeFiles:  uint64(stat.Ffree),
		NameMax:    255,
	}, nil
}
