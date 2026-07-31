package smb

import (
	"errors"
	"syscall"
)

func errnoStatus(err error) (uint32, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case syscall.ENOTEMPTY:
		return statusDirectoryNotEmpty, true
	case syscall.ENOSPC, syscall.EDQUOT:
		return statusDiskFull, true
	case syscall.EROFS:
		return statusMediaWriteProtected, true
	case syscall.EISDIR:
		return statusFileIsADirectory, true
	case syscall.ENOTDIR:
		return statusNotADirectory, true
	}
	return 0, false
}
