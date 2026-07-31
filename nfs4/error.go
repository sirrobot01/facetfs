package nfs4

import (
	"context"
	"errors"
	"io/fs"
	"syscall"
)

// nameErr maps a FileSystem error for an operation whose object was named by
// an argument in the request.
func nameErr(err error) nfsStat {
	if err == nil {
		return nfs4OK
	}
	// The errno mapping runs first because it is the more specific one: an
	// io/fs sentinel covers several conditions at once, and ENOTEMPTY in
	// particular satisfies fs.ErrExist.
	if st, ok := errnoStat(err); ok {
		return st
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nfs4ErrNoEnt
	case errors.Is(err, fs.ErrExist):
		return nfs4ErrExist
	case errors.Is(err, fs.ErrPermission):
		return nfs4ErrAccess
	case errors.Is(err, fs.ErrInvalid):
		return nfs4ErrInval
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return nfs4ErrDelay
	default:
		return nfs4ErrIO
	}
}

// errnoStat maps the conditions a native filesystem reports that the io/fs
// sentinels cannot express. Without it a full disk or a read-only export
// reaches the client as a plain I/O error and nothing up the stack can say
// what went wrong.
func errnoStat(err error) (nfsStat, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case syscall.ENOSPC:
		return nfs4ErrNoSpc, true
	case syscall.EDQUOT:
		return nfs4ErrDQuot, true
	case syscall.EROFS:
		return nfs4ErrROFS, true
	case syscall.EISDIR:
		return nfs4ErrIsDir, true
	case syscall.ENOTDIR:
		return nfs4ErrNotDir, true
	case syscall.ENOTEMPTY:
		return nfs4ErrNotEmpty, true
	case syscall.EMLINK:
		return nfs4ErrMLink, true
	case syscall.EXDEV:
		return nfs4ErrXDev, true
	case syscall.ENXIO:
		return nfs4ErrNXIO, true
	case syscall.ENAMETOOLONG:
		return nfs4ErrNameTooLong, true
	case syscall.EFBIG:
		return nfs4ErrFBig, true
	case syscall.EBUSY, syscall.ETXTBSY:
		return nfs4ErrFileOpen, true
	}
	return 0, false
}

// fhErr maps a FileSystem error for an operation on the object the current
// filehandle references: a missing object means the volatile handle went
// stale, never NOENT.
func fhErr(err error) nfsStat {
	var errno syscall.Errno
	if errors.Is(err, fs.ErrNotExist) && (!errors.As(err, &errno) || errno == syscall.ENOENT) {
		return nfs4ErrStale
	}
	return nameErr(err)
}
