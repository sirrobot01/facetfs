package nfs4

import (
	"context"
	"errors"
	"io/fs"
)

// nameErr maps a FileSystem error for an operation whose object was named by
// an argument in the request.
func nameErr(err error) nfsStat {
	switch {
	case err == nil:
		return nfs4OK
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

// fhErr maps a FileSystem error for an operation on the object the current
// filehandle references: a missing object means the volatile handle went
// stale, never NOENT.
func fhErr(err error) nfsStat {
	if errors.Is(err, fs.ErrNotExist) {
		return nfs4ErrStale
	}
	return nameErr(err)
}
