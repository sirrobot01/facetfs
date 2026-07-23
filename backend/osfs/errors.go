package osfs

import (
	"errors"
	"io/fs"

	"github.com/sirrobot01/facetfs"
)

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if code := platformError(err); code != "" {
		return facetfs.Wrap(code, "", err)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return facetfs.Wrap(facetfs.ErrNotFound, "", err)
	case errors.Is(err, fs.ErrExist):
		return facetfs.Wrap(facetfs.ErrExists, "", err)
	case errors.Is(err, fs.ErrPermission):
		return facetfs.Wrap(facetfs.ErrAccessDenied, "", err)
	case errors.Is(err, fs.ErrInvalid):
		return facetfs.Wrap(facetfs.ErrInvalid, "", err)
	}
	return facetfs.Wrap(facetfs.ErrIO, "", err)
}
