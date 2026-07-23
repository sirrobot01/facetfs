//go:build windows

package osfs

import (
	"errors"
	"syscall"

	"github.com/sirrobot01/facetfs"
)

const (
	hardLinks     = false
	symlinks      = false
	caseSensitive = false
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
