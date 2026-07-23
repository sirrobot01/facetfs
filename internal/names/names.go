package names

import (
	"strings"
	"unicode/utf8"

	"github.com/sirrobot01/facetfs"
)

func Validate(name string) error {
	if len(name) > 255 {
		return facetfs.ErrNameTooLong
	}
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
		return facetfs.ErrInvalid
	}
	return nil
}
