// Package names validates path segments shared by the protocol packages.
package names

import (
	"fmt"
	"io/fs"
	"strings"
	"unicode/utf8"
)

// Validate reports whether name is acceptable as a single path segment. The
// returned error wraps fs.ErrInvalid.
func Validate(name string) error {
	if len(name) > 255 {
		return fmt.Errorf("name %q is too long: %w", name, fs.ErrInvalid)
	}
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("invalid name %q: %w", name, fs.ErrInvalid)
	}
	return nil
}
