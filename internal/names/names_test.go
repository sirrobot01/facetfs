package names

import (
	"errors"
	"strings"
	"testing"

	"github.com/sirrobot01/facetfs"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		want error
	}{
		{"file", nil},
		{"", facetfs.ErrInvalid},
		{".", facetfs.ErrInvalid},
		{"..", facetfs.ErrInvalid},
		{"a/b", facetfs.ErrInvalid},
		{string([]byte{0xff}), facetfs.ErrInvalid},
		{strings.Repeat("a", 256), facetfs.ErrNameTooLong},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.name); !errors.Is(err, test.want) {
				t.Fatalf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
}
