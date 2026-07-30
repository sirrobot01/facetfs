package names

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		want error
	}{
		{"file", nil},
		{"", fs.ErrInvalid},
		{".", fs.ErrInvalid},
		{"..", fs.ErrInvalid},
		{"a/b", fs.ErrInvalid},
		{string([]byte{0xff}), fs.ErrInvalid},
		{strings.Repeat("a", 256), fs.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.name); !errors.Is(err, test.want) {
				t.Fatalf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
}
