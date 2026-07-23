package facetfs

import (
	"context"
	"errors"
	"testing"
)

func TestCodeOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{name: "nil", want: ""},
		{name: "canonical", err: ErrNotFound, want: ErrNotFound},
		{name: "wrapped", err: Error(ErrAccessDenied, "open", errors.New("private detail")), want: ErrAccessDenied},
		{name: "canceled", err: context.Canceled, want: ErrCanceled},
		{name: "deadline", err: context.DeadlineExceeded, want: ErrTimeout},
		{name: "unknown", err: errors.New("boom"), want: ErrIO},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := CodeOf(test.err); got != test.want {
				t.Fatalf("CodeOf() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOpErrorMatchesCode(t *testing.T) {
	t.Parallel()
	err := Error(ErrNotFound, "lookup", errors.New("backend detail"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("wrapped error does not match its canonical code")
	}
	if errors.Is(err, ErrAccessDenied) {
		t.Fatal("wrapped error matches an unrelated canonical code")
	}
}
