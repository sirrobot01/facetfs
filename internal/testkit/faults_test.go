package testkit

import (
	"errors"
	"testing"
)

func TestFaults(t *testing.T) {
	first := errors.New("first")
	second := errors.New("second")
	var faults Faults
	faults.Add("commit", first, second)

	if err := faults.Check("other"); err != nil {
		t.Fatalf("other point = %v", err)
	}
	if err := faults.Check("commit"); !errors.Is(err, first) {
		t.Fatalf("first check = %v", err)
	}
	if err := faults.Check("commit"); !errors.Is(err, second) {
		t.Fatalf("second check = %v", err)
	}
	if err := faults.Check("commit"); err != nil {
		t.Fatalf("exhausted point = %v", err)
	}
}
