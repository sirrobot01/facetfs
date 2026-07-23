package coord

import (
	"errors"
	"testing"
)

func TestOpenTable(t *testing.T) {
	var table OpenTable
	first, err := table.Reserve("file", "one", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Reserve("file", "two", 2, 3); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting reserve = %v", err)
	}
	if !table.Conflicts("file", 2) {
		t.Fatal("direct write did not conflict")
	}
	second, err := table.Reserve("file", "two", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	table.Release(first)
	table.ReleaseOwner("two")
	if _, err := table.Reserve("file", "three", 2, 3); err != nil {
		t.Fatal(err)
	}
	table.Release(second)
}
