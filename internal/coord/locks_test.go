package coord

import (
	"errors"
	"testing"
)

func TestLockTable(t *testing.T) {
	var table LockTable
	first, err := table.Lock("file", "one", 0, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Lock("file", "two", 5, 10, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlapping lock = %v", err)
	}
	second, err := table.Lock("file", "two", 10, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	if !table.Conflicts("file", "three", 12, 1, true) {
		t.Fatal("write did not conflict")
	}
	table.Unlock(first)
	table.ReleaseOwner("two")
	if table.Conflicts("file", "three", 0, 20, true) {
		t.Fatal("released locks still conflict")
	}
	table.Unlock(second)
}
