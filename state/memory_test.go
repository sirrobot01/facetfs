package state

import (
	"errors"
	"testing"
)

func TestMemory(t *testing.T) {
	store := NewMemory()
	if _, err := store.Get(t.Context(), "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() = %v", err)
	}
	if swapped, err := store.CompareAndSwap(t.Context(), "key", nil, []byte("one")); err != nil || !swapped {
		t.Fatalf("CompareAndSwap() = %v, %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(t.Context(), "key", nil, []byte("two")); err != nil || swapped {
		t.Fatalf("second CompareAndSwap() = %v, %v", swapped, err)
	}
	value, err := store.Get(t.Context(), "key")
	if err != nil || string(value) != "one" {
		t.Fatalf("Get() = %q, %v", value, err)
	}
	value[0] = 'x'
	value, err = store.Get(t.Context(), "key")
	if err != nil || string(value) != "one" {
		t.Fatal("stored value was not copied")
	}
	if err := store.Put(t.Context(), "key", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if swapped, err := store.CompareAndSwap(t.Context(), "key", []byte("two"), nil); err != nil || !swapped {
		t.Fatalf("delete CompareAndSwap() = %v, %v", swapped, err)
	}
}
