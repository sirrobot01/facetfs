package coord

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestNamespaceLocks(t *testing.T) {
	var locks NamespaceLocks
	const workers = 32
	value := 0
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := locks.Lock(t.Context(), "b", "a")
			if err != nil {
				t.Error(err)
				return
			}
			value++
			unlock()
		}()
	}
	wg.Wait()
	if value != workers {
		t.Fatalf("value = %d", value)
	}
}

func TestNamespaceLocksCancellation(t *testing.T) {
	var locks NamespaceLocks
	unlock, err := locks.Lock(t.Context(), "key")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := locks.Lock(ctx, "key"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lock() = %v", err)
	}
	unlock()
}
