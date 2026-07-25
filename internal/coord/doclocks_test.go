package coord

import (
	"errors"
	"testing"
	"time"
)

func TestDocLockTable(t *testing.T) {
	now := time.Unix(1000, 0)
	table := NewDocLockTable(func() time.Time { return now }, 0)

	held, err := table.Acquire(DocLock{Token: "t1", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Acquire = %v", err)
	}
	if held.Token != "t1" {
		t.Fatalf("token = %q", held.Token)
	}

	// An exclusive lock conflicts with a second acquisition.
	if _, err := table.Acquire(DocLock{Token: "t2", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second Acquire = %v", err)
	}

	// A caller without a matching token is guarded; the holder is not.
	if _, locked := table.Guard("a", []string{"other"}); !locked {
		t.Fatal("Guard did not report a conflict for a foreign token")
	}
	if _, locked := table.Guard("a", []string{"t1"}); locked {
		t.Fatal("Guard reported a conflict for the holding token")
	}
	if _, locked := table.Guard("b", nil); locked {
		t.Fatal("Guard reported a conflict on an unlocked key")
	}

	// Release frees the key for a new lock.
	if !table.Release("a", "t1") {
		t.Fatal("Release did not find the lock")
	}
	if _, locked := table.Guard("a", nil); locked {
		t.Fatal("Guard reported a conflict after release")
	}
	if _, err := table.Acquire(DocLock{Token: "t3", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Acquire after release = %v", err)
	}
}

func TestDocLockExpiry(t *testing.T) {
	now := time.Unix(2000, 0)
	table := NewDocLockTable(func() time.Time { return now }, 0)
	if _, err := table.Acquire(DocLock{Token: "t1", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Acquire = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, locked := table.Guard("a", nil); locked {
		t.Fatal("expired lock still guards the key")
	}
	// The key is reusable after expiry.
	if _, err := table.Acquire(DocLock{Token: "t2", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Acquire after expiry = %v", err)
	}
}

func TestDocLockLimit(t *testing.T) {
	now := time.Unix(3000, 0)
	table := NewDocLockTable(func() time.Time { return now }, 1)
	if _, err := table.Acquire(DocLock{Token: "t1", Key: "a", Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("first Acquire = %v", err)
	}
	if _, err := table.Acquire(DocLock{Token: "t2", Key: "b", Exclusive: true, Expires: now.Add(time.Minute)}); !errors.Is(err, ErrLimit) {
		t.Fatalf("Acquire past limit = %v", err)
	}
}

// Locks that expire on keys no caller revisits must not hold the ceiling: the
// only reclamation path for them is the sweep Acquire runs before refusing.
func TestDocLockLimitReclaimsExpired(t *testing.T) {
	now := time.Unix(4000, 0)
	table := NewDocLockTable(func() time.Time { return now }, 4)
	keys := []string{"a", "b", "c", "d"}
	for _, key := range keys {
		if _, err := table.Acquire(DocLock{Token: "t" + key, Key: key, Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
			t.Fatalf("Acquire %s = %v", key, err)
		}
	}
	// Every lock expires and nothing touches keys a-d again.
	now = now.Add(time.Hour)
	if _, err := table.Acquire(DocLock{Token: "fresh", Key: "e", Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Acquire after every lock expired = %v (count %d)", err, table.count.Load())
	}
	if count := table.count.Load(); count != 1 {
		t.Fatalf("live count = %d, want 1", count)
	}
	// The reclaimed keys are free, and the ceiling still binds on live locks.
	for _, key := range keys[:3] {
		if _, err := table.Acquire(DocLock{Token: "n" + key, Key: key, Exclusive: true, Expires: now.Add(time.Minute)}); err != nil {
			t.Fatalf("Acquire reclaimed %s = %v", key, err)
		}
	}
	if _, err := table.Acquire(DocLock{Token: "over", Key: "z", Exclusive: true, Expires: now.Add(time.Minute)}); !errors.Is(err, ErrLimit) {
		t.Fatalf("Acquire past limit with live locks = %v", err)
	}
}
