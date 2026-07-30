package webdav

import (
	"errors"
	"testing"
	"time"
)

func TestMemLSLifecycle(t *testing.T) {
	ls := NewMemLS()
	t0 := time.Unix(1_000_000, 0)

	held, err := ls.Create(t0, LockDetails{Root: "/file", Owner: "o", Duration: time.Minute})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if held.Token == "" || !held.Expires.Equal(t0.Add(time.Minute)) {
		t.Fatalf("held = %+v", held)
	}

	if _, err := ls.Create(t0, LockDetails{Root: "/file"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("conflicting Create: err = %v, want ErrLocked", err)
	}

	if _, locked := ls.Guard(t0, "/file", nil); !locked {
		t.Fatal("Guard without token did not report the lock")
	}
	if _, locked := ls.Guard(t0, "/file", []string{held.Token}); locked {
		t.Fatal("Guard with the token reported a conflict")
	}
	if _, ok := ls.Holder(t0, "/file"); !ok {
		t.Fatal("Holder did not find the live lock")
	}

	refreshed, err := ls.Refresh(t0.Add(30*time.Second), "/file", held.Token, time.Hour)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !refreshed.Expires.Equal(t0.Add(30*time.Second + time.Hour)) {
		t.Fatalf("refreshed.Expires = %v", refreshed.Expires)
	}
	if _, err := ls.Refresh(t0, "/file", "wrong", time.Minute); !errors.Is(err, ErrNoSuchLock) {
		t.Fatalf("Refresh with wrong token: err = %v, want ErrNoSuchLock", err)
	}

	if err := ls.Unlock(t0, "/file", "wrong"); !errors.Is(err, ErrNoSuchLock) {
		t.Fatalf("Unlock with wrong token: err = %v, want ErrNoSuchLock", err)
	}
	if err := ls.Unlock(t0, "/file", held.Token); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, ok := ls.Holder(t0, "/file"); ok {
		t.Fatal("Holder found a released lock")
	}
}

func TestMemLSExpiry(t *testing.T) {
	ls := NewMemLS()
	t0 := time.Unix(1_000_000, 0)

	held, err := ls.Create(t0, LockDetails{Root: "/file", Duration: time.Minute})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	expired := t0.Add(2 * time.Minute)
	if _, locked := ls.Guard(expired, "/file", nil); locked {
		t.Fatal("Guard reported an expired lock")
	}
	if _, ok := ls.Holder(expired, "/file"); ok {
		t.Fatal("Holder found an expired lock")
	}
	if _, err := ls.Refresh(expired, "/file", held.Token, time.Minute); !errors.Is(err, ErrNoSuchLock) {
		t.Fatalf("Refresh of expired lock: err = %v, want ErrNoSuchLock", err)
	}
	if _, err := ls.Create(expired, LockDetails{Root: "/file", Duration: time.Minute}); err != nil {
		t.Fatalf("Create after expiry: %v", err)
	}
}

func TestClampLockDuration(t *testing.T) {
	tests := []struct {
		in, want time.Duration
	}{
		{0, defaultLockDuration},
		{-time.Second, defaultLockDuration},
		{time.Second, minLockDuration},
		{30 * time.Minute, 30 * time.Minute},
		{24 * time.Hour, maxLockDuration},
	}
	for _, test := range tests {
		if got := clampLockDuration(test.in); got != test.want {
			t.Fatalf("clampLockDuration(%v) = %v, want %v", test.in, got, test.want)
		}
	}
}
