package nfs4

import (
	"testing"
	"time"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// A LOCK whose open_stateid slot carries a lock stateid must be refused. It
// once resolved to the same owner as the lock_owner and made the server take
// one mutex twice, hanging the request and every later op on that owner.
func TestLockStateidAsOpenStateidIsRefused(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "open-owner", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, locked, _ := lockNew(t, tc, opened.fh, writeLT, 0, 100, 2, opened.state, 0, clientID, "lock-a")
	if st != nfs4OK {
		t.Fatalf("first LOCK status = %d", st)
	}

	done := make(chan nfsStat, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nfs4ErrServerFault
			}
		}()
		s, _, _ := lockNew(t, tc, opened.fh, writeLT, 200, 10, 3, locked, 1, clientID, "lock-a")
		done <- s
	}()
	select {
	case st := <-done:
		if st != nfs4ErrBadStateID {
			t.Fatalf("LOCK with a lock stateid as open_stateid = %d, want BAD_STATEID", st)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the server never answered: it deadlocked on one owner's mutex")
	}

	// The connection still serves the same owner afterwards.
	st, _, _ = lockExisting(t, tc, opened.fh, writeLT, 300, 10, 1, locked)
	if st != nfs4OK {
		t.Fatalf("LOCK after the refused request = %d, want OK", st)
	}
}

// A LOCK that repeats one sequence id and advances the other is not a
// retransmission. Replaying the cached reply told the client it held a range
// it had never been granted.
func TestLockPartialReplayIsRefused(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "open-owner", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, _, _ = lockNew(t, tc, opened.fh, writeLT, 0, 100, 2, opened.state, 0, clientID, "lock-L")
	if st != nfs4OK {
		t.Fatalf("first LOCK status = %d", st)
	}

	// The open sequence advances, the lock sequence repeats, and the range is
	// a different one.
	st, _, _ = lockNew(t, tc, opened.fh, writeLT, 500, 10, 3, opened.state, 0, clientID, "lock-L")
	if st != nfs4ErrBadSeqID {
		t.Fatalf("partial replay = %d, want BAD_SEQID", st)
	}

	// The range must not have been granted: another owner can still lock it.
	st, _, _ = lockNew(t, tc, opened.fh, writeLT, 500, 10, 3, opened.state, 0, clientID, "lock-other")
	if st != nfs4OK {
		t.Fatalf("LOCK of the never-granted range by another owner = %d, want OK", st)
	}

	// A true retransmission still replays.
	first := tc.rawCompound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opLock)
		e.Uint32(writeLT)
		e.Bool(false)
		e.Uint64(700)
		e.Uint64(10)
		e.Bool(true)
		e.Uint32(4)
		putStateid(e, opened.state)
		e.Uint32(0)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-replay"))
		return 2
	})
	second := tc.rawCompound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opLock)
		e.Uint32(writeLT)
		e.Bool(false)
		e.Uint64(700)
		e.Uint64(10)
		e.Bool(true)
		e.Uint32(4)
		putStateid(e, opened.state)
		e.Uint32(0)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-replay"))
		return 2
	})
	if string(first) != string(second) {
		t.Fatalf("retransmitted LOCK was not replayed byte for byte")
	}
}

// A second new-lock-owner LOCK for a lock-owner that already holds state on
// the file must leave the sequence stream usable.
func TestDuplicateLockOwnerStaysRecoverable(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "open-owner", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, locked, _ := lockNew(t, tc, opened.fh, writeLT, 0, 100, 2, opened.state, 0, clientID, "lock-dup")
	if st != nfs4OK {
		t.Fatalf("first LOCK status = %d", st)
	}
	if st, _, _ := lockNew(t, tc, opened.fh, writeLT, 200, 10, 3, opened.state, 1, clientID, "lock-dup"); st == nfs4OK {
		t.Fatal("a duplicate new-lock-owner LOCK succeeded")
	}
	// The lock-owner's stream is still usable through the existing-owner form.
	if st, _, _ := lockExisting(t, tc, opened.fh, writeLT, 200, 10, 2, locked); st != nfs4OK {
		t.Fatalf("LOCK after the duplicate = %d, want OK: the stream is wedged", st)
	}
}
