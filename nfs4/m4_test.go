package nfs4

import (
	"context"
	"math"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

func TestLockRangeSplitMergeAndInfinity(t *testing.T) {
	write := lockRange{start: 0, end: 100, write: true}
	readMiddle := lockRange{start: 20, end: 60}
	ranges := setLockRange(nil, write)
	ranges = setLockRange(ranges, readMiddle)
	want := []lockRange{
		{start: 0, end: 20, write: true},
		{start: 20, end: 60},
		{start: 60, end: 100, write: true},
	}
	if !slices.Equal(ranges, want) {
		t.Fatalf("downgrade ranges = %#v, want %#v", ranges, want)
	}

	// Adjacent ranges of the same type merge, then an arbitrary unlock splits.
	ranges = setLockRange(ranges, lockRange{start: 60, end: 100})
	ranges = subtractRange(ranges, lockRange{start: 30, end: 50})
	want = []lockRange{
		{start: 0, end: 20, write: true},
		{start: 20, end: 30},
		{start: 50, end: 100},
	}
	if !slices.Equal(ranges, want) {
		t.Fatalf("split ranges = %#v, want %#v", ranges, want)
	}

	toEOF, st := makeLockRange(100, math.MaxUint64, true)
	if st != nfs4OK || !toEOF.toEOF {
		t.Fatalf("to-EOF range = %#v, status %d", toEOF, st)
	}
	if _, st := makeLockRange(0, 0, false); st != nfs4ErrInval {
		t.Fatalf("zero range status = %d", st)
	}
	if _, st := makeLockRange(math.MaxUint64, 1, false); st != nfs4ErrInval {
		t.Fatalf("overflow range status = %d", st)
	}
}

func lockNew(t *testing.T, tc *testClient, fh []byte, typ uint32, offset, length uint64, openSeq uint32, openState wireStateid, lockSeq uint32, clientID uint64, owner string) (nfsStat, wireStateid, *xdr.Decoder) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opLock)
		e.Uint32(typ)
		e.Bool(false)
		e.Uint64(offset)
		e.Uint64(length)
		e.Bool(true)
		e.Uint32(openSeq)
		putStateid(e, openState)
		e.Uint32(lockSeq)
		e.Uint64(clientID)
		e.Opaque([]byte(owner))
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opLock, st)
	if st == nfs4OK {
		return st, getStateid(d), d
	}
	return st, wireStateid{}, d
}

func lockExisting(t *testing.T, tc *testClient, fh []byte, typ uint32, offset, length uint64, seqid uint32, state wireStateid) (nfsStat, wireStateid, *xdr.Decoder) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opLock)
		e.Uint32(typ)
		e.Bool(false)
		e.Uint64(offset)
		e.Uint64(length)
		e.Bool(false)
		putStateid(e, state)
		e.Uint32(seqid)
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opLock, st)
	if st == nfs4OK {
		return st, getStateid(d), d
	}
	return st, wireStateid{}, d
}

func unlock(t *testing.T, tc *testClient, fh []byte, typ uint32, offset, length uint64, seqid uint32, state wireStateid) (nfsStat, wireStateid) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opLockU)
		e.Uint32(typ)
		e.Uint32(seqid)
		putStateid(e, state)
		e.Uint64(offset)
		e.Uint64(length)
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opLockU, st)
	if st != nfs4OK {
		return st, wireStateid{}
	}
	return st, getStateid(d)
}

func setClientNamed(t *testing.T, tc *testClient, name string) uint64 {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientID)
		e.OpaqueFixed([]byte("verify01"))
		e.Opaque([]byte(name))
		e.Uint32(0)
		e.String("tcp")
		e.String("0.0.0.0.0.0")
		e.Uint32(0)
		return 1
	})
	if st != nfs4OK {
		t.Fatalf("SETCLIENTID(%q) status = %d", name, st)
	}
	expectOp(t, d, opSetClientID, nfs4OK)
	clientID := d.Uint64()
	confirm := d.OpaqueFixed(8)

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientIDConfirm)
		e.Uint64(clientID)
		e.OpaqueFixed(confirm)
		return 1
	})
	if st != nfs4OK {
		t.Fatalf("SETCLIENTID_CONFIRM(%q) status = %d", name, st)
	}
	expectOp(t, d, opSetClientIDConfirm, nfs4OK)
	return clientID
}

func TestLockContentionAcrossClients(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientA := setClientNamed(t, tc, "client-a")
	clientB := setClientNamed(t, tc, "client-b")

	st, openedA := openAtRoot(t, tc, clientA, "open-a", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("client A OPEN status = %d", st)
	}
	openedA.state = confirmOpen(t, tc, openedA.fh, openedA.state, 1)
	st, openedB := openAtRoot(t, tc, clientB, "open-b", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("client B OPEN status = %d", st)
	}
	openedB.state = confirmOpen(t, tc, openedB.fh, openedB.state, 1)

	st, _, _ = lockNew(t, tc, openedA.fh, writeLT, 0, math.MaxUint64, 2, openedA.state, 0, clientA, "lock-a")
	if st != nfs4OK {
		t.Fatalf("client A LOCK status = %d", st)
	}
	st, _, denied := lockNew(t, tc, openedB.fh, readLT, 40, 20, 2, openedB.state, 0, clientB, "lock-b")
	if st != nfs4ErrDenied {
		t.Fatalf("client B conflicting LOCK status = %d", st)
	}
	if off, length, typ := denied.Uint64(), denied.Uint64(), denied.Uint32(); off != 0 || length != math.MaxUint64 || typ != writeLT {
		t.Fatalf("denied range offset=%d length=%d type=%d", off, length, typ)
	}
	if holderID, holder := denied.Uint64(), denied.Opaque(maxLockOwnerID); holderID != clientA || string(holder) != "lock-a" {
		t.Fatalf("denied holder id=%d owner=%q", holderID, holder)
	}
}

func TestLockReclaimGetsNoGrace(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "open-owner", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opLock)
		e.Uint32(writeLT)
		e.Bool(true)
		e.Uint64(0)
		e.Uint64(1)
		e.Bool(true)
		e.Uint32(2)
		putStateid(e, opened.state)
		e.Uint32(0)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-owner"))
		return 2
	})
	if st != nfs4ErrNoGrace {
		t.Fatalf("reclaim LOCK status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opLock, nfs4ErrNoGrace)
}

func TestByteRangeLockProtocol(t *testing.T) {
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
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opReleaseLockOwner)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-a"))
		return 1
	})
	if st != nfs4ErrLocksHeld {
		t.Fatalf("RELEASE_LOCKOWNER with ranges status = %d", st)
	}

	// A different owner conflicts; blocking lock types are answered
	// immediately with the exact holder and range.
	st, _, denied := lockNew(t, tc, opened.fh, readWLT, 0, 100, 3, opened.state, 0, clientID, "lock-b")
	if st != nfs4ErrDenied {
		t.Fatalf("conflicting LOCK status = %d", st)
	}
	if off, length, typ := denied.Uint64(), denied.Uint64(), denied.Uint32(); off != 0 || length != 100 || typ != writeLT {
		t.Fatalf("denied range offset=%d length=%d type=%d", off, length, typ)
	}
	if holderID, holder := denied.Uint64(), denied.Opaque(maxLockOwnerID); holderID != clientID || string(holder) != "lock-a" {
		t.Fatalf("denied holder id=%d owner=%q", holderID, holder)
	}

	// Same-owner overlap atomically downgrades the middle of the write lock.
	st, locked, _ = lockExisting(t, tc, opened.fh, readLT, 20, 40, 1, locked)
	if st != nfs4OK || locked.seq != 2 {
		t.Fatalf("overlapping LOCK status=%d state=%v", st, locked)
	}

	// LOCKT excludes its own identity but detects another lock-owner.
	st, denied = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opLockT)
		e.Uint32(readLT)
		e.Uint64(0)
		e.Uint64(10)
		e.Uint64(clientID)
		e.Opaque([]byte("probe"))
		return 2
	})
	if st != nfs4ErrDenied {
		t.Fatalf("LOCKT status = %d", st)
	}
	expectOp(t, denied, opPutFH, nfs4OK)
	expectOp(t, denied, opLockT, nfs4ErrDenied)
	denied.Uint64()
	denied.Uint64()
	denied.Uint32()
	denied.Uint64()
	denied.Opaque(maxLockOwnerID)
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opLockT)
		e.Uint32(writeLT)
		e.Uint64(0)
		e.Uint64(100)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-a"))
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("same-owner LOCKT status = %d", st)
	}

	// A lock stateid is valid for I/O and byte-range locks remain advisory.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opRead)
		putStateid(e, locked)
		e.Uint64(0)
		e.Uint32(4)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("READ with lock stateid status = %d", st)
	}

	st, partial := unlock(t, tc, opened.fh, writeWLT, 30, 20, 2, locked)
	if st != nfs4OK || partial.seq != 3 {
		t.Fatalf("partial LOCKU status=%d state=%v", st, partial)
	}
	// Exact replay returns the cached stateid without applying the split twice.
	if replayStatus, replay := unlock(t, tc, opened.fh, readLT, 30, 20, 2, locked); replayStatus != nfs4OK || replay != partial {
		t.Fatalf("LOCKU replay status=%d state=%v, want %v", replayStatus, replay, partial)
	}

	// A downgrade that would invalidate the write locks is refused.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opOpenDowngrade)
		putStateid(e, opened.state)
		e.Uint32(4)
		e.Uint32(shareRead)
		e.Uint32(denyNone)
		return 2
	})
	if st != nfs4ErrLocksHeld {
		t.Fatalf("OPEN_DOWNGRADE with write locks status = %d", st)
	}

	// CLOSE is refused until every range is gone.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opClose)
		e.Uint32(5)
		putStateid(e, opened.state)
		return 2
	})
	if st != nfs4ErrLocksHeld {
		t.Fatalf("CLOSE with locks status = %d", st)
	}

	st, locked = unlock(t, tc, opened.fh, readLT, 0, math.MaxUint64, 3, partial)
	if st != nfs4OK || locked.seq != 4 {
		t.Fatalf("final LOCKU status=%d state=%v", st, locked)
	}
	st, locked = unlock(t, tc, opened.fh, writeLT, 1000, 10, 4, locked)
	if st != nfs4OK || locked.seq != 5 {
		t.Fatalf("empty-range LOCKU status=%d state=%v", st, locked)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opReleaseLockOwner)
		e.Uint64(clientID)
		e.Opaque([]byte("lock-a"))
		return 1
	})
	if st != nfs4OK {
		t.Fatalf("RELEASE_LOCKOWNER status = %d", st)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opClose)
		e.Uint32(6)
		putStateid(e, opened.state)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("CLOSE after unlock status = %d", st)
	}
}

type closeTrackingFile struct {
	facetfs.File
	closed bool
}

func (f *closeTrackingFile) Close() error {
	f.closed = true
	return f.File.Close()
}

func TestLeaseSweepAndExpiredTombstones(t *testing.T) {
	now := time.Unix(100, 0)
	store := newStateStore(10 * time.Second)
	store.now = func() time.Time { return now }
	id, confirm, st := store.setClientID("lease-client", [8]byte{}, "none", callbackPath{})
	if _, cst := store.confirmClientID(id, confirm); st != nfs4OK || cst != nfs4OK {
		t.Fatal("could not establish test client")
	}
	owner, st := store.ownerOf(id, "open-owner")
	if st != nfs4OK {
		t.Fatal(st)
	}
	owner.confirmed = true
	underlying, err := testFS(t).OpenFile(context.Background(), "/hello.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	tracked := &closeTrackingFile{File: underlying}
	store.mu.Lock()
	other := store.newOther()
	opened := &openState{
		other: other, seq: 1, client: owner.client, owner: owner,
		path: "/file", access: shareBoth, file: newOpenFile(tracked),
	}
	store.opens[other] = opened
	store.stateOwners[other] = owner
	store.byPath[opened.path] = []*openState{opened}
	store.mu.Unlock()

	now = now.Add(9 * time.Second)
	if st := store.renew(id); st != nfs4OK {
		t.Fatalf("RENEW status = %d", st)
	}
	now = now.Add(9 * time.Second)
	store.sweepExpired()
	if _, st := store.ownerForStateid(other); st != nfs4OK {
		t.Fatalf("renewed state expired early: %d", st)
	}

	now = now.Add(11 * time.Second)
	store.sweepExpired()
	if _, st := store.ownerForStateid(other); st != nfs4ErrExpired {
		t.Fatalf("expired stateid status = %d", st)
	}
	if st := store.renew(id); st != nfs4ErrExpired {
		t.Fatalf("expired clientid RENEW status = %d", st)
	}
	if !tracked.closed {
		t.Fatal("lease expiry did not close the client's open file")
	}

	// Tombstones are bounded to one additional lease interval.
	now = now.Add(10 * time.Second)
	store.sweepExpired()
	if _, st := store.ownerForStateid(other); st != nfs4ErrBadStateID {
		t.Fatalf("pruned stateid status = %d", st)
	}
	if st := store.renew(id); st != nfs4ErrStaleClientID {
		t.Fatalf("pruned clientid status = %d", st)
	}
}
