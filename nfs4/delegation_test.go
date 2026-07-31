package nfs4

import (
	"testing"
	"time"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

const testCBProgram = 0x40000000

// delegHarness starts a delegation-enabled server with an answering callback
// service and a confirmed client.
func delegHarness(t *testing.T) (*testClient, *cbNullServer, uint64) {
	t.Helper()
	cb := startCBNullServer(t, testCBProgram, "answer")
	tc := newTestClientFor(t, &Server{FileSystem: testFS(t), ReadDelegations: true})
	id := setClientIDCallback(tc, "client-a", testCBProgram, "tcp", cb.uaddr())
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, up := callbackState(tc.s, id); up {
			return tc, cb, id
		}
		if time.Now().After(deadline) {
			t.Fatal("callback path never recorded as answering")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type delegOpen struct {
	state     wireStateid
	fh        []byte
	rflags    uint32
	delegType uint32
	deleg     wireStateid
}

// openRoot performs OPEN of an existing name at the root and decodes the
// whole result, including the delegation arm.
func openRoot(t *testing.T, tc *testClient, clientID uint64, owner string, seqid, access, deny uint32, name string) (nfsStat, delegOpen) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opOpen)
		e.Uint32(seqid)
		e.Uint32(access)
		e.Uint32(deny)
		e.Uint64(clientID)
		e.Opaque([]byte(owner))
		e.Uint32(openNoCreate)
		e.Uint32(claimNull)
		e.String(name)
		e.Uint32(opGetFH)
		return 3
	})
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opOpen, st)
	if st != nfs4OK {
		return st, delegOpen{}
	}
	got := delegOpen{state: getStateid(d)}
	d.Bool()
	d.Uint64()
	d.Uint64()
	got.rflags = d.Uint32()
	decodeBitmap(d)
	got.delegType = d.Uint32()
	if got.delegType == openDelegateRead {
		got.deleg = getStateid(d)
		d.Bool()               // recall
		d.Uint32()             // ace type
		d.Uint32()             // ace flag
		d.Uint32()             // ace access mask
		d.String(maxNameBytes) // ace who
	}
	expectOp(t, d, opGetFH, nfs4OK)
	got.fh = append([]byte(nil), d.Opaque(maxFHBytes)...)
	if d.Err() != nil {
		t.Fatalf("decode OPEN: %v", d.Err())
	}
	return st, got
}

// confirmedOpen opens name read-only under a fresh owner and confirms it, so
// the owner's next OPEN is eligible for a delegation.
func confirmedOpen(t *testing.T, tc *testClient, clientID uint64, owner, name string) delegOpen {
	t.Helper()
	st, first := openRoot(t, tc, clientID, owner, 1, shareRead, denyNone, name)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	if first.delegType != openDelegateNone {
		t.Fatalf("delegation granted to an unconfirmed owner")
	}
	first.state = confirmOpen(t, tc, first.fh, first.state, 2)
	return first
}

func (tc *testClient) readWith(t *testing.T, fh []byte, state wireStateid, count uint32) (nfsStat, []byte) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opRead)
		putStateid(e, state)
		e.Uint64(0)
		e.Uint32(count)
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opRead, st)
	if st != nfs4OK {
		return st, nil
	}
	d.Bool()
	return st, append([]byte(nil), d.Opaque(count)...)
}

func (tc *testClient) delegReturn(t *testing.T, fh []byte, state wireStateid) nfsStat {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opDelegReturn)
		putStateid(e, state)
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opDelegReturn, st)
	return st
}

func TestReadDelegationGrantReadReturn(t *testing.T) {
	tc, _, clientID := delegHarness(t)
	confirmedOpen(t, tc, clientID, "owner-a", "hello.txt")

	st, second := openRoot(t, tc, clientID, "owner-a", 3, shareRead, denyNone, "hello.txt")
	if st != nfs4OK {
		t.Fatalf("second OPEN status = %d", st)
	}
	if second.delegType != openDelegateRead {
		t.Fatalf("delegation type = %d, want OPEN_DELEGATE_READ", second.delegType)
	}

	st, data := tc.readWith(t, second.fh, second.deleg, 64)
	if st != nfs4OK || string(data) != "hello nfs" {
		t.Fatalf("READ with delegation stateid = %d, %q", st, data)
	}

	// A read delegation must not authorize a write.
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(second.fh)
		e.Uint32(opWrite)
		putStateid(e, second.deleg)
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque([]byte("x"))
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	if st != nfs4ErrOpenMode {
		t.Fatalf("WRITE with delegation stateid = %d, want NFS4ERR_OPENMODE", st)
	}

	if st := tc.delegReturn(t, second.fh, second.deleg); st != nfs4OK {
		t.Fatalf("DELEGRETURN = %d", st)
	}
	if st := tc.delegReturn(t, second.fh, second.deleg); st != nfs4ErrBadStateID {
		t.Fatalf("second DELEGRETURN = %d, want NFS4ERR_BAD_STATEID", st)
	}
}

func TestNoDelegationWhenDisabled(t *testing.T) {
	cb := startCBNullServer(t, testCBProgram, "answer")
	tc := newTestClientFor(t, &Server{FileSystem: testFS(t)})
	clientID := setClientIDCallback(tc, "client-a", testCBProgram, "tcp", cb.uaddr())
	confirmedOpen(t, tc, clientID, "owner-a", "hello.txt")
	st, got := openRoot(t, tc, clientID, "owner-a", 3, shareRead, denyNone, "hello.txt")
	if st != nfs4OK || got.delegType != openDelegateNone {
		t.Fatalf("OPEN = %d, delegation type = %d, want none", st, got.delegType)
	}
}

func TestNoDelegationWithoutCallback(t *testing.T) {
	tc := newTestClientFor(t, &Server{FileSystem: testFS(t), ReadDelegations: true})
	clientID := setClientIDCallback(tc, "client-a", testCBProgram, "tcp", "0.0.0.0.0.0")
	confirmedOpen(t, tc, clientID, "owner-a", "hello.txt")
	st, got := openRoot(t, tc, clientID, "owner-a", 3, shareRead, denyNone, "hello.txt")
	if st != nfs4OK || got.delegType != openDelegateNone {
		t.Fatalf("OPEN = %d, delegation type = %d, want none", st, got.delegType)
	}
}

func TestNoDelegationForWriteOpen(t *testing.T) {
	tc, _, clientID := delegHarness(t)
	confirmedOpen(t, tc, clientID, "owner-a", "hello.txt")
	st, got := openRoot(t, tc, clientID, "owner-a", 3, shareRead|shareWrite, denyNone, "hello.txt")
	if st != nfs4OK || got.delegType != openDelegateNone {
		t.Fatalf("OPEN = %d, delegation type = %d, want none", st, got.delegType)
	}
}

func TestNoDelegationAgainstWriterClient(t *testing.T) {
	tc, cb, clientID := delegHarness(t)

	// A second client holds the file open for write.
	writer := newTestClientFor(t, tc.s)
	writerID := setClientIDCallback(writer, "client-w", testCBProgram, "tcp", cb.uaddr())
	st, w := openRoot(t, writer, writerID, "owner-w", 1, shareWrite, denyNone, "hello.txt")
	if st != nfs4OK {
		t.Fatalf("writer OPEN = %d", st)
	}
	confirmOpen(t, writer, w.fh, w.state, 2)

	confirmedOpen(t, tc, clientID, "owner-a", "hello.txt")
	st, got := openRoot(t, tc, clientID, "owner-a", 3, shareRead, denyNone, "hello.txt")
	if st != nfs4OK || got.delegType != openDelegateNone {
		t.Fatalf("OPEN = %d, delegation type = %d, want none against a writer", st, got.delegType)
	}
}

// TestDelegationExpiresWithLease drives the store directly: an expired lease
// revokes the client's delegations and tombstones their stateids.
func TestDelegationExpiresWithLease(t *testing.T) {
	now := time.Unix(100, 0)
	store := newStateStore(10 * time.Second)
	store.now = func() time.Time { return now }
	id, confirm, st := store.setClientID("deleg-client", [8]byte{}, "none", callbackPath{})
	if _, cst := store.confirmClientID(id, confirm); st != nfs4OK || cst != nfs4OK {
		t.Fatal("could not establish test client")
	}
	owner, st := store.ownerOf(id, "open-owner")
	if st != nfs4OK {
		t.Fatal(st)
	}
	owner.confirmed = true
	store.mu.Lock()
	c := store.confirmed[id]
	c.cbUp = true
	dl := store.grantDelegationLocked("/f", owner, shareRead)
	store.mu.Unlock()
	if dl == nil {
		t.Fatal("no delegation granted")
	}

	now = now.Add(11 * time.Second)
	store.sweepExpired()
	if _, _, _, st := store.resolveIOStateid(dl.seq, dl.other, "/f"); st != nfs4ErrExpired {
		t.Fatalf("expired delegation stateid = %d, want NFS4ERR_EXPIRED", st)
	}
	store.mu.Lock()
	held, byPath := len(store.delegs), len(store.delegsByPath)
	store.mu.Unlock()
	if held != 0 || byPath != 0 {
		t.Fatalf("delegation state survived lease expiry: %d, %d", held, byPath)
	}
}

// grantDeleg confirms an owner and opens name a second time to obtain a read
// delegation.
func grantDeleg(t *testing.T, tc *testClient, clientID uint64, owner, name string) delegOpen {
	t.Helper()
	confirmedOpen(t, tc, clientID, owner, name)
	st, got := openRoot(t, tc, clientID, owner, 3, shareRead, denyNone, name)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	if got.delegType != openDelegateRead {
		t.Fatalf("delegation type = %d, want OPEN_DELEGATE_READ", got.delegType)
	}
	return got
}

func waitRecall(t *testing.T, cb *cbNullServer) wireStateid {
	t.Helper()
	select {
	case state := <-cb.recalls:
		return state
	case <-time.After(5 * time.Second):
		t.Fatal("no CB_RECALL arrived")
		return wireStateid{}
	}
}

func TestConflictingOpenRecallsDelegation(t *testing.T) {
	tc, cb, clientID := delegHarness(t)
	held := grantDeleg(t, tc, clientID, "owner-a", "hello.txt")

	writer := newTestClientFor(t, tc.s)
	writerID := setClientIDCallback(writer, "client-w", testCBProgram, "tcp", cb.uaddr())
	st, _ := openRoot(t, writer, writerID, "owner-w", 1, shareWrite, denyNone, "hello.txt")
	if st != nfs4ErrDelay {
		t.Fatalf("conflicting OPEN = %d, want NFS4ERR_DELAY", st)
	}
	if got := waitRecall(t, cb); got != held.deleg {
		t.Fatalf("CB_RECALL stateid = %+v, want %+v", got, held.deleg)
	}

	if st := tc.delegReturn(t, held.fh, held.deleg); st != nfs4OK {
		t.Fatalf("DELEGRETURN = %d", st)
	}
	st, w := openRoot(t, writer, writerID, "owner-w", 2, shareWrite, denyNone, "hello.txt")
	if st != nfs4OK {
		t.Fatalf("retried OPEN = %d, want OK after DELEGRETURN", st)
	}
	if w.delegType != openDelegateNone {
		t.Fatalf("write OPEN got delegation type %d", w.delegType)
	}
}

func TestRepeatedConflictSendsOneRecall(t *testing.T) {
	tc, cb, clientID := delegHarness(t)
	grantDeleg(t, tc, clientID, "owner-a", "hello.txt")

	writer := newTestClientFor(t, tc.s)
	writerID := setClientIDCallback(writer, "client-w", testCBProgram, "tcp", cb.uaddr())
	for seqid := uint32(1); seqid <= 3; seqid++ {
		if st, _ := openRoot(t, writer, writerID, "owner-w", seqid, shareWrite, denyNone, "hello.txt"); st != nfs4ErrDelay {
			t.Fatalf("conflicting OPEN = %d, want NFS4ERR_DELAY", st)
		}
	}
	waitRecall(t, cb)
	select {
	case extra := <-cb.recalls:
		t.Fatalf("second CB_RECALL sent: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRecallTimeoutRevokes(t *testing.T) {
	held := recallTimeout
	recallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { recallTimeout = held })

	tc, cb, clientID := delegHarness(t)
	cb.recallMode = "ignore"
	granted := grantDeleg(t, tc, clientID, "owner-a", "hello.txt")

	writer := newTestClientFor(t, tc.s)
	writerID := setClientIDCallback(writer, "client-w", testCBProgram, "tcp", cb.uaddr())
	if st, _ := openRoot(t, writer, writerID, "owner-w", 1, shareWrite, denyNone, "hello.txt"); st != nfs4ErrDelay {
		t.Fatalf("conflicting OPEN = %d, want NFS4ERR_DELAY", st)
	}
	waitRecall(t, cb)

	// The holder never returns; after the recall timeout the conflicting
	// request proceeds and the delegation is revoked.
	deadline := time.Now().Add(5 * time.Second)
	seqid := uint32(2)
	for {
		st, _ := openRoot(t, writer, writerID, "owner-w", seqid, shareWrite, denyNone, "hello.txt")
		if st == nfs4OK {
			break
		}
		if st != nfs4ErrDelay {
			t.Fatalf("retried OPEN = %d", st)
		}
		if time.Now().After(deadline) {
			t.Fatal("conflicting OPEN never proceeded")
		}
		seqid++
		time.Sleep(20 * time.Millisecond)
	}

	if st, _ := tc.readWith(t, granted.fh, granted.deleg, 8); st != nfs4ErrAdminRevoked {
		t.Fatalf("READ with revoked delegation = %d, want NFS4ERR_ADMIN_REVOKED", st)
	}
	if st := tc.delegReturn(t, granted.fh, granted.deleg); st != nfs4ErrAdminRevoked {
		t.Fatalf("DELEGRETURN of revoked delegation = %d, want NFS4ERR_ADMIN_REVOKED", st)
	}
}

func TestRemoveRecallsHoldersDelegation(t *testing.T) {
	tc, cb, clientID := delegHarness(t)
	held := grantDeleg(t, tc, clientID, "owner-a", "hello.txt")

	remove := func() nfsStat {
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opRemove)
			e.String("hello.txt")
			return 2
		})
		expectOp(t, d, opPutRootFH, nfs4OK)
		return st
	}
	if st := remove(); st != nfs4ErrDelay {
		t.Fatalf("REMOVE of a delegated file = %d, want NFS4ERR_DELAY", st)
	}
	waitRecall(t, cb)
	if st := tc.delegReturn(t, held.fh, held.deleg); st != nfs4OK {
		t.Fatalf("DELEGRETURN = %d", st)
	}
	if st := remove(); st != nfs4OK {
		t.Fatalf("retried REMOVE = %d, want OK", st)
	}
}

func TestOwnWritesLeaveOwnDelegation(t *testing.T) {
	tc, cb, clientID := delegHarness(t)
	held := grantDeleg(t, tc, clientID, "owner-a", "hello.txt")

	// The holder itself opens for write and writes: its cache stays coherent
	// with its own changes, so nothing is recalled.
	st, w := openRoot(t, tc, clientID, "owner-b", 1, shareWrite, denyNone, "hello.txt")
	if st != nfs4OK {
		t.Fatalf("holder's write OPEN = %d", st)
	}
	w.state = confirmOpen(t, tc, w.fh, w.state, 2)
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(w.fh)
		e.Uint32(opWrite)
		putStateid(e, w.state)
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque([]byte("fresh"))
		return 2
	})
	expectOp(t, d, opPutFH, nfs4OK)
	if st != nfs4OK {
		t.Fatalf("holder's WRITE = %d", st)
	}
	select {
	case got := <-cb.recalls:
		t.Fatalf("own write recalled own delegation: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	if st, _ := tc.readWith(t, held.fh, held.deleg, 8); st != nfs4OK {
		t.Fatalf("delegation stateid after own write = %d", st)
	}
}
