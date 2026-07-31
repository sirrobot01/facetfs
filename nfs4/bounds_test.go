package nfs4

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// A fragment large enough to overflow the running total must be refused.
// Checking only the total would wrap on a 32-bit platform and admit a two
// gigabyte allocation.
func TestOversizedFragmentIsRefused(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		var marker [4]byte
		binary.BigEndian.PutUint32(marker[:], 1<<31|uint32(1<<31-1))
		client.Write(marker[:])
	}()
	if _, err := readRecord(server, (&Server{}).requestCap()); !errors.Is(err, errFraming) {
		t.Fatalf("readRecord of a two gigabyte fragment = %v, want a framing error", err)
	}
}

// A client's open count must fall again when its opens close. A count that
// only rose would refuse the client's opens once it had used the bound, however
// many it had since closed.
func TestOpenCountIsReleased(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()

	// The open-owner's sequence runs across every operation it makes, so it
	// is tracked rather than derived from the iteration.
	seqid := uint32(0)
	confirmed := false
	for i := range 4 {
		st, opened := openAtRoot(t, tc, clientID, "counted", seqid, shareBoth, denyNone, "hello.txt", nil, nil, nil)
		if st != nfs4OK {
			t.Fatalf("OPEN %d = %d", i, st)
		}
		seqid++
		if !confirmed {
			opened.state = confirmOpen(t, tc, opened.fh, opened.state, seqid)
			seqid++
			confirmed = true
		}
		closeSeq := seqid
		seqid++
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutFH)
			e.Opaque(opened.fh)
			e.Uint32(opClose)
			e.Uint32(closeSeq)
			putStateid(e, opened.state)
			return 2
		})
		if st != nfs4OK {
			t.Fatalf("CLOSE %d = %d", i, st)
		}
		expectOp(t, d, opPutFH, nfs4OK)
		expectOp(t, d, opClose, nfs4OK)
	}
}

// One lock-owner's ranges are bounded. Disjoint ranges never merge, so a
// client could otherwise grow the set without limit.
func TestLockRangesAreBounded(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "range-open", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, locked, _ := lockNew(t, tc, opened.fh, writeLT, 0, 2, 2, opened.state, 0, clientID, "range-owner")
	if st != nfs4OK {
		t.Fatalf("first LOCK = %d", st)
	}

	// Every range is disjoint from the last, so the set grows by one each time.
	refused := false
	for i := 1; i < maxLockRanges+16; i++ {
		st, next, _ := lockExisting(t, tc, opened.fh, writeLT, uint64(i)*4, 2, uint32(i), locked)
		if st == nfs4ErrResource {
			refused = true
			break
		}
		if st != nfs4OK {
			t.Fatalf("LOCK of range %d = %d", i, st)
		}
		locked = next
	}
	if !refused {
		t.Fatalf("the server accepted more than %d ranges for one owner", maxLockRanges)
	}
}
