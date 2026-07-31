package nfs4

import (
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// openExclusive sends OPEN with the EXCLUSIVE4 create mode.
func openExclusive(t *testing.T, tc *testClient, clientID uint64, owner string, seqid uint32, name string, verf []byte) nfsStat {
	t.Helper()
	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opOpen)
		e.Uint32(seqid)
		e.Uint32(shareWrite)
		e.Uint32(denyNone)
		e.Uint64(clientID)
		e.Opaque([]byte(owner))
		e.Uint32(openCreate)
		e.Uint32(createExclusive)
		e.OpaqueFixed(verf)
		e.Uint32(claimNull)
		encodeName(e, name)
		return 2
	})
	return st
}

// Linux creates an ordinary file with the EXCLUSIVE4 mode, so refusing it
// leaves a client unable to write anything at all. A repeat carrying the same
// verifier is the same create; one carrying another verifier is a second
// create of a file that already exists.
func TestExclusiveCreate(t *testing.T) {
	fsys := facetfs.NewMemFS()
	tc := newTestClient(t, fsys)
	clientID := tc.setClientID()
	first := []byte("verifier")
	second := []byte("OTHERVER")

	if st := openExclusive(t, tc, clientID, "excl-a", 0, "file", first); st != nfs4OK {
		t.Fatalf("exclusive create = %d, want OK", st)
	}
	if _, err := fsys.Stat(t.Context(), "/file"); err != nil {
		t.Fatalf("the file was not created: %v", err)
	}

	// A retry from another owner carrying the same verifier is the same
	// request and must not fail.
	if st := openExclusive(t, tc, clientID, "excl-b", 0, "file", first); st != nfs4OK {
		t.Fatalf("retried exclusive create = %d, want OK", st)
	}
	// A different verifier means a genuinely new create of an existing file.
	if st := openExclusive(t, tc, clientID, "excl-c", 0, "file", second); st != nfs4ErrExist {
		t.Fatalf("exclusive create of an existing file = %d, want EXIST", st)
	}
	// A file nobody created exclusively is not claimable by any verifier.
	writeFile(t, fsys, "/plain", "")
	if st := openExclusive(t, tc, clientID, "excl-d", 0, "plain", first); st != nfs4ErrExist {
		t.Fatalf("exclusive create over an unrelated file = %d, want EXIST", st)
	}
}

func TestExclusiveVerifierTableBounds(t *testing.T) {
	now := time.Unix(1000, 0)
	x := newExclusiveCreates(func() time.Time { return now }, time.Minute, 2)
	verf := [8]byte{1}

	x.record("/a", verf)
	x.record("/b", verf)
	if !x.matches("/a", verf) || !x.matches("/b", verf) {
		t.Fatal("recorded verifiers were not held")
	}
	x.record("/c", verf)
	if len(x.verfs) > x.max {
		t.Fatalf("the table holds %d entries, above the bound of %d", len(x.verfs), x.max)
	}

	// Records expire, so a much later retry is answered as a fresh create.
	now = now.Add(2 * time.Minute)
	if x.matches("/c", verf) {
		t.Fatal("an expired verifier still matched")
	}
	x.record("/d", verf)
	if len(x.verfs) != 1 {
		t.Fatalf("expired records were not reclaimed: %d held", len(x.verfs))
	}
}
