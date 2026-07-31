package nfs4

import (
	"os"
	"testing"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// Lock state follows a renamed file. It was keyed by path, so a rename let a
// second client take a conflicting write lock on the same file under its new
// name.
func TestLockStateFollowsRename(t *testing.T) {
	fsys := testFS(t)
	tc := newTestClient(t, fsys)
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "open-owner", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)
	if st, _, _ := lockNew(t, tc, opened.fh, writeLT, 0, 100, 2, opened.state, 0, clientID, "lock-holder"); st != nfs4OK {
		t.Fatalf("LOCK status = %d", st)
	}

	if st := renameAtRoot(t, tc, "hello.txt", "moved.txt"); st != nfs4OK {
		t.Fatalf("RENAME status = %d", st)
	}

	// LOCKT through the new name must still see the holder's lock.
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "moved.txt")
		e.Uint32(opLockT)
		e.Uint32(writeLT)
		e.Uint64(0)
		e.Uint64(100)
		e.Uint64(clientID)
		e.Opaque([]byte("other-owner"))
		return 3
	})
	if st != nfs4ErrDenied {
		t.Fatalf("LOCKT through the new name = %d, want DENIED: the lock was lost by the rename", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)

	// A file created at the freed name must not inherit the lock.
	f, err := fsys.OpenFile(t.Context(), "/hello.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opLockT)
		e.Uint32(writeLT)
		e.Uint64(0)
		e.Uint64(100)
		e.Uint64(clientID)
		e.Opaque([]byte("other-owner"))
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("LOCKT on a new file at the freed name = %d, want OK: it inherited a phantom lock", st)
	}
}

// Renaming a directory moves the state of everything under it.
func TestLockStateFollowsDirectoryRename(t *testing.T) {
	fsys := testFS(t)
	tc := newTestClient(t, fsys)
	clientID := tc.setClientID()

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "docs")
		e.Uint32(opOpen)
		e.Uint32(0)
		e.Uint32(shareBoth)
		e.Uint32(denyNone)
		e.Uint64(clientID)
		e.Opaque([]byte("dir-owner"))
		e.Uint32(openNoCreate)
		e.Uint32(claimNull)
		encodeName(e, "a.txt")
		e.Uint32(opGetFH)
		return 4
	})
	if st != nfs4OK {
		t.Fatalf("OPEN under /docs = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opOpen, nfs4OK)
	state := getStateid(d)
	d.Bool()
	d.Uint64()
	d.Uint64()
	d.Uint32()
	decodeBitmap(d)
	d.Uint32()
	expectOp(t, d, opGetFH, nfs4OK)
	fh := append([]byte(nil), d.Opaque(maxFHBytes)...)
	state = confirmOpen(t, tc, fh, state, 1)

	if st, _, _ := lockNew(t, tc, fh, writeLT, 0, 50, 2, state, 0, clientID, "dir-lock"); st != nfs4OK {
		t.Fatalf("LOCK under /docs = %d", st)
	}
	if st := renameAtRoot(t, tc, "docs", "papers"); st != nfs4OK {
		t.Fatalf("directory RENAME = %d", st)
	}

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "papers")
		e.Uint32(opLookup)
		encodeName(e, "a.txt")
		e.Uint32(opLockT)
		e.Uint32(writeLT)
		e.Uint64(0)
		e.Uint64(50)
		e.Uint64(clientID)
		e.Opaque([]byte("other-owner"))
		return 4
	})
	if st != nfs4ErrDenied {
		t.Fatalf("LOCKT under the renamed directory = %d, want DENIED", st)
	}
}
