package nfs4

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

type wireStateid struct {
	seq   uint32
	other [12]byte
}

func putStateid(e *xdr.Encoder, s wireStateid) {
	encodeStateid(e, s.seq, s.other)
}

func getStateid(d *xdr.Decoder) wireStateid {
	seq, other := decodeStateid(d)
	return wireStateid{seq: seq, other: other}
}

type wireOpen struct {
	state wireStateid
	fh    []byte
	flags uint32
}

func openAtRoot(t *testing.T, tc *testClient, clientID uint64, owner string, seqid, access, deny uint32, name string, createMode *uint32, attrs bitmap, vals []byte) (nfsStat, wireOpen) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opOpen)
		e.Uint32(seqid)
		e.Uint32(access)
		e.Uint32(deny)
		e.Uint64(clientID)
		e.Opaque([]byte(owner))
		if createMode == nil {
			e.Uint32(openNoCreate)
		} else {
			e.Uint32(openCreate)
			e.Uint32(*createMode)
			encodeBitmap(e, attrs)
			e.Opaque(vals)
		}
		e.Uint32(claimNull)
		e.String(name)
		e.Uint32(opGetFH)
		return 3
	})
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opOpen, st)
	if st != nfs4OK {
		return st, wireOpen{}
	}
	got := wireOpen{state: getStateid(d)}
	d.Bool()
	d.Uint64()
	d.Uint64()
	got.flags = d.Uint32()
	decodeBitmap(d)
	d.Uint32() // OPEN_DELEGATE_NONE
	expectOp(t, d, opGetFH, nfs4OK)
	got.fh = append([]byte(nil), d.Opaque(maxFHBytes)...)
	if d.Err() != nil {
		t.Fatalf("decode OPEN: %v", d.Err())
	}
	return st, got
}

func confirmOpen(t *testing.T, tc *testClient, fh []byte, state wireStateid, seqid uint32) wireStateid {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opOpenConfirm)
		putStateid(e, state)
		e.Uint32(seqid)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("OPEN_CONFIRM status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opOpenConfirm, nfs4OK)
	return getStateid(d)
}

func TestOpenReadWriteDowngradeClose(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, opened := openAtRoot(t, tc, clientID, "owner-a", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK || opened.flags&openResultConfirm == 0 {
		t.Fatalf("OPEN status=%d flags=%#x", st, opened.flags)
	}
	st, replayed := openAtRoot(t, tc, clientID, "owner-a", 0, shareBoth, denyNone, "hello.txt", nil, nil, nil)
	if st != nfs4OK || replayed.state != opened.state || string(replayed.fh) != string(opened.fh) {
		t.Fatalf("OPEN replay status=%d state=%v fh_equal=%v", st, replayed.state, string(replayed.fh) == string(opened.fh))
	}

	// A new owner's stateid cannot be used until OPEN_CONFIRM.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opRead)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(16)
		return 2
	})
	if st != nfs4ErrBadStateID {
		t.Fatalf("READ before confirm status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opWrite)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque([]byte("HELLO"))
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("WRITE status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opWrite, nfs4OK)
	if count := d.Uint32(); count != 5 {
		t.Fatalf("WRITE count = %d", count)
	}
	if committed := d.Uint32(); committed != unstable4 {
		t.Fatalf("WRITE committed = %d", committed)
	}
	d.OpaqueFixed(8)

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opRead)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(32)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("READ status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opRead, nfs4OK)
	if !d.Bool() {
		t.Fatal("READ did not report EOF")
	}
	if got := string(d.Opaque(32)); got != "HELLO nfs" {
		t.Fatalf("READ data = %q", got)
	}

	// A bad seqid does not advance the owner.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opOpenDowngrade)
		putStateid(e, opened.state)
		e.Uint32(7)
		e.Uint32(shareRead)
		e.Uint32(denyNone)
		return 2
	})
	if st != nfs4ErrBadSeqID {
		t.Fatalf("OPEN_DOWNGRADE bad seqid status = %d", st)
	}

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opOpenDowngrade)
		putStateid(e, opened.state)
		e.Uint32(2)
		e.Uint32(shareRead)
		e.Uint32(denyNone)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("OPEN_DOWNGRADE status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opOpenDowngrade, nfs4OK)
	opened.state = getStateid(d)

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opWrite)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque([]byte("x"))
		return 2
	})
	if st != nfs4ErrOpenMode {
		t.Fatalf("WRITE after downgrade status = %d", st)
	}

	closeCall := func(seqid uint32) (nfsStat, wireStateid) {
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutFH)
			e.Opaque(opened.fh)
			e.Uint32(opClose)
			e.Uint32(seqid)
			putStateid(e, opened.state)
			return 2
		})
		expectOp(t, d, opPutFH, nfs4OK)
		expectOp(t, d, opClose, st)
		if st != nfs4OK {
			return st, wireStateid{}
		}
		return st, getStateid(d)
	}
	st, closed := closeCall(3)
	if st != nfs4OK {
		t.Fatalf("CLOSE status = %d", st)
	}
	// Exact replay succeeds even though the live open has already gone.
	if replayStatus, replay := closeCall(3); replayStatus != nfs4OK || replay != closed {
		t.Fatalf("CLOSE replay status=%d state=%v, want %v", replayStatus, replay, closed)
	}
}

func TestOpenShareReservationAndCreate(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	clientID := tc.setClientID()
	st, first := openAtRoot(t, tc, clientID, "owner-a", 0, shareRead, denyWrite, "hello.txt", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("first OPEN status = %d", st)
	}
	first.state = confirmOpen(t, tc, first.fh, first.state, 1)
	if st, _ := openAtRoot(t, tc, clientID, "owner-b", 0, shareWrite, denyNone, "hello.txt", nil, nil, nil); st != nfs4ErrShareDenied {
		t.Fatalf("conflicting OPEN status = %d", st)
	}

	var attrs bitmap
	attrs.set(attrMode)
	var vals xdr.Encoder
	vals.Uint32(0o640)
	guarded := uint32(createGuarded)
	st, created := openAtRoot(t, tc, clientID, "owner-c", 0, shareBoth, denyNone, "created.txt", &guarded, attrs, vals.Bytes())
	if st != nfs4OK {
		t.Fatalf("OPEN create status = %d", st)
	}
	created.state = confirmOpen(t, tc, created.fh, created.state, 1)
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(created.fh)
		e.Uint32(opGetAttr)
		var requested bitmap
		requested.set(attrMode)
		encodeBitmap(e, requested)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("GETATTR created mode status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opGetAttr, nfs4OK)
	decodeBitmap(d)
	attrVals := xdr.NewDecoder(d.Opaque(32))
	if mode := attrVals.Uint32(); mode != 0o640 {
		t.Fatalf("created mode = %#o", mode)
	}
}

func TestSetattrCreateRemoveRenameLinkAndCommit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	tc := newTestClient(t, facetfs.Dir(root))

	// SETATTR uses a special stateid for this path-only metadata change.
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		e.String("source.txt")
		e.Uint32(opSetAttr)
		putStateid(e, wireStateid{})
		var mask bitmap
		mask.set(attrSize)
		mask.set(attrMode)
		encodeBitmap(e, mask)
		var vals xdr.Encoder
		vals.Uint64(3)
		vals.Uint32(0o600)
		e.Opaque(vals.Bytes())
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("SETATTR status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opSetAttr, nfs4OK)
	set := decodeBitmap(d)
	if !set.has(attrSize) || !set.has(attrMode) {
		t.Fatalf("SETATTR applied = %v", set)
	}

	createObj := func(typ uint32, name, target string) {
		t.Helper()
		st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opCreate)
			e.Uint32(typ)
			if typ == nf4Lnk {
				e.String(target)
			}
			e.String(name)
			encodeBitmap(e, nil)
			e.Opaque(nil)
			return 2
		})
		if st != nfs4OK {
			t.Fatalf("CREATE %q status = %d", name, st)
		}
	}
	createObj(nf4Dir, "dir", "")
	createObj(nf4Lnk, "sym", "source.txt")

	// Saved FH is the hard-link source; current FH is its target directory.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		e.String("source.txt")
		e.Uint32(opSaveFH)
		e.Uint32(opPutRootFH)
		e.Uint32(opLink)
		e.String("hard")
		return 5
	})
	if st != nfs4OK {
		t.Fatalf("LINK status = %d", st)
	}

	// Saved and current FH are both root directories for RENAME.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opSaveFH)
		e.Uint32(opRename)
		e.String("hard")
		e.String("renamed")
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("RENAME status = %d", st)
	}

	for _, name := range []string{"renamed", "sym", "dir"} {
		st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opRemove)
			e.String(name)
			return 2
		})
		if st != nfs4OK {
			t.Fatalf("REMOVE %q status = %d", name, st)
		}
	}

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		e.String("source.txt")
		e.Uint32(opWrite)
		putStateid(e, wireStateid{})
		e.Uint64(3)
		e.Uint32(fileSync4)
		e.Opaque([]byte("!"))
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("stable WRITE status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opWrite, nfs4OK)
	if count, committed := d.Uint32(), d.Uint32(); count != 1 || committed != fileSync4 {
		t.Fatalf("stable WRITE count=%d committed=%d", count, committed)
	}
	d.OpaqueFixed(8)

	// Native files implement Sync, so COMMIT is available.
	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		e.String("source.txt")
		e.Uint32(opCommit)
		e.Uint64(0)
		e.Uint32(0)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("COMMIT status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opCommit, nfs4OK)
	if len(d.OpaqueFixed(8)) != 8 {
		t.Fatal("missing COMMIT verifier")
	}
}
