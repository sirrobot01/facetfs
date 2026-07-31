package nfs4

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// rawCompound sends a COMPOUND and returns the reply record with the xid
// stripped, so two replies can be compared byte for byte.
func (tc *testClient) rawCompound(ops func(*xdr.Encoder) uint32) []byte {
	tc.t.Helper()
	tc.xid++
	if err := call(tc.c, nfsCall(tc.xid, compoundArgs("", 0, ops))); err != nil {
		tc.t.Fatal(err)
	}
	record, err := readRecord(tc.c, 1<<24)
	if err != nil {
		tc.t.Fatal(err)
	}
	return record[4:]
}

// openOwnerCompound builds PUTROOTFH + OPEN(CREATE, UNCHECKED) for one owner.
func openCompound(clientID uint64, owner, name string, seqid uint32) func(*xdr.Encoder) uint32 {
	return func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opOpen)
		e.Uint32(seqid)
		e.Uint32(shareRead | shareWrite)
		e.Uint32(denyNone)
		e.Uint64(clientID)
		e.Opaque([]byte(owner))
		e.Uint32(openCreate)
		e.Uint32(createUnchecked)
		encodeBitmap(e, nil)
		e.Opaque(nil)
		e.Uint32(claimNull)
		encodeName(e, name)
		return 2
	}
}

// A retransmitted open-owner sequence id must replay the cached reply exactly
// and must not create a second open.
func TestProbeSeqidReplayIsByteIdentical(t *testing.T) {
	tc := newTestClient(t, facetfs.NewMemFS())
	clientID := tc.setClientID()

	first := tc.rawCompound(openCompound(clientID, "owner-replay", "replay.txt", 1))
	second := tc.rawCompound(openCompound(clientID, "owner-replay", "replay.txt", 1))
	if !bytes.Equal(first, second) {
		t.Fatalf("replay is not byte-identical:\n first=%x\nsecond=%x", first, second)
	}

	// A skipped sequence id fails and must leave the owner's sequence intact.
	st, _ := tc.compound(openCompound(clientID, "owner-replay", "replay.txt", 9))
	if st != nfs4ErrBadSeqID {
		t.Fatalf("skipped seqid status = %d, want BAD_SEQID", st)
	}
	st, _ = tc.compound(openCompound(clientID, "owner-replay", "replay.txt", 2))
	if st != nfs4OK {
		t.Fatalf("OPEN after BAD_SEQID status = %d, want OK: seqid must not advance", st)
	}
}

// openOnce performs the full OPEN plus OPEN_CONFIRM dance and returns the
// confirmed stateid and the file's filehandle.
func openOnce(t *testing.T, tc *testClient, clientID uint64, owner, name string) (uint32, [12]byte, []byte) {
	t.Helper()
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		openCompound(clientID, owner, name, 1)(e)
		e.Uint32(opGetFH)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opOpen, nfs4OK)
	seq, other := decodeStateid(d)
	d.Bool()
	d.Uint64()
	d.Uint64()
	rflags := d.Uint32()
	decodeBitmap(d)
	d.Uint32() // delegation type
	expectOp(t, d, opGetFH, nfs4OK)
	fh := append([]byte(nil), d.Opaque(maxFHBytes)...)

	if rflags&openResultConfirm != 0 {
		st, d = tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutFH)
			e.Opaque(fh)
			e.Uint32(opOpenConfirm)
			encodeStateid(e, seq, other)
			e.Uint32(2)
			return 2
		})
		if st != nfs4OK {
			t.Fatalf("OPEN_CONFIRM status = %d", st)
		}
		expectOp(t, d, opPutFH, nfs4OK)
		expectOp(t, d, opOpenConfirm, nfs4OK)
		seq, other = decodeStateid(d)
	}
	return seq, other, fh
}

// The stateid error taxonomy must distinguish stale, old, and bad.
func TestProbeStateidTaxonomy(t *testing.T) {
	tc := newTestClient(t, facetfs.NewMemFS())
	clientID := tc.setClientID()
	seq, other, fh := openOnce(t, tc, clientID, "owner-taxonomy", "state.txt")

	readWith := func(seq uint32, other [12]byte) nfsStat {
		st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutFH)
			e.Opaque(fh)
			e.Uint32(opRead)
			encodeStateid(e, seq, other)
			e.Uint64(0)
			e.Uint32(4)
			return 2
		})
		return st
	}
	if st := readWith(seq, other); st != nfs4OK {
		t.Fatalf("valid stateid read = %d", st)
	}

	staleEpoch := other
	staleEpoch[0] ^= 0xff
	if st := readWith(seq, staleEpoch); st != nfs4ErrStaleStateID {
		t.Fatalf("wrong epoch = %d, want STALE_STATEID", st)
	}

	unknown := other
	unknown[11] ^= 0xff
	if st := readWith(seq, unknown); st != nfs4ErrBadStateID {
		t.Fatalf("unknown stateid = %d, want BAD_STATEID", st)
	}
	if st := readWith(seq-1, other); st != nfs4ErrOldStateID {
		t.Fatalf("older sequence = %d, want OLD_STATEID", st)
	}
	if st := readWith(seq+5, other); st != nfs4ErrBadStateID {
		t.Fatalf("newer sequence = %d, want BAD_STATEID", st)
	}
	if st := readWith(7, [12]byte{}); st != nfs4ErrBadStateID {
		t.Fatalf("anonymous stateid with sequence 7 = %d, want BAD_STATEID", st)
	}
}

// A rename of "/a" to "/ab" must succeed: "/ab" is a sibling, not a
// descendant. A plain string-prefix test rejects it.
func TestProbeRenameSiblingPrefix(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	if err := fsys.Mkdir(ctx, "/a", 0o755); err != nil {
		t.Fatal(err)
	}
	tc := newTestClient(t, fsys)

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opSaveFH)
		e.Uint32(opPutRootFH)
		e.Uint32(opRename)
		encodeName(e, "a")
		encodeName(e, "ab")
		return 4
	})
	if st != nfs4OK {
		t.Fatalf("rename /a to /ab = %d, want OK: it is a sibling", st)
	}
	if _, err := fsys.Stat(ctx, "/ab"); err != nil {
		t.Fatalf("stat /ab after rename: %v", err)
	}

	// Renaming a directory into its own descendant must be refused.
	fsys.Mkdir(ctx, "/d", 0o755)
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opSaveFH)
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "d")
		e.Uint32(opRename)
		encodeName(e, "d")
		encodeName(e, "inner")
		return 5
	})
	if st == nfs4OK {
		t.Fatal("rename of /d into /d/inner succeeded")
	}
}

// READ and WRITE with the anonymous stateid must work without an OPEN.
func TestProbeAnonymousStateidIO(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	f, err := fsys.OpenFile(ctx, "/anon.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("0123456789"))
	f.Close()
	tc := newTestClient(t, fsys)

	read := func(offset uint64, count uint32) (nfsStat, bool, []byte) {
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opLookup)
			encodeName(e, "anon.txt")
			e.Uint32(opRead)
			encodeStateid(e, 0, [12]byte{})
			e.Uint64(offset)
			e.Uint32(count)
			return 3
		})
		if st != nfs4OK {
			return st, false, nil
		}
		expectOp(t, d, opPutRootFH, nfs4OK)
		expectOp(t, d, opLookup, nfs4OK)
		expectOp(t, d, opRead, nfs4OK)
		eof := d.Bool()
		return st, eof, d.Opaque(1 << 20)
	}

	if st, eof, data := read(0, 5); st != nfs4OK || eof || string(data) != "01234" {
		t.Fatalf("read = %d eof=%v %q", st, eof, data)
	}
	if st, eof, data := read(5, 100); st != nfs4OK || !eof || string(data) != "56789" {
		t.Fatalf("short read at EOF = %d eof=%v %q", st, eof, data)
	}
	if st, eof, data := read(1000, 10); st != nfs4OK || !eof || len(data) != 0 {
		t.Fatalf("read past EOF = %d eof=%v %q", st, eof, data)
	}

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "anon.txt")
		e.Uint32(opWrite)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(2)
		e.Uint32(0) // UNSTABLE4
		e.Opaque([]byte("XX"))
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("anonymous WRITE status = %d", st)
	}
	if got := readAll(t, fsys, "/anon.txt"); string(got) != "01XX456789" {
		t.Fatalf("content after anonymous write = %q", got)
	}

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "anon.txt")
		e.Uint32(opWrite)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(0)
		e.Opaque(nil)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("zero-length WRITE status = %d", st)
	}
}

// CREATE must refuse a regular file and reject device types.
func TestProbeCreateTypes(t *testing.T) {
	tc := newTestClient(t, facetfs.NewMemFS())

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opCreate)
		e.Uint32(nf4Reg)
		encodeName(e, "reg")
		encodeBitmap(e, nil)
		e.Opaque(nil)
		return 2
	})
	if st != nfs4ErrInval && st != nfs4ErrBadType {
		t.Fatalf("CREATE NF4REG = %d, want INVAL or BADTYPE", st)
	}

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opCreate)
		e.Uint32(nf4Blk)
		e.Uint32(1)
		e.Uint32(1)
		encodeName(e, "dev")
		encodeBitmap(e, nil)
		e.Opaque(nil)
		return 2
	})
	if st != nfs4ErrBadType {
		t.Fatalf("CREATE NF4BLK = %d, want BADTYPE", st)
	}
}

// REMOVE of a non-empty directory must be refused: RemoveAll is recursive.
func TestProbeRemoveNonEmptyDirectory(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	fsys.Mkdir(ctx, "/full", 0o755)
	f, _ := fsys.OpenFile(ctx, "/full/child", os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()
	tc := newTestClient(t, fsys)

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opRemove)
		encodeName(e, "full")
		return 2
	})
	if st != nfs4ErrNotEmpty {
		t.Fatalf("REMOVE of a non-empty directory = %d, want NOTEMPTY", st)
	}
	if _, err := fsys.Stat(ctx, "/full/child"); err != nil {
		t.Fatalf("a refused REMOVE deleted the subtree: %v", err)
	}
}

// A filehandle must go stale after its path is renamed away.
func TestProbeFilehandleStaleAfterRename(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	f, _ := fsys.OpenFile(ctx, "/old.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	f.Close()
	tc := newTestClient(t, fsys)

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "old.txt")
		e.Uint32(opGetFH)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("lookup status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opGetFH, nfs4OK)
	fh := append([]byte(nil), d.Opaque(maxFHBytes)...)

	if err := fsys.Rename(ctx, "/old.txt", "/new.txt"); err != nil {
		t.Fatal(err)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(fh)
		e.Uint32(opGetAttr)
		var b bitmap
		b.set(attrSize)
		encodeBitmap(e, b)
		return 2
	})
	if st != nfs4ErrStale {
		t.Fatalf("GETATTR on a renamed-away handle = %d, want STALE", st)
	}
}

func readAll(t *testing.T, fsys facetfs.FileSystem, name string) []byte {
	t.Helper()
	f, err := fsys.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	return buf[:n]
}
