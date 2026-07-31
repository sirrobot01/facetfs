package nfs4

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// writeFile creates name holding data.
func writeFile(t *testing.T, fsys facetfs.FileSystem, name, data string) {
	t.Helper()
	f, err := fsys.OpenFile(t.Context(), name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// coreOnlyFS hides every optional interface of the filesystem it wraps.
type coreOnlyFS struct{ facetfs.FileSystem }

// A truncating open must work on a filesystem that implements only the core
// interface. Linux sends it as OPEN with a size of zero in the create
// attributes, which used to be served through SetStatFS and so failed.
func TestOpenTruncatesWithoutSetStatFS(t *testing.T) {
	inner := facetfs.NewMemFS()
	writeFile(t, inner, "/data", "previous contents")

	tc := newTestClient(t, coreOnlyFS{inner})
	clientID := tc.setClientID()

	zero := uint64(0)
	var mask bitmap
	mask.set(attrSize)
	var vals xdr.Encoder
	vals.Uint64(zero)
	mode := uint32(createUnchecked)
	st, _ := openAtRoot(t, tc, clientID, "trunc-owner", 0, shareBoth, denyNone, "data", &mode, mask, vals.Bytes())
	if st != nfs4OK {
		t.Fatalf("truncating OPEN = %d, want OK", st)
	}
	if fi, err := inner.Stat(t.Context(), "/data"); err != nil || fi.Size() != 0 {
		t.Fatalf("size after truncating open = %v (%v), want 0", fi, err)
	}
}

// A READ asking for more than maxread returns what it can, not an error.
func TestReadClampsToMaxRead(t *testing.T) {
	fsys := facetfs.NewMemFS()
	writeFile(t, fsys, "/data", strings.Repeat("x", 4096))
	tc := newSizedClient(t, fsys, 1024, 0)

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opRead)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(1 << 20) // far above maxread
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("oversized READ = %d, want OK with a short read", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opRead, nfs4OK)
	d.Bool()
	if got := len(d.Opaque(1 << 20)); got != 1024 {
		t.Fatalf("read returned %d bytes, want maxread of 1024", got)
	}
}

// enospcFS fails every write with ENOSPC.
type enospcFS struct{ facetfs.FileSystem }

func (f enospcFS) OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (facetfs.File, error) {
	file, err := f.FileSystem.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	return fullFile{File: file}, nil
}

type fullFile struct{ facetfs.File }

func (fullFile) WriteAt([]byte, int64) (int, error) { return 0, syscall.ENOSPC }
func (fullFile) Write([]byte) (int, error)          { return 0, syscall.ENOSPC }

// A condition the io/fs sentinels cannot express must still reach the client.
func TestErrnoReachesTheClient(t *testing.T) {
	fsys := facetfs.NewMemFS()
	writeFile(t, fsys, "/data", "")
	tc := newTestClient(t, enospcFS{fsys})

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opWrite)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque([]byte("bytes"))
		return 3
	})
	if st != nfs4ErrNoSpc {
		t.Fatalf("WRITE on a full filesystem = %d, want NFS4ERR_NOSPC", st)
	}
}

// SETATTR must refuse a size on a directory and must tell a read-only
// attribute apart from an unsupported one.
func TestSetattrRejections(t *testing.T) {
	fsys := facetfs.NewMemFS()
	if err := fsys.Mkdir(t.Context(), "/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	tc := newTestClient(t, fsys)

	setattr := func(target string, attr int, encode func(*xdr.Encoder)) nfsStat {
		st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opLookup)
			encodeName(e, target)
			e.Uint32(opSetAttr)
			encodeStateid(e, 0, [12]byte{})
			var mask bitmap
			mask.set(attr)
			encodeBitmap(e, mask)
			var vals xdr.Encoder
			encode(&vals)
			e.Opaque(vals.Bytes())
			return 3
		})
		return st
	}

	if st := setattr("dir", attrSize, func(v *xdr.Encoder) { v.Uint64(0) }); st != nfs4ErrIsDir {
		t.Fatalf("SETATTR of size on a directory = %d, want ISDIR", st)
	}
	// change is reported by this server but cannot be set, so it is read-only.
	if st := setattr("dir", attrChange, func(v *xdr.Encoder) { v.Uint64(1) }); st != nfs4ErrInval {
		t.Fatalf("SETATTR of a read-only attribute = %d, want INVAL", st)
	}
	// The ACL attribute is not in the supported set at all.
	const attrACL = 12
	if c := (&Server{FileSystem: facetfs.NewMemFS()}); c.supportedAttrs().has(attrACL) {
		t.Fatal("this test needs an attribute the server does not report")
	}
	if st := setattr("dir", attrACL, func(v *xdr.Encoder) { v.Uint32(0) }); st != nfs4ErrAttrNotSupp {
		t.Fatalf("SETATTR of an unsupported attribute = %d, want ATTRNOTSUPP", st)
	}
}

// A share reservation must hold against the anonymous stateid too, or a
// client could reach through it what its own OPEN would be refused.
func TestSpecialStateidHonoursShareReservations(t *testing.T) {
	fsys := facetfs.NewMemFS()
	writeFile(t, fsys, "/guarded", "secret")
	tc := newTestClient(t, fsys)
	clientID := tc.setClientID()

	st, opened := openAtRoot(t, tc, clientID, "deny-owner", 0, shareBoth, denyRead, "guarded", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN with DENY_READ = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opRead)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(6)
		return 2
	})
	if st != nfs4ErrLocked {
		t.Fatalf("anonymous READ against DENY_READ = %d, want LOCKED", st)
	}

	// The owner holding the reservation still reads through its own stateid.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opRead)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(6)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("READ by the reservation holder = %d, want OK", st)
	}
}

// REMOVE must not delete a subtree. With a non-recursive remove the refusal
// is the filesystem's own, so nothing can be created into the window between
// an emptiness check and the removal.
func TestRemoveUsesNonRecursiveRemove(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := t.Context()
	if err := fsys.Mkdir(ctx, "/full", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fsys, "/full/child", "")
	if _, ok := fsys.(facetfs.RemoveFS); !ok {
		t.Fatal("the in-memory filesystem should implement RemoveFS")
	}
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
		t.Fatalf("the subtree was deleted: %v", err)
	}

	// An empty directory still goes.
	if err := fsys.RemoveAll(ctx, "/full/child"); err != nil {
		t.Fatal(err)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opRemove)
		encodeName(e, "full")
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("REMOVE of an empty directory = %d, want OK", st)
	}
}
