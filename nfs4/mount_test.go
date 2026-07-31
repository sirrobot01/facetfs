package nfs4

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// testClient drives the server with raw COMPOUND calls.
type testClient struct {
	t    *testing.T
	c    net.Conn
	s    *Server
	xid  uint32
	deep int
}

func newTestClient(t *testing.T, fsys facetfs.FileSystem) *testClient {
	t.Helper()
	return newTestClientFor(t, &Server{FileSystem: fsys})
}

func newTestClientFor(t *testing.T, s *Server) *testClient {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(ctx, server) }()
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{t: t, c: client, s: s}
}

// compound sends the ops and returns the overall status and a decoder
// positioned at the eresarray count.
func (tc *testClient) compound(ops func(*xdr.Encoder) uint32) (nfsStat, *xdr.Decoder) {
	tc.t.Helper()
	tc.xid++
	if err := call(tc.c, nfsCall(tc.xid, compoundArgs("", 0, ops))); err != nil {
		tc.t.Fatal(err)
	}
	d := acceptedReply(tc.t, tc.c, tc.xid, acceptSuccess)
	st := nfsStat(d.Uint32())
	d.Opaque(maxTagBytes)
	d.Uint32() // result count
	return st, d
}

// expectOp asserts the next result is op with status want.
func expectOp(t *testing.T, d *xdr.Decoder, op uint32, want nfsStat) {
	t.Helper()
	if got := d.Uint32(); got != op {
		t.Fatalf("resop = %d, want %d", got, op)
	}
	if got := nfsStat(d.Uint32()); got != want {
		t.Fatalf("op %d status = %d, want %d", op, got, want)
	}
}

func encodeName(e *xdr.Encoder, name string) {
	e.String(name)
}

func (tc *testClient) setClientID() uint64 {
	tc.t.Helper()
	var clientID uint64
	var confirm []byte
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientID)
		e.OpaqueFixed([]byte("verify01"))
		e.Opaque([]byte("test-client"))
		e.Uint32(0)
		e.String("tcp")
		e.String("0.0.0.0.0.0")
		e.Uint32(0)
		return 1
	})
	if st != nfs4OK {
		tc.t.Fatalf("SETCLIENTID status = %d", st)
	}
	expectOp(tc.t, d, opSetClientID, nfs4OK)
	clientID = d.Uint64()
	confirm = d.OpaqueFixed(8)

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientIDConfirm)
		e.Uint64(clientID)
		e.OpaqueFixed(confirm)
		return 1
	})
	if st != nfs4OK {
		tc.t.Fatalf("SETCLIENTID_CONFIRM status = %d", st)
	}
	expectOp(tc.t, d, opSetClientIDConfirm, nfs4OK)
	return clientID
}

func testFS(t *testing.T) facetfs.FileSystem {
	t.Helper()
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	if err := fsys.Mkdir(ctx, "/docs", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ name, data string }{
		{"/hello.txt", "hello nfs"},
		{"/docs/a.txt", "aaa"},
		{"/docs/b.txt", "bbbb"},
	} {
		w, err := fsys.OpenFile(ctx, f.name, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f.data))
		w.Close()
	}
	fsys.(facetfs.SymlinkFS).Symlink(ctx, "hello.txt", "/link")
	return fsys
}

func TestMountSequence(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	tc.setClientID()

	// PUTROOTFH; GETFH; GETATTR(supported_attrs, fh_expire_type, lease_time).
	var rootFH []byte
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opGetFH)
		e.Uint32(opGetAttr)
		var b bitmap
		b.set(attrSupportedAttrs)
		b.set(attrFHExpireType)
		b.set(attrLeaseTime)
		b.set(attrMaxRead)
		b.set(attrMaxWrite)
		encodeBitmap(e, b)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("mount compound status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opGetFH, nfs4OK)
	rootFH = append(rootFH, d.Opaque(maxFHBytes)...)
	if len(rootFH) == 0 {
		t.Fatal("empty root filehandle")
	}
	expectOp(t, d, opGetAttr, nfs4OK)
	granted := decodeBitmap(d)
	vals := xdr.NewDecoder(d.Opaque(1 << 16))
	if !granted.has(attrFHExpireType) || !granted.has(attrLeaseTime) {
		t.Fatalf("granted bitmap missing required attrs: %v", granted)
	}
	decodeBitmap(vals) // supported_attrs value
	if expire := vals.Uint32(); expire != fh4VolatileAny {
		t.Fatalf("fh_expire_type = %d", expire)
	}
	if lease := vals.Uint32(); lease != 90 {
		t.Fatalf("lease_time = %d", lease)
	}
	if maxread := vals.Uint64(); maxread != defaultMaxIO {
		t.Fatalf("maxread = %d", maxread)
	}

	// PUTFH(root); LOOKUP(hello.txt); GETATTR(size, type).
	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(rootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opGetAttr)
		var b bitmap
		b.set(attrType)
		b.set(attrSize)
		encodeBitmap(e, b)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("lookup compound status = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opGetAttr, nfs4OK)
	decodeBitmap(d)
	vals = xdr.NewDecoder(d.Opaque(1 << 16))
	if typ := vals.Uint32(); typ != nf4Reg {
		t.Fatalf("type = %d", typ)
	}
	if size := vals.Uint64(); size != 9 {
		t.Fatalf("size = %d", size)
	}
}

func TestLookupErrors(t *testing.T) {
	tc := newTestClient(t, testFS(t))

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "missing")
		return 2
	})
	if st != nfs4ErrNoEnt {
		t.Fatalf("missing lookup status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4ErrNoEnt)

	// LOOKUP through a file is NOTDIR.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opLookup)
		encodeName(e, "child")
		return 3
	})
	if st != nfs4ErrNotDir {
		t.Fatalf("lookup through file status = %d", st)
	}

	// LOOKUP through a symlink is SYMLINK.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "link")
		e.Uint32(opLookup)
		encodeName(e, "child")
		return 3
	})
	if st != nfs4ErrSymlink {
		t.Fatalf("lookup through symlink status = %d", st)
	}

	// ".." as a component is BADNAME; LOOKUPP at the root is NOENT.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "..")
		return 2
	})
	if st != nfs4ErrBadName {
		t.Fatalf("dotdot lookup status = %d", st)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookupP)
		return 2
	})
	if st != nfs4ErrNoEnt {
		t.Fatalf("LOOKUPP at root status = %d", st)
	}

	// GETFH without a filehandle.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opGetFH)
		return 1
	})
	if st != nfs4ErrNoFilehandle {
		t.Fatalf("GETFH without fh status = %d", st)
	}

	// RESTOREFH without a saved filehandle.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opRestoreFH)
		return 1
	})
	if st != nfs4ErrRestoreFH {
		t.Fatalf("RESTOREFH status = %d", st)
	}
}

func TestBadFilehandles(t *testing.T) {
	tc := newTestClient(t, testFS(t))

	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque([]byte{0x07, 1, 2, 3})
		return 1
	})
	if st != nfs4ErrBadHandle {
		t.Fatalf("malformed PUTFH status = %d", st)
	}

	// A forged MAC means an expired volatile handle, not a protocol error.
	forged := make([]byte, 40)
	forged[0] = 0x01
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(forged)
		return 1
	})
	if st != nfs4ErrFHExpired {
		t.Fatalf("forged PUTFH status = %d", st)
	}
}

func TestReadlinkAndAccess(t *testing.T) {
	tc := newTestClient(t, testFS(t))

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "link")
		e.Uint32(opReadLink)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("READLINK status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opLookup, nfs4OK)
	expectOp(t, d, opReadLink, nfs4OK)
	if target := d.String(maxLinkData); target != "hello.txt" {
		t.Fatalf("readlink target = %q", target)
	}

	st, d = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opAccess)
		e.Uint32(accessRead | accessLookup | accessModify)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("ACCESS status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opAccess, nfs4OK)
	supported := d.Uint32()
	granted := d.Uint32()
	if supported != accessRead|accessLookup|accessModify || granted != supported {
		t.Fatalf("ACCESS supported=%b granted=%b", supported, granted)
	}
}

func TestReaddirPaging(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	names := make(map[string]bool)
	for i := range 100 {
		name := "/f" + strings.Repeat("x", i%7) + "-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		f, err := fsys.OpenFile(ctx, name, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		names[name[1:]] = false
	}
	tc := newTestClient(t, fsys)

	var attrs bitmap
	attrs.set(attrFileID)
	attrs.set(attrType)
	cookie := uint64(0)
	verf := make([]byte, 8)
	pages := 0
	for {
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opReadDir)
			e.Uint64(cookie)
			e.OpaqueFixed(verf)
			e.Uint32(1 << 20)
			e.Uint32(600) // small maxcount forces paging
			encodeBitmap(e, attrs)
			return 2
		})
		if st != nfs4OK {
			t.Fatalf("READDIR status = %d", st)
		}
		expectOp(t, d, opPutRootFH, nfs4OK)
		expectOp(t, d, opReadDir, nfs4OK)
		verf = append([]byte(nil), d.OpaqueFixed(8)...)
		for d.Bool() {
			cookie = d.Uint64()
			name := d.String(maxNameBytes)
			decodeBitmap(d)
			d.Opaque(1 << 16)
			seen, ok := names[name]
			if !ok || seen {
				t.Fatalf("entry %q unknown or repeated", name)
			}
			names[name] = true
		}
		eof := d.Bool()
		if d.Err() != nil {
			t.Fatalf("decode: %v", d.Err())
		}
		pages++
		if eof {
			break
		}
		if pages > 100 {
			t.Fatal("no EOF after 100 pages")
		}
	}
	if pages < 3 {
		t.Fatalf("expected paging, got %d pages", pages)
	}
	for name, seen := range names {
		if !seen {
			t.Fatalf("entry %q never listed", name)
		}
	}
}

func TestReaddirBadCookies(t *testing.T) {
	tc := newTestClient(t, testFS(t))
	for _, cookie := range []uint64{1, 2} {
		st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opReadDir)
			e.Uint64(cookie)
			e.OpaqueFixed(make([]byte, 8))
			e.Uint32(1024)
			e.Uint32(1024)
			encodeBitmap(e, nil)
			return 2
		})
		if st != nfs4ErrBadCookie {
			t.Fatalf("READDIR cookie %d status = %d", cookie, st)
		}
	}
	// Cookie 0 with a non-zero verifier is rejected.
	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opReadDir)
		e.Uint64(0)
		e.OpaqueFixed([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		e.Uint32(1024)
		e.Uint32(1024)
		encodeBitmap(e, nil)
		return 2
	})
	if st != nfs4ErrBadCookie {
		t.Fatalf("nonzero verifier with cookie 0: status = %d", st)
	}
	// A tiny maxcount that cannot fit one entry is TOOSMALL.
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opReadDir)
		e.Uint64(0)
		e.OpaqueFixed(make([]byte, 8))
		e.Uint32(1024)
		e.Uint32(8)
		encodeBitmap(e, nil)
		return 2
	})
	if st != nfs4ErrTooSmall {
		t.Fatalf("tiny maxcount status = %d", st)
	}
}

func TestVerifyOps(t *testing.T) {
	tc := newTestClient(t, testFS(t))

	sizeAttr := func(e *xdr.Encoder, size uint64) {
		var b bitmap
		b.set(attrSize)
		encodeBitmap(e, b)
		var vals xdr.Encoder
		vals.Uint64(size)
		e.Opaque(vals.Bytes())
	}
	// VERIFY with the correct size passes; the follow-up GETFH runs.
	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opVerify)
		sizeAttr(e, 9)
		e.Uint32(opGetFH)
		return 4
	})
	if st != nfs4OK {
		t.Fatalf("VERIFY same status = %d", st)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opVerify)
		sizeAttr(e, 10)
		return 3
	})
	if st != nfs4ErrNotSame {
		t.Fatalf("VERIFY different status = %d", st)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "hello.txt")
		e.Uint32(opNVerify)
		sizeAttr(e, 9)
		return 3
	})
	if st != nfs4ErrSame {
		t.Fatalf("NVERIFY same status = %d", st)
	}
}

func TestClientIDDance(t *testing.T) {
	tc := newTestClient(t, testFS(t))

	// Confirm with a bogus verifier is stale.
	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opSetClientIDConfirm)
		e.Uint64(999)
		e.OpaqueFixed(make([]byte, 8))
		return 1
	})
	if st != nfs4ErrStaleClientID {
		t.Fatalf("bogus confirm status = %d", st)
	}

	id := tc.setClientID()
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opRenew)
		e.Uint64(id)
		return 1
	})
	if st != nfs4OK {
		t.Fatalf("RENEW status = %d", st)
	}
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opRenew)
		e.Uint64(id + 77)
		return 1
	})
	if st != nfs4ErrStaleClientID {
		t.Fatalf("RENEW of unknown client status = %d", st)
	}
}
