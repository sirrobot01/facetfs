package nfs4

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// testConn runs ServeConn over a pipe and returns the client side.
func testConn(t *testing.T) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	s := &Server{FileSystem: facetfs.NewMemFS()}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(ctx, server) }()
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	return client
}

type rpcCall struct {
	xid        uint32
	rpcvers    uint32
	prog, vers uint32
	proc       uint32
	credFlavor uint32
	credBody   []byte
	verfFlavor uint32
	body       []byte
}

func call(c net.Conn, call rpcCall) error {
	var e xdr.Encoder
	e.Uint32(call.xid)
	e.Uint32(msgCall)
	e.Uint32(call.rpcvers)
	e.Uint32(call.prog)
	e.Uint32(call.vers)
	e.Uint32(call.proc)
	e.Uint32(call.credFlavor)
	e.Opaque(call.credBody)
	e.Uint32(call.verfFlavor)
	e.Opaque(nil)
	e.OpaqueFixed(call.body)
	return writeRecord(c, e.Bytes())
}

func nfsCall(xid uint32, body []byte) rpcCall {
	return rpcCall{xid: xid, rpcvers: rpcVersion, prog: nfsProgram, vers: nfsVersion, proc: procCompound, body: body}
}

func reply(t *testing.T, c net.Conn) *xdr.Decoder {
	t.Helper()
	record, err := readRecord(c, 1<<24)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return xdr.NewDecoder(record)
}

// acceptedReply asserts the RPC accepted layer and returns a decoder over the
// procedure results.
func acceptedReply(t *testing.T, c net.Conn, wantXID, wantStat uint32) *xdr.Decoder {
	t.Helper()
	d := reply(t, c)
	if xid := d.Uint32(); xid != wantXID {
		t.Fatalf("xid = %d, want %d", xid, wantXID)
	}
	if mtype := d.Uint32(); mtype != msgReply {
		t.Fatalf("mtype = %d", mtype)
	}
	if stat := d.Uint32(); stat != replyAccepted {
		t.Fatalf("reply_stat = %d, want accepted", stat)
	}
	d.Uint32()
	d.Opaque(maxCredBytes) // verifier
	if stat := d.Uint32(); stat != wantStat {
		t.Fatalf("accept_stat = %d, want %d", stat, wantStat)
	}
	return d
}

func compoundArgs(tag string, minor uint32, ops func(*xdr.Encoder) uint32) []byte {
	var e xdr.Encoder
	e.String(tag)
	e.Uint32(minor)
	var body xdr.Encoder
	n := uint32(0)
	if ops != nil {
		n = ops(&body)
	}
	e.Uint32(n)
	e.OpaqueFixed(body.Bytes())
	return e.Bytes()
}

func TestNullProcedure(t *testing.T) {
	c := testConn(t)
	if err := call(c, rpcCall{xid: 1, rpcvers: rpcVersion, prog: nfsProgram, vers: nfsVersion, proc: procNull}); err != nil {
		t.Fatal(err)
	}
	d := acceptedReply(t, c, 1, acceptSuccess)
	if d.Remaining() != 0 {
		t.Fatalf("NULL reply has %d trailing bytes", d.Remaining())
	}
}

func TestRPCVersionMismatch(t *testing.T) {
	c := testConn(t)
	if err := call(c, rpcCall{xid: 2, rpcvers: 3, prog: nfsProgram, vers: nfsVersion, proc: procNull}); err != nil {
		t.Fatal(err)
	}
	d := reply(t, c)
	d.Uint32()
	d.Uint32()
	if stat := d.Uint32(); stat != replyDenied {
		t.Fatalf("reply_stat = %d, want denied", stat)
	}
	if reject := d.Uint32(); reject != rejectRPCMismatch {
		t.Fatalf("reject_stat = %d", reject)
	}
	if low, high := d.Uint32(), d.Uint32(); low != rpcVersion || high != rpcVersion {
		t.Fatalf("mismatch range = %d..%d", low, high)
	}
}

func TestProgramErrors(t *testing.T) {
	c := testConn(t)
	if err := call(c, rpcCall{xid: 3, rpcvers: rpcVersion, prog: 100005, vers: nfsVersion, proc: procNull}); err != nil {
		t.Fatal(err)
	}
	acceptedReply(t, c, 3, acceptProgUnavail)

	if err := call(c, rpcCall{xid: 4, rpcvers: rpcVersion, prog: nfsProgram, vers: 3, proc: procNull}); err != nil {
		t.Fatal(err)
	}
	d := acceptedReply(t, c, 4, acceptProgMismatch)
	if low, high := d.Uint32(), d.Uint32(); low != nfsVersion || high != nfsVersion {
		t.Fatalf("version range = %d..%d", low, high)
	}

	if err := call(c, rpcCall{xid: 5, rpcvers: rpcVersion, prog: nfsProgram, vers: nfsVersion, proc: 9}); err != nil {
		t.Fatal(err)
	}
	acceptedReply(t, c, 5, acceptProcUnavail)
}

func TestBadAuthFlavor(t *testing.T) {
	c := testConn(t)
	if err := call(c, rpcCall{xid: 6, rpcvers: rpcVersion, prog: nfsProgram, vers: nfsVersion, proc: procNull, credFlavor: 6}); err != nil {
		t.Fatal(err)
	}
	d := reply(t, c)
	d.Uint32()
	d.Uint32()
	if stat := d.Uint32(); stat != replyDenied {
		t.Fatalf("reply_stat = %d", stat)
	}
	if reject := d.Uint32(); reject != rejectAuthError {
		t.Fatalf("reject_stat = %d", reject)
	}
	if auth := d.Uint32(); auth != authBadCred {
		t.Fatalf("auth_stat = %d", auth)
	}
}

func TestAuthSysAccepted(t *testing.T) {
	c := testConn(t)
	var cred xdr.Encoder
	cred.Uint32(0)
	cred.String("testhost")
	cred.Uint32(501)
	cred.Uint32(20)
	cred.Uint32(2)
	cred.Uint32(20)
	cred.Uint32(80)
	if err := call(c, rpcCall{xid: 7, rpcvers: rpcVersion, prog: nfsProgram, vers: nfsVersion, proc: procNull, credFlavor: authSys, credBody: cred.Bytes()}); err != nil {
		t.Fatal(err)
	}
	acceptedReply(t, c, 7, acceptSuccess)
}

func TestCompoundMinorVersionMismatch(t *testing.T) {
	c := testConn(t)
	if err := call(c, nfsCall(8, compoundArgs("t", 1, nil))); err != nil {
		t.Fatal(err)
	}
	d := acceptedReply(t, c, 8, acceptSuccess)
	if status := nfsStat(d.Uint32()); status != nfs4ErrMinorVersMismatch {
		t.Fatalf("status = %d", status)
	}
	if tag := d.String(maxTagBytes); tag != "t" {
		t.Fatalf("tag = %q", tag)
	}
	if n := d.Uint32(); n != 0 {
		t.Fatalf("resarray count = %d, want 0", n)
	}
}

func TestCompoundIllegalOp(t *testing.T) {
	c := testConn(t)
	body := compoundArgs("", 0, func(e *xdr.Encoder) uint32 {
		e.Uint32(200) // not an NFSv4.0 op
		return 1
	})
	if err := call(c, nfsCall(9, body)); err != nil {
		t.Fatal(err)
	}
	d := acceptedReply(t, c, 9, acceptSuccess)
	if status := nfsStat(d.Uint32()); status != nfs4ErrOpIllegal {
		t.Fatalf("status = %d", status)
	}
	d.Opaque(maxTagBytes)
	if n := d.Uint32(); n != 1 {
		t.Fatalf("resarray count = %d", n)
	}
	if op := d.Uint32(); op != opIllegal {
		t.Fatalf("resop = %d, want OP_ILLEGAL", op)
	}
	if status := nfsStat(d.Uint32()); status != nfs4ErrOpIllegal {
		t.Fatalf("op status = %d", status)
	}
}

func TestCompoundGarbageArgs(t *testing.T) {
	c := testConn(t)
	if err := call(c, nfsCall(10, []byte{0xff})); err != nil {
		t.Fatal(err)
	}
	acceptedReply(t, c, 10, acceptGarbageArgs)
}

func TestOversizedFragmentDropsConnection(t *testing.T) {
	c := testConn(t)
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], 1<<31|uint32((&Server{}).requestCap()+1))
	if _, err := c.Write(marker[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(c, 1<<24); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("connection survived oversized fragment: %v", err)
	}
}

func TestCompoundTooManyOps(t *testing.T) {
	c := testConn(t)
	body := compoundArgs("", 0, func(e *xdr.Encoder) uint32 {
		for range maxCompoundOps + 1 {
			e.Uint32(opGetFH)
		}
		return maxCompoundOps + 1
	})
	if err := call(c, nfsCall(11, body)); err != nil {
		t.Fatal(err)
	}
	d := acceptedReply(t, c, 11, acceptSuccess)
	if status := nfsStat(d.Uint32()); status != nfs4ErrResource {
		t.Fatalf("status = %d, want NFS4ERR_RESOURCE", status)
	}
}
