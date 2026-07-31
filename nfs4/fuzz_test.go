package nfs4

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// FuzzServeConn drives the whole server with arbitrary bytes framed as one RPC
// record. It asserts the server neither panics nor hangs, whatever it is sent.
func FuzzServeConn(f *testing.F) {
	f.Add(compoundRecord(1, compoundArgs("", 0, nil)))
	f.Add(compoundRecord(2, compoundArgs("tag", 0, func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opGetFH)
		e.Uint32(opGetAttr)
		var b bitmap
		b.set(attrSupportedAttrs)
		b.set(attrSize)
		encodeBitmap(e, b)
		return 3
	})))
	f.Add(compoundRecord(3, compoundArgs("", 0, func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opOpen)
		e.Uint32(1)
		e.Uint32(shareRead | shareWrite)
		e.Uint32(denyNone)
		e.Uint64(1)
		e.Opaque([]byte("fuzz-owner"))
		e.Uint32(openCreate)
		e.Uint32(createUnchecked)
		encodeBitmap(e, nil)
		e.Opaque(nil)
		e.Uint32(claimNull)
		encodeName(e, "f")
		return 2
	})))
	f.Add(compoundRecord(4, compoundArgs("", 0, func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opReadDir)
		e.Uint64(0)
		e.OpaqueFixed(make([]byte, 8))
		e.Uint32(4096)
		e.Uint32(4096)
		encodeBitmap(e, nil)
		return 2
	})))
	f.Add(compoundRecord(5, compoundArgs("", 0, func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLock)
		e.Uint32(1)
		e.Uint32(0)
		e.Bool(false)
		e.Uint64(0)
		e.Uint64(^uint64(0))
		e.Bool(true)
		e.Uint32(1)
		encodeStateid(e, 1, [12]byte{})
		e.Uint32(1)
		e.Uint64(1)
		e.Opaque([]byte("lock-owner"))
		return 2
	})))

	f.Fuzz(func(t *testing.T, record []byte) {
		if len(record) > 1<<16 {
			t.Skip()
		}
		server, client := net.Pipe()
		s := &Server{FileSystem: facetfs.NewMemFS()}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- s.ServeConn(ctx, server) }()

		client.SetDeadline(time.Now().Add(5 * time.Second))
		if err := writeRecord(client, record); err == nil {
			// Drain whatever the server chooses to answer, then close.
			readRecord(client, 1<<24)
		}
		client.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("ServeConn did not return: the server hung on this input")
		}
	})
}

// compoundRecord frames a COMPOUND call as one RPC record body.
func compoundRecord(xid uint32, args []byte) []byte {
	var e xdr.Encoder
	e.Uint32(xid)
	e.Uint32(msgCall)
	e.Uint32(rpcVersion)
	e.Uint32(nfsProgram)
	e.Uint32(nfsVersion)
	e.Uint32(procCompound)
	e.Uint32(authNone)
	e.Opaque(nil)
	e.Uint32(authNone)
	e.Opaque(nil)
	e.OpaqueFixed(args)
	return e.Bytes()
}
