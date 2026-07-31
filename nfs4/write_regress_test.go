package nfs4

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// newSizedClient serves fsys with explicit transfer limits.
func newSizedClient(t *testing.T, fsys facetfs.FileSystem, maxRead, maxWrite uint32) *testClient {
	t.Helper()
	server, client := net.Pipe()
	s := &Server{FileSystem: fsys, MaxReadBytes: maxRead, MaxWriteBytes: maxWrite}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(ctx, server) }()
	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})
	client.SetDeadline(time.Now().Add(30 * time.Second))
	return &testClient{t: t, c: client}
}

// A WRITE of exactly the advertised maxwrite must be served. The record cap
// was once a fixed constant equal to the advertised size, so the framing
// overhead pushed every full-size write past it and killed the connection.
func TestWriteAtAdvertisedMaxWrite(t *testing.T) {
	for _, maxWrite := range []uint32{0, 64 << 10, 1 << 20} {
		fsys := facetfs.NewMemFS()
		f, err := fsys.OpenFile(t.Context(), "/big", os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		tc := newSizedClient(t, fsys, 0, maxWrite)

		advertised := maxWrite
		if advertised == 0 {
			advertised = defaultMaxIO
		}
		payload := bytes.Repeat([]byte{0xab}, int(advertised))
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opLookup)
			encodeName(e, "big")
			e.Uint32(opWrite)
			encodeStateid(e, 0, [12]byte{})
			e.Uint64(0)
			e.Uint32(unstable4)
			e.Opaque(payload)
			return 3
		})
		if st != nfs4OK {
			t.Fatalf("MaxWriteBytes=%d: WRITE of %d bytes = %d, want OK", maxWrite, len(payload), st)
		}
		expectOp(t, d, opPutRootFH, nfs4OK)
		expectOp(t, d, opLookup, nfs4OK)
		expectOp(t, d, opWrite, nfs4OK)
		if n := d.Uint32(); n != advertised {
			t.Fatalf("MaxWriteBytes=%d: wrote %d bytes, want %d", maxWrite, n, advertised)
		}

		fi, err := fsys.Stat(t.Context(), "/big")
		if err != nil || fi.Size() != int64(advertised) {
			t.Fatalf("MaxWriteBytes=%d: file size = %v (%v)", maxWrite, fi, err)
		}
	}
}

// The advertised maxwrite must equal what the server will actually accept.
func TestAdvertisedMaxWriteMatchesRecordCap(t *testing.T) {
	for _, maxWrite := range []uint32{0, 64 << 10, 4 << 20} {
		s := &Server{FileSystem: facetfs.NewMemFS(), MaxWriteBytes: maxWrite}
		if s.requestCap() < int(s.maxWrite()) {
			t.Fatalf("MaxWriteBytes=%d: record cap %d is below the advertised maxwrite %d",
				maxWrite, s.requestCap(), s.maxWrite())
		}
	}
}
