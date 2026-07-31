package nfs4

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// benchConn drives one server over a loopback connection. Requests are
// encoded once so the measurement is the server's cost, not the harness's.
type benchConn struct {
	conn  net.Conn
	reply []byte
}

func newBenchConn(b *testing.B, fsys facetfs.FileSystem) *benchConn {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	s := &Server{FileSystem: fsys}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		s.Serve(ctx, listener)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		b.Fatal(err)
	}
	b.Cleanup(func() {
		conn.Close()
		cancel()
		listener.Close()
		<-served
	})
	return &benchConn{conn: conn, reply: make([]byte, 0, 1<<21)}
}

// roundTrip sends a pre-encoded record and reads the whole reply.
func (bc *benchConn) roundTrip(b *testing.B, record []byte) *xdr.Decoder {
	b.Helper()
	if err := writeRecord(bc.conn, record); err != nil {
		b.Fatal(err)
	}
	reply, err := readRecord(bc.conn, 1<<24)
	if err != nil {
		b.Fatal(err)
	}
	return xdr.NewDecoder(reply)
}

// benchRecord encodes one COMPOUND call as an RPC record body.
func benchRecord(ops func(*xdr.Encoder) uint32) []byte {
	return compoundRecord(1, compoundArgs("", 0, ops))
}

// expectOK asserts the compound succeeded without decoding the results.
func expectOK(b *testing.B, d *xdr.Decoder) {
	b.Helper()
	d.Uint32() // xid
	d.Uint32() // mtype
	d.Uint32() // reply_stat
	d.Uint32() // verifier flavor
	d.Opaque(maxCredBytes)
	d.Uint32() // accept_stat
	if st := nfsStat(d.Uint32()); st != nfs4OK {
		b.Fatalf("compound status = %d", st)
	}
}

func benchFS(b *testing.B, size int) (facetfs.FileSystem, []byte) {
	b.Helper()
	fsys := facetfs.NewMemFS()
	f, err := fsys.OpenFile(context.Background(), "/data", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	if size > 0 {
		if _, err := f.Write(make([]byte, size)); err != nil {
			b.Fatal(err)
		}
	}
	f.Close()
	return fsys, nil
}

// BenchmarkGetattr measures the common metadata round trip: resolve a name
// and read its attributes.
func BenchmarkGetattr(b *testing.B) {
	fsys, _ := benchFS(b, 1024)
	bc := newBenchConn(b, fsys)
	var attrs bitmap
	for _, n := range []int{attrType, attrSize, attrChange, attrFileID, attrMode, attrTimeModify} {
		attrs.set(n)
	}
	record := benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opGetAttr)
		encodeBitmap(e, attrs)
		return 3
	})

	b.ReportAllocs()
	for b.Loop() {
		expectOK(b, bc.roundTrip(b, record))
	}
}

func benchRead(b *testing.B, size int) {
	fsys, _ := benchFS(b, size)
	bc := newBenchConn(b, fsys)
	record := benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opRead)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(uint32(size))
		return 3
	})

	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		expectOK(b, bc.roundTrip(b, record))
	}
}

func BenchmarkRead4K(b *testing.B)  { benchRead(b, 4<<10) }
func BenchmarkRead64K(b *testing.B) { benchRead(b, 64<<10) }
func BenchmarkRead1M(b *testing.B)  { benchRead(b, 1<<20) }

func benchWrite(b *testing.B, size int) {
	fsys, _ := benchFS(b, 0)
	bc := newBenchConn(b, fsys)
	payload := make([]byte, size)
	record := benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "data")
		e.Uint32(opWrite)
		encodeStateid(e, 0, [12]byte{})
		e.Uint64(0)
		e.Uint32(unstable4)
		e.Opaque(payload)
		return 3
	})

	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		expectOK(b, bc.roundTrip(b, record))
	}
}

func BenchmarkWrite4K(b *testing.B)  { benchWrite(b, 4<<10) }
func BenchmarkWrite64K(b *testing.B) { benchWrite(b, 64<<10) }
func BenchmarkWrite1M(b *testing.B)  { benchWrite(b, 1<<20) }

// benchReaddir lists a whole directory. A resume re-walks the directory and
// skips what it already sent, so the cost of a full listing grows with the
// square of the entry count once it needs more than one page.
func benchReaddir(b *testing.B, entries int, maxcount uint32) {
	fsys := facetfs.NewMemFS()
	ctx := context.Background()
	for i := range entries {
		f, err := fsys.OpenFile(ctx, fmt.Sprintf("/entry-%05d", i), os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			b.Fatal(err)
		}
		f.Close()
	}
	bc := newBenchConn(b, fsys)
	var attrs bitmap
	attrs.set(attrType)
	attrs.set(attrFileID)

	b.ReportAllocs()
	for b.Loop() {
		cookie := uint64(0)
		verf := make([]byte, 8)
		for pages := 0; ; pages++ {
			if pages > entries+2 {
				b.Fatal("listing did not finish")
			}
			record := benchRecord(func(e *xdr.Encoder) uint32 {
				e.Uint32(opPutRootFH)
				e.Uint32(opReadDir)
				e.Uint64(cookie)
				e.OpaqueFixed(verf)
				e.Uint32(1 << 20)
				e.Uint32(maxcount)
				encodeBitmap(e, attrs)
				return 2
			})
			d := bc.roundTrip(b, record)
			expectOK(b, d)
			d.Opaque(maxTagBytes)
			d.Uint32() // result count
			d.Uint32() // PUTROOTFH op
			d.Uint32() // PUTROOTFH status
			d.Uint32() // READDIR op
			if st := nfsStat(d.Uint32()); st != nfs4OK {
				b.Fatalf("READDIR status = %d", st)
			}
			verf = append(verf[:0], d.OpaqueFixed(8)...)
			for d.Bool() {
				cookie = d.Uint64()
				d.String(maxNameBytes)
				decodeBitmap(d)
				d.Opaque(1 << 16)
			}
			if d.Bool() {
				break
			}
		}
	}
}

// One page holds the whole listing.
func BenchmarkReaddir100Paged(b *testing.B)  { benchReaddir(b, 100, 1<<20) }
func BenchmarkReaddir1000Paged(b *testing.B) { benchReaddir(b, 1000, 1<<20) }

// A small reply size forces many resumes, which is what real clients do.
func BenchmarkReaddir100Resumed(b *testing.B)  { benchReaddir(b, 100, 8<<10) }
func BenchmarkReaddir1000Resumed(b *testing.B) { benchReaddir(b, 1000, 8<<10) }

// benchGetattrWithClients measures how the per-request lease sweep scales
// with the number of registered clients.
func benchGetattrWithClients(b *testing.B, clients int) {
	fsys, _ := benchFS(b, 1024)
	bc := newBenchConn(b, fsys)
	for i := range clients {
		record := benchRecord(func(e *xdr.Encoder) uint32 {
			e.Uint32(opSetClientID)
			e.OpaqueFixed([]byte("verifier"))
			e.Opaque(fmt.Appendf(nil, "bench-client-%d", i))
			e.Uint32(0)
			e.String("tcp")
			e.String("0.0.0.0.0.0")
			e.Uint32(0)
			return 1
		})
		d := bc.roundTrip(b, record)
		expectOK(b, d)
		d.Opaque(maxTagBytes)
		d.Uint32()
		d.Uint32()
		d.Uint32()
		id := d.Uint64()
		confirm := append([]byte(nil), d.OpaqueFixed(8)...)
		confirmRecord := benchRecord(func(e *xdr.Encoder) uint32 {
			e.Uint32(opSetClientIDConfirm)
			e.Uint64(id)
			e.OpaqueFixed(confirm)
			return 1
		})
		expectOK(b, bc.roundTrip(b, confirmRecord))
	}

	var attrs bitmap
	attrs.set(attrSize)
	record := benchRecord(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opGetAttr)
		encodeBitmap(e, attrs)
		return 2
	})
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		expectOK(b, bc.roundTrip(b, record))
	}
}

func BenchmarkGetattr1Client(b *testing.B)    { benchGetattrWithClients(b, 1) }
func BenchmarkGetattr100Clients(b *testing.B) { benchGetattrWithClients(b, 100) }
func BenchmarkGetattr500Clients(b *testing.B) { benchGetattrWithClients(b, 500) }

// The resume cost grows with the square of the entry count: each page
// re-walks every entry before it.
func BenchmarkReaddirScale500(b *testing.B)  { benchReaddir(b, 500, 8<<10) }
func BenchmarkReaddirScale2000(b *testing.B) { benchReaddir(b, 2000, 8<<10) }
func BenchmarkReaddirScale4000(b *testing.B) { benchReaddir(b, 4000, 8<<10) }

// benchSweep isolates the lease sweep from network noise.
func benchSweep(b *testing.B, clients int, gated bool) {
	store := newStateStore(90 * time.Second)
	for i := range clients {
		id, confirm, st := store.setClientID(fmt.Sprintf("sweep-%d", i), [8]byte{}, "none", callbackPath{})
		if _, cst := store.confirmClientID(id, confirm); st != nfs4OK || cst != nfs4OK {
			b.Fatal("could not register client")
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		if gated {
			store.sweepDue()
		} else {
			store.sweepExpired()
		}
	}
}

func BenchmarkSweepUngated100(b *testing.B)  { benchSweep(b, 100, false) }
func BenchmarkSweepUngated1000(b *testing.B) { benchSweep(b, 1000, false) }
func BenchmarkSweepGated100(b *testing.B)    { benchSweep(b, 100, true) }
func BenchmarkSweepGated1000(b *testing.B)   { benchSweep(b, 1000, true) }
