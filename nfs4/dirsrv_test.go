package nfs4

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// benchDirRead measures a READ against a real directory, so the numbers
// include the Dir adapter and the operating system, not just the protocol.
func benchDirRead(b *testing.B, size int) {
	tmp := b.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "data"), make([]byte, size), 0o644); err != nil {
		b.Fatal(err)
	}
	bc := newBenchConn(b, facetfs.Dir(tmp))
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

func BenchmarkDirRead64K(b *testing.B) { benchDirRead(b, 64<<10) }
func BenchmarkDirRead1M(b *testing.B)  { benchDirRead(b, 1<<20) }

func BenchmarkDirGetattr(b *testing.B) {
	tmp := b.TempDir()
	os.WriteFile(filepath.Join(tmp, "data"), []byte("x"), 0o644)
	bc := newBenchConn(b, facetfs.Dir(tmp))
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
