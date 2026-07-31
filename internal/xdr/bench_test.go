package xdr

import "testing"

func BenchmarkDecoder(b *testing.B) {
	var e Encoder
	for range 64 {
		e.Uint32(7)
		e.Uint64(1 << 40)
		e.String("a name of moderate length")
	}
	buf := e.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		d := NewDecoder(buf)
		for range 64 {
			d.Uint32()
			d.Uint64()
			d.String(64)
		}
		if d.Err() != nil {
			b.Fatal(d.Err())
		}
	}
}

func BenchmarkEncoder(b *testing.B) {
	payload := make([]byte, 256)
	b.ReportAllocs()
	for b.Loop() {
		var e Encoder
		for range 64 {
			e.Uint32(7)
			e.Uint64(1 << 40)
			e.Opaque(payload)
		}
		if e.Len() == 0 {
			b.Fatal("empty")
		}
	}
}
