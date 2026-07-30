package xdr

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var e Encoder
	e.Uint32(7)
	e.Uint64(1 << 40)
	e.Bool(true)
	e.Bool(false)
	e.Opaque([]byte("abc"))
	e.String("hello")
	e.OpaqueFixed([]byte{1, 2, 3, 4, 5})

	if e.Len()%4 != 0 {
		t.Fatalf("encoded length %d is not a multiple of 4", e.Len())
	}

	d := NewDecoder(e.Bytes())
	if got := d.Uint32(); got != 7 {
		t.Fatalf("Uint32 = %d", got)
	}
	if got := d.Uint64(); got != 1<<40 {
		t.Fatalf("Uint64 = %d", got)
	}
	if !d.Bool() || d.Bool() {
		t.Fatal("Bool round trip failed")
	}
	if got := d.Opaque(16); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("Opaque = %q", got)
	}
	if got := d.String(16); got != "hello" {
		t.Fatalf("String = %q", got)
	}
	if got := d.OpaqueFixed(5); !bytes.Equal(got, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("OpaqueFixed = %v", got)
	}
	if d.Err() != nil || d.Remaining() != 0 {
		t.Fatalf("err = %v, remaining = %d", d.Err(), d.Remaining())
	}
}

func TestDecoderBounds(t *testing.T) {
	var e Encoder
	e.Opaque(make([]byte, 32))
	d := NewDecoder(e.Bytes())
	if d.Opaque(16) != nil || !errors.Is(d.Err(), ErrBound) {
		t.Fatalf("over-bound Opaque: err = %v", d.Err())
	}
	// The error sticks.
	if d.Uint32() != 0 || !errors.Is(d.Err(), ErrBound) {
		t.Fatalf("sticky error lost: %v", d.Err())
	}
}

func TestDecoderShort(t *testing.T) {
	d := NewDecoder([]byte{0, 0})
	if d.Uint32() != 0 || !errors.Is(d.Err(), ErrShort) {
		t.Fatalf("short Uint32: err = %v", d.Err())
	}

	// Declared length larger than the remaining buffer.
	var e Encoder
	e.Uint32(100)
	d = NewDecoder(e.Bytes())
	if d.Opaque(200) != nil || !errors.Is(d.Err(), ErrShort) {
		t.Fatalf("truncated Opaque: err = %v", d.Err())
	}
}

func TestDecoderBadBool(t *testing.T) {
	var e Encoder
	e.Uint32(2)
	d := NewDecoder(e.Bytes())
	if d.Bool() || !errors.Is(d.Err(), ErrValue) {
		t.Fatalf("Bool(2): err = %v", d.Err())
	}
}

func TestPadding(t *testing.T) {
	for n := 0; n <= 8; n++ {
		var e Encoder
		e.Opaque(make([]byte, n))
		if e.Len() != 4+n+int(pad(uint32(n))) || e.Len()%4 != 0 {
			t.Fatalf("Opaque(%d) encoded to %d bytes", n, e.Len())
		}
		d := NewDecoder(e.Bytes())
		if got := d.Opaque(16); len(got) != n || d.Err() != nil || d.Remaining() != 0 {
			t.Fatalf("Opaque(%d) round trip: len %d, err %v, remaining %d", n, len(got), d.Err(), d.Remaining())
		}
	}
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte{}, uint32(16))
	f.Add([]byte{0, 0, 0, 3, 'a', 'b', 'c', 0}, uint32(3))
	f.Add(bytes.Repeat([]byte{0xff}, 64), uint32(8))
	f.Fuzz(func(t *testing.T, data []byte, max uint32) {
		max %= 1 << 20
		d := NewDecoder(data)
		for d.Err() == nil && d.Remaining() > 0 {
			before := d.off
			switch before % 5 {
			case 0:
				d.Uint32()
			case 1:
				d.Uint64()
			case 2:
				d.Bool()
			case 3:
				d.Opaque(max)
			case 4:
				d.String(max)
			}
			if d.err == nil && d.off <= before {
				t.Fatalf("offset did not advance: %d -> %d", before, d.off)
			}
			if d.off > len(d.buf) {
				t.Fatalf("offset %d beyond buffer %d", d.off, len(d.buf))
			}
		}
	})
}
