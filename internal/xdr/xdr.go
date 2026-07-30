// Package xdr implements the XDR primitives of RFC 4506 over byte buffers.
// Every variable-length decode takes an explicit bound at the call site so the
// package's callers stay auditable for unbounded allocation.
package xdr

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrShort reports a read past the end of the buffer.
	ErrShort = errors.New("xdr: short buffer")
	// ErrBound reports a declared length above the caller's bound.
	ErrBound = errors.New("xdr: length exceeds bound")
	// ErrValue reports an encoding that XDR forbids, such as a boolean
	// other than 0 or 1.
	ErrValue = errors.New("xdr: invalid value")
)

// Decoder reads XDR values from a buffer. The first error sticks: after a
// failed read every method returns a zero value and Err reports the failure.
type Decoder struct {
	buf []byte
	off int
	err error
}

func NewDecoder(buf []byte) *Decoder {
	return &Decoder{buf: buf}
}

func (d *Decoder) Err() error     { return d.err }
func (d *Decoder) Remaining() int { return len(d.buf) - d.off }

func (d *Decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *Decoder) Uint32() uint32 {
	if d.err != nil {
		return 0
	}
	if d.Remaining() < 4 {
		d.fail(ErrShort)
		return 0
	}
	v := binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v
}

func (d *Decoder) Uint64() uint64 {
	if d.err != nil {
		return 0
	}
	if d.Remaining() < 8 {
		d.fail(ErrShort)
		return 0
	}
	v := binary.BigEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v
}

func (d *Decoder) Bool() bool {
	switch d.Uint32() {
	case 0:
		return false
	case 1:
		return true
	default:
		d.fail(ErrValue)
		return false
	}
}

// OpaqueFixed reads n bytes plus padding. The returned slice aliases the
// decode buffer.
func (d *Decoder) OpaqueFixed(n uint32) []byte {
	if d.err != nil {
		return nil
	}
	padded := int64(n) + int64(pad(n))
	if int64(d.Remaining()) < padded {
		d.fail(ErrShort)
		return nil
	}
	b := d.buf[d.off : d.off+int(n)]
	d.off += int(padded)
	return b
}

// Opaque reads a variable-length opaque whose declared length must not exceed
// max.
func (d *Decoder) Opaque(max uint32) []byte {
	n := d.Uint32()
	if d.err != nil {
		return nil
	}
	if n > max {
		d.fail(ErrBound)
		return nil
	}
	return d.OpaqueFixed(n)
}

func (d *Decoder) String(max uint32) string {
	return string(d.Opaque(max))
}

// Skip discards n bytes plus padding.
func (d *Decoder) Skip(n uint32) {
	d.OpaqueFixed(n)
}

// Encoder appends XDR values to a buffer.
type Encoder struct {
	b []byte
}

func (e *Encoder) Len() int      { return len(e.b) }
func (e *Encoder) Bytes() []byte { return e.b }

// Truncate discards everything encoded after offset n.
func (e *Encoder) Truncate(n int) {
	e.b = e.b[:n]
}

func (e *Encoder) Uint32(v uint32) {
	e.b = binary.BigEndian.AppendUint32(e.b, v)
}

func (e *Encoder) Uint64(v uint64) {
	e.b = binary.BigEndian.AppendUint64(e.b, v)
}

func (e *Encoder) Bool(v bool) {
	if v {
		e.Uint32(1)
	} else {
		e.Uint32(0)
	}
}

// OpaqueFixed writes b plus padding without a length prefix.
func (e *Encoder) OpaqueFixed(b []byte) {
	e.b = append(e.b, b...)
	e.b = append(e.b, make([]byte, pad(uint32(len(b))))...)
}

func (e *Encoder) Opaque(b []byte) {
	e.Uint32(uint32(len(b)))
	e.OpaqueFixed(b)
}

func (e *Encoder) String(s string) {
	e.Uint32(uint32(len(s)))
	e.b = append(e.b, s...)
	e.b = append(e.b, make([]byte, pad(uint32(len(s))))...)
}

func pad(n uint32) uint32 {
	return (4 - n%4) % 4
}
