package smb

import (
	"encoding/binary"
	"time"
)

var protocolID = [4]byte{0xFE, 'S', 'M', 'B'}

// smb1ProtocolID starts an SMB1 message. The server recognizes it only far
// enough to answer the multi-protocol NEGOTIATE in SMB2: it must never parse
// SMB1 beyond that one dialect list.
var smb1ProtocolID = [4]byte{0xFF, 'S', 'M', 'B'}

// header is the fixed 64-byte SMB2 header ([MS-SMB2] section 2.2.1.2).
type header struct {
	creditCharge uint16
	status       uint32
	command      uint16
	credits      uint16
	flags        uint32
	nextCommand  uint32
	messageID    uint64
	treeID       uint32
	sessionID    uint64
	signature    [16]byte
}

func decodeHeader(b []byte) (header, bool) {
	if len(b) < headerSize {
		return header{}, false
	}
	if [4]byte(b[0:4]) != protocolID {
		return header{}, false
	}
	if binary.LittleEndian.Uint16(b[4:]) != headerSize {
		return header{}, false
	}
	return header{
		creditCharge: binary.LittleEndian.Uint16(b[6:]),
		status:       binary.LittleEndian.Uint32(b[8:]),
		command:      binary.LittleEndian.Uint16(b[12:]),
		credits:      binary.LittleEndian.Uint16(b[14:]),
		flags:        binary.LittleEndian.Uint32(b[16:]),
		nextCommand:  binary.LittleEndian.Uint32(b[20:]),
		messageID:    binary.LittleEndian.Uint64(b[24:]),
		treeID:       binary.LittleEndian.Uint32(b[36:]),
		sessionID:    binary.LittleEndian.Uint64(b[40:]),
		signature:    [16]byte(b[48:64]),
	}, true
}

// encode writes the header into a fresh 64-byte slice. The signature stays
// zero: signing runs over the assembled response.
func (h header) encode() []byte {
	b := make([]byte, headerSize)
	copy(b, protocolID[:])
	binary.LittleEndian.PutUint16(b[4:], headerSize)
	binary.LittleEndian.PutUint16(b[6:], h.creditCharge)
	binary.LittleEndian.PutUint32(b[8:], h.status)
	binary.LittleEndian.PutUint16(b[12:], h.command)
	binary.LittleEndian.PutUint16(b[14:], h.credits)
	binary.LittleEndian.PutUint32(b[16:], h.flags)
	binary.LittleEndian.PutUint32(b[20:], h.nextCommand)
	binary.LittleEndian.PutUint64(b[24:], h.messageID)
	binary.LittleEndian.PutUint32(b[36:], h.treeID)
	binary.LittleEndian.PutUint64(b[40:], h.sessionID)
	copy(b[48:], h.signature[:])
	return b
}

// message is one SMB2 message inside a frame: its header, its body, and the
// bytes of both. [MS-SMB2] measures nearly every offset from the start of the
// header, and a chained message does not start the frame, so raw is what
// those offsets index.
type message struct {
	hdr           header
	raw           []byte
	body          []byte
	relatedFileID *[16]byte
	resultFileID  *[16]byte
	closeSession  *session
}

// slice returns the region an offset and length pair names. Every such pair
// in the protocol goes through here: it is the package's memory-safety
// surface, and no call site may index raw itself.
func (m *message) slice(offset, length, max uint32) ([]byte, bool) {
	if length == 0 {
		return nil, true
	}
	if length > max || offset < headerSize {
		return nil, false
	}
	end := uint64(offset) + uint64(length)
	if end > uint64(len(m.raw)) {
		return nil, false
	}
	return m.raw[offset:end], true
}

// fileTimeEpoch is the offset between the Unix epoch and the Windows FILETIME
// epoch of 1601-01-01, in 100-nanosecond intervals.
const fileTimeEpoch = 116444736000000000

func fileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	v := t.UnixNano()/100 + fileTimeEpoch
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// align8 rounds up to the 8-byte boundary [MS-SMB2] requires between chained
// messages and between negotiate contexts.
func align8(n int) int { return (n + 7) &^ 7 }
