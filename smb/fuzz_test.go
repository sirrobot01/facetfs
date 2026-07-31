package smb

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/sirrobot01/facetfs"
)

// fuzzServer is shared by the unauthenticated decoder targets. Reusing it
// keeps the iteration cost focused on the wire handling under test.
func fuzzServer(tb testing.TB) *Server {
	tb.Helper()
	s := &Server{FileSystem: facetfs.NewMemFS(), Authenticator: stubAuth{}}
	if err := s.init(); err != nil {
		tb.Fatal(err)
	}
	return s
}

// FuzzHandleFrame drives one whole frame through the header decode, the
// compound chain walk, the credit and message-id rules, and the commands.
// The decoders are hand written, so this is the target that covers the offset
// and length pairs the protocol is built from.
//
// It runs against the connection rather than a socket: the reply path is
// synchronous, so the iteration explores parsing instead of scheduling.
func FuzzHandleFrame(f *testing.F) {
	f.Add(append(header{command: cmdNegotiate, credits: 1}.encode(),
		negotiateRequest([]uint16{dialect311, dialect210}, true)...))
	f.Add(append(header{command: cmdNegotiate, credits: 1}.encode(),
		negotiateRequest([]uint16{dialect210}, false)...))
	f.Add(append(header{command: cmdEcho, credits: 1}.encode(), echoRequest()...))
	f.Add(header{command: cmdCancel}.encode())
	f.Add(header{command: cmdTreeConnect}.encode())
	f.Add(make([]byte, headerSize))
	f.Add([]byte{})

	chained := append(header{command: cmdEcho, credits: 1, nextCommand: 72}.encode(), echoRequest()...)
	chained = append(chained, make([]byte, 72-len(chained))...)
	f.Add(append(chained, append(header{command: cmdEcho, credits: 1, messageID: 1,
		flags: flagRelatedOps}.encode(), echoRequest()...)...))

	s := fuzzServer(f)
	f.Fuzz(func(t *testing.T, frame []byte) {
		conn := &connection{s: s, credits: maxCredits}
		defer s.state.closeConnection(conn)
		reply, ok, _ := conn.handleFrame(t.Context(), frame)
		if !ok {
			if reply != nil {
				t.Fatal("a refused frame produced a reply")
			}
			return
		}
		checkReplyChain(t, reply)
	})
}

// checkReplyChain asserts the server described its own reply correctly. A
// client walks the chain exactly this way, so a chain that does not walk is a
// fault however well the request parsed.
func checkReplyChain(t *testing.T, reply []byte) {
	t.Helper()
	if reply == nil {
		return
	}
	for count := 0; ; count++ {
		if count > maxChainedMessages {
			t.Fatalf("reply chains more than %d messages", maxChainedMessages)
		}
		h, ok := decodeHeader(reply)
		if !ok {
			t.Fatalf("reply message %d does not decode: %x", count, reply)
		}
		if h.flags&flagServerToRedir == 0 {
			t.Fatalf("reply message %d is not marked as a response", count)
		}
		if h.credits < 1 {
			t.Fatalf("reply message %d granted no credits, so the client would stall", count)
		}
		if h.nextCommand == 0 {
			return
		}
		next := int(h.nextCommand)
		if next%8 != 0 || next < headerSize || next > len(reply) {
			t.Fatalf("reply message %d chains to %d in a %d byte reply", count, next, len(reply))
		}
		reply = reply[next:]
	}
}

// FuzzReadFrame drives the transport framing alone.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 64})
	f.Add(append([]byte{0, 0, 0, 64}, make([]byte, 64)...))
	f.Add([]byte{0, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{1, 0, 0, 64})

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := readFrame(bytes.NewReader(data), 1<<16)
		if err != nil {
			return
		}
		if len(frame) < smb1MinNegotiate || len(frame) > 1<<16 {
			t.Fatalf("accepted a %d byte frame", len(frame))
		}
		if len(frame)+transportHeaderSize > len(data) {
			t.Fatalf("accepted a %d byte frame from %d bytes", len(frame), len(data))
		}
	})
}

// FuzzNegotiate drives the negotiation alone, which reaches the context walk
// far more often than a whole frame does.
func FuzzNegotiate(f *testing.F) {
	f.Add(negotiateRequest([]uint16{dialect311, dialect210}, true))
	f.Add(negotiateRequest([]uint16{dialect210}, false))
	f.Add(make([]byte, 36))

	s := fuzzServer(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		conn := &connection{s: s, credits: 1}
		frame := append(header{command: cmdNegotiate}.encode(), body...)
		m := &message{
			hdr:  header{command: cmdNegotiate},
			raw:  frame,
			body: frame[headerSize:],
		}
		reply, status := conn.negotiate(m)
		if status != statusSuccess {
			return
		}
		// A successful negotiation must describe itself consistently: every
		// offset it reports has to stay inside the message it belongs to.
		if len(reply) < 64 {
			t.Fatalf("accepted NEGOTIATE produced a %d byte body", len(reply))
		}
		if conn.dialect != dialect210 && conn.dialect != dialect311 {
			t.Fatalf("settled on dialect %#x", conn.dialect)
		}
		securityOffset := int(binary.LittleEndian.Uint16(reply[56:]))
		securityLength := int(binary.LittleEndian.Uint16(reply[58:]))
		if securityOffset < headerSize || securityOffset-headerSize+securityLength > len(reply) {
			t.Fatalf("security buffer at %d for %d bytes leaves a %d byte body",
				securityOffset, securityLength, len(reply))
		}
		contextOffset := int(binary.LittleEndian.Uint32(reply[60:]))
		if contextOffset == 0 {
			return
		}
		if contextOffset%8 != 0 || contextOffset-headerSize > len(reply) {
			t.Fatalf("contexts at %d leave a %d byte body", contextOffset, len(reply))
		}
		// Every context the server built must walk back out again.
		block := reply[contextOffset-headerSize:]
		for pos := 0; pos+8 <= len(block); {
			length := int(binary.LittleEndian.Uint16(block[pos+2:]))
			if pos+8+length > len(block) {
				t.Fatalf("a context of %d bytes at %d leaves a %d byte block", length, pos, len(block))
			}
			pos = align8(pos + 8 + length)
		}
	})
}

func FuzzNTLMAndPaths(f *testing.F) {
	f.Add(type1Message())
	f.Add(utf16Bytes("dir\\file.txt"))
	f.Add([]byte{})
	auth := passwordAuth{hashes: map[string][]byte{"DOMAIN\\alice": NTHash("password")}}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ntlmToken(data)
		var challenge [8]byte
		_, _ = authenticateNTLM(t.Context(), auth, data, challenge)
		_, _ = smbPath(data)
		_ = validCreateContexts(data)
	})
}
