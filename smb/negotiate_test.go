package smb

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/sirrobot01/facetfs"
)

// negotiateResponse is the decoded fixed part of a NEGOTIATE response, plus
// the two variable blocks that follow it.
type negotiateResponse struct {
	securityMode   uint16
	dialect        uint16
	contextCount   uint16
	capabilities   uint32
	maxTransact    uint32
	maxRead        uint32
	maxWrite       uint32
	securityBuffer []byte
	contexts       []byte
}

// parseNegotiate reads a NEGOTIATE response body. The offsets it carries are
// measured from the start of the SMB2 header, so the body index is the offset
// less the header.
func parseNegotiate(t *testing.T, body []byte) negotiateResponse {
	t.Helper()
	if len(body) < 64 {
		t.Fatalf("NEGOTIATE body is %d bytes, want at least 64", len(body))
	}
	if got := binary.LittleEndian.Uint16(body[0:]); got != 65 {
		t.Fatalf("StructureSize = %d, want 65", got)
	}
	r := negotiateResponse{
		securityMode: binary.LittleEndian.Uint16(body[2:]),
		dialect:      binary.LittleEndian.Uint16(body[4:]),
		contextCount: binary.LittleEndian.Uint16(body[6:]),
		capabilities: binary.LittleEndian.Uint32(body[24:]),
		maxTransact:  binary.LittleEndian.Uint32(body[28:]),
		maxRead:      binary.LittleEndian.Uint32(body[32:]),
		maxWrite:     binary.LittleEndian.Uint32(body[36:]),
	}
	securityOffset := int(binary.LittleEndian.Uint16(body[56:]))
	securityLength := int(binary.LittleEndian.Uint16(body[58:]))
	if securityOffset < headerSize || securityOffset-headerSize+securityLength > len(body) {
		t.Fatalf("security buffer at %d for %d bytes leaves the body", securityOffset, securityLength)
	}
	r.securityBuffer = body[securityOffset-headerSize : securityOffset-headerSize+securityLength]
	if contextOffset := int(binary.LittleEndian.Uint32(body[60:])); contextOffset != 0 {
		if contextOffset%8 != 0 {
			t.Fatalf("negotiate contexts at %d are not 8-byte aligned", contextOffset)
		}
		if contextOffset-headerSize > len(body) {
			t.Fatalf("negotiate contexts at %d leave the body", contextOffset)
		}
		r.contexts = body[contextOffset-headerSize:]
	}
	return r
}

func TestNegotiatePrefersLatestDialect(t *testing.T) {
	tests := []struct {
		name     string
		offered  []uint16
		contexts bool
		want     uint16
	}{
		{"3.1.1 preferred over 2.1", []uint16{dialect210, dialect311}, true, dialect311},
		{"2.1 when it is alone", []uint16{dialect210}, false, dialect210},
		{"2.1 when the rest are unserved", []uint16{dialect202, dialect210, dialect300, dialect302}, false, dialect210},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestClient(t)
			h, body := tc.negotiate(tt.offered, tt.contexts)
			if h.status != statusSuccess {
				t.Fatalf("NEGOTIATE status = %#x", h.status)
			}
			if got := parseNegotiate(t, body).dialect; got != tt.want {
				t.Fatalf("dialect = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestNegotiateRefusesUnknownDialects(t *testing.T) {
	tc := newTestClient(t)
	// SMB 2.0.2 and 3.0 are recognized but not served, so a client offering
	// only those gets nothing.
	h, _ := tc.negotiate([]uint16{dialect202, dialect300, 0x0999}, false)
	if h.status != statusNotSupported {
		t.Fatalf("status = %#x, want STATUS_NOT_SUPPORTED", h.status)
	}
}

func TestNegotiateAdvertisesOnlyWhatItServes(t *testing.T) {
	tc := newTestClient(t)
	_, body := tc.negotiate([]uint16{dialect311}, true)
	r := parseNegotiate(t, body)
	if r.capabilities != capLargeMTU {
		t.Fatalf("capabilities = %#x, want large MTU only", r.capabilities)
	}
	for _, unwanted := range []struct {
		name string
		bit  uint32
	}{
		{"leasing", capLeasing},
		{"encryption", capEncryption},
		{"multichannel", capMultiChannel},
		{"persistent handles", capPersistentHandles},
		{"directory leasing", capDirectoryLeasing},
		{"DFS", capDFS},
	} {
		if r.capabilities&unwanted.bit != 0 {
			t.Errorf("the server advertised %s, which it does not implement", unwanted.name)
		}
	}
	if r.maxRead != defaultMaxIO || r.maxWrite != defaultMaxIO || r.maxTransact != defaultMaxIO {
		t.Errorf("sizes = read %d, write %d, transact %d", r.maxRead, r.maxWrite, r.maxTransact)
	}
	if !bytes.Equal(r.securityBuffer, spnegoNegTokenInit) {
		t.Errorf("security buffer = %x, want the SPNEGO token", r.securityBuffer)
	}
}

func TestNegotiateSizesFollowTheServer(t *testing.T) {
	tc := newTestClientFor(t, &Server{
		FileSystem:       facetfs.NewMemFS(),
		Authenticator:    stubAuth{},
		MaxReadBytes:     1 << 16,
		MaxWriteBytes:    1 << 17,
		MaxTransactBytes: 1 << 18,
	})
	_, body := tc.negotiate([]uint16{dialect210}, false)
	r := parseNegotiate(t, body)
	if r.maxRead != 1<<16 || r.maxWrite != 1<<17 || r.maxTransact != 1<<18 {
		t.Fatalf("sizes = read %d, write %d, transact %d", r.maxRead, r.maxWrite, r.maxTransact)
	}
}

func TestNegotiateAnswersRequiredContexts(t *testing.T) {
	tc := newTestClient(t)
	_, body := tc.negotiate([]uint16{dialect311}, true)
	r := parseNegotiate(t, body)
	if r.dialect != dialect311 {
		t.Fatalf("dialect = %#x", r.dialect)
	}
	if r.contextCount != 2 {
		t.Fatalf("context count = %d, want 2", r.contextCount)
	}

	seen := map[uint16][]byte{}
	for pos := 0; pos+8 <= len(r.contexts); {
		ctype := binary.LittleEndian.Uint16(r.contexts[pos:])
		length := int(binary.LittleEndian.Uint16(r.contexts[pos+2:]))
		if pos+8+length > len(r.contexts) {
			t.Fatalf("context %#x runs past the block", ctype)
		}
		seen[ctype] = r.contexts[pos+8 : pos+8+length]
		pos = align8(pos + 8 + length)
	}
	preauth, ok := seen[contextPreauthIntegrity]
	if !ok {
		t.Fatal("no pre-authentication integrity context in the response")
	}
	if len(preauth) != 6+preauthSaltSize {
		t.Fatalf("preauth context is %d bytes", len(preauth))
	}
	if got := binary.LittleEndian.Uint16(preauth[4:]); got != hashSHA512 {
		t.Fatalf("hash algorithm = %#x, want SHA-512", got)
	}
	if binary.LittleEndian.Uint16(preauth[2:]) != preauthSaltSize {
		t.Fatal("the salt length does not match the salt")
	}
	if bytes.Equal(preauth[6:], make([]byte, preauthSaltSize)) {
		t.Fatal("the server sent a zero salt")
	}
	signing, ok := seen[contextSigning]
	if !ok {
		t.Fatal("no signing context in the response")
	}
	if got := binary.LittleEndian.Uint16(signing[2:]); got != signAESCMAC {
		t.Fatalf("signing algorithm = %#x, want AES-CMAC", got)
	}
}

func TestNegotiate311NeedsPreauthContext(t *testing.T) {
	tc := newTestClient(t)
	// 3.1.1 with a signing context but no pre-authentication integrity one:
	// the session key would have nothing to bind to.
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], 1)
	binary.LittleEndian.PutUint16(b[4:], signingEnabled)
	b = binary.LittleEndian.AppendUint16(b, dialect311)
	for (headerSize+len(b))%8 != 0 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint32(b[28:], uint32(headerSize+len(b)))
	binary.LittleEndian.PutUint16(b[32:], 1)
	signing := make([]byte, 4)
	binary.LittleEndian.PutUint16(signing[0:], 1)
	binary.LittleEndian.PutUint16(signing[2:], signAESCMAC)
	b = appendContext(b, contextSigning, signing)

	tc.send(tc.request(cmdNegotiate, b))
	if h, _ := tc.recv(); h.status != statusInvalidParameter {
		t.Fatalf("status = %#x, want STATUS_INVALID_PARAMETER", h.status)
	}
}

// negotiateInProcess runs one NEGOTIATE against a connection the test holds,
// so that the connection state a later command depends on can be read.
func negotiateInProcess(t *testing.T, dialects []uint16, contexts bool) *connection {
	t.Helper()
	s := &Server{FileSystem: facetfs.NewMemFS(), Authenticator: stubAuth{}}
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	conn := &connection{s: s, credits: 1}
	frame := append(header{command: cmdNegotiate, credits: 32}.encode(),
		negotiateRequest(dialects, contexts)...)
	reply, ok, _ := conn.handleFrame(t.Context(), frame)
	if !ok {
		t.Fatal("NEGOTIATE was refused at the framing layer")
	}
	if h, _ := decodeHeader(reply); h.status != statusSuccess {
		t.Fatalf("NEGOTIATE status = %#x", h.status)
	}
	return conn
}

func TestPreauthHashAdvancesOnlyFor311(t *testing.T) {
	zero := [preauthHashSize]byte{}

	if got := negotiateInProcess(t, []uint16{dialect210}, false).preauth; got != zero {
		t.Error("2.1 advanced the pre-authentication hash, which that dialect has none of")
	}
	first := negotiateInProcess(t, []uint16{dialect311}, true).preauth
	if first == zero {
		t.Fatal("3.1.1 left the pre-authentication hash at its seed")
	}
	// The hash binds the session key to the exact negotiation, so a different
	// offer must not produce the same chain.
	second := negotiateInProcess(t, []uint16{dialect311, dialect210}, true).preauth
	if first == second {
		t.Error("two different negotiations produced one pre-authentication hash")
	}
}

func TestNegotiateRecordsTheDialect(t *testing.T) {
	conn := negotiateInProcess(t, []uint16{dialect311}, true)
	if conn.dialect != dialect311 || conn.signAlg != signAESCMAC {
		t.Fatalf("connection settled on dialect %#x with signing %#x", conn.dialect, conn.signAlg)
	}
	old := negotiateInProcess(t, []uint16{dialect210}, false)
	if old.dialect != dialect210 || old.signAlg != signHMACSHA256 {
		t.Fatalf("connection settled on dialect %#x with signing %#x", old.dialect, old.signAlg)
	}
}

func TestNegotiateRejectsMalformedBodies(t *testing.T) {
	tests := []struct {
		name string
		body func() []byte
	}{
		{"short", func() []byte { return make([]byte, 8) }},
		{"wrong structure size", func() []byte {
			b := negotiateRequest([]uint16{dialect210}, false)
			binary.LittleEndian.PutUint16(b[0:], 64)
			return b
		}},
		{"no dialects", func() []byte {
			b := negotiateRequest([]uint16{dialect210}, false)
			binary.LittleEndian.PutUint16(b[2:], 0)
			return b
		}},
		{"more dialects than bytes", func() []byte {
			b := negotiateRequest([]uint16{dialect210}, false)
			binary.LittleEndian.PutUint16(b[2:], 64)
			return b
		}},
		{"more dialects than the bound", func() []byte {
			b := negotiateRequest([]uint16{dialect210}, false)
			binary.LittleEndian.PutUint16(b[2:], maxDialects+1)
			return b
		}},
		{"context count above the bound", func() []byte {
			b := negotiateRequest([]uint16{dialect311}, true)
			binary.LittleEndian.PutUint16(b[32:], maxNegotiateContexts+1)
			return b
		}},
		{"context offset past the message", func() []byte {
			b := negotiateRequest([]uint16{dialect311}, true)
			binary.LittleEndian.PutUint32(b[28:], 1<<20)
			return b
		}},
		{"context offset inside the header", func() []byte {
			b := negotiateRequest([]uint16{dialect311}, true)
			binary.LittleEndian.PutUint32(b[28:], 8)
			return b
		}},
		{"context length past the message", func() []byte {
			b := negotiateRequest([]uint16{dialect311}, true)
			offset := int(binary.LittleEndian.Uint32(b[28:])) - headerSize
			binary.LittleEndian.PutUint16(b[offset+2:], 0xFFFF)
			return b
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := newTestClient(t)
			tc.send(tc.request(cmdNegotiate, tt.body()))
			h, _ := tc.recv()
			if h.status == statusSuccess {
				t.Fatal("a malformed NEGOTIATE was accepted")
			}
		})
	}
}

func TestRequireSigningRefusesAClientThatWillNotSign(t *testing.T) {
	tc := newTestClientFor(t, &Server{
		FileSystem:     facetfs.NewMemFS(),
		Authenticator:  stubAuth{},
		RequireSigning: true,
	})
	b := negotiateRequest([]uint16{dialect210}, false)
	binary.LittleEndian.PutUint16(b[4:], 0) // no signing offered
	tc.send(tc.request(cmdNegotiate, b))
	if h, _ := tc.recv(); h.status != statusAccessDenied {
		t.Fatalf("status = %#x, want STATUS_ACCESS_DENIED", h.status)
	}

	signing := newTestClientFor(t, &Server{
		FileSystem:     facetfs.NewMemFS(),
		Authenticator:  stubAuth{},
		RequireSigning: true,
	})
	_, body := signing.negotiate([]uint16{dialect210}, false)
	if mode := parseNegotiate(t, body).securityMode; mode&signingRequired == 0 {
		t.Fatalf("security mode = %#x, want signing required", mode)
	}
}
