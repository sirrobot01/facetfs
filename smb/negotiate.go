package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"time"
)

// serverDialects are the dialects the package serves, in preference order.
// Section 17 of the component design records why the three between them are
// not served.
var serverDialects = []uint16{dialect311, dialect210}

// spnegoNegTokenInit advertises NTLM and nothing else. It is constant: the
// package supports one mechanism, so there is nothing to vary.
//
//	InitialContextToken := [APPLICATION 0] { OID 1.3.6.1.5.5.2 (SPNEGO),
//	    NegTokenInit := { mechTypes := { OID 1.3.6.1.4.1.311.2.2.10 (NTLM) } } }
var spnegoNegTokenInit = []byte{
	0x60, 0x1c,
	0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
	0xa0, 0x12,
	0x30, 0x10,
	0xa0, 0x0e,
	0x30, 0x0c,
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
}

// negotiate answers NEGOTIATE ([MS-SMB2] section 2.2.3).
func (conn *connection) negotiate(m *message) ([]byte, uint32) {
	b := m.body
	if len(b) < 36 || binary.LittleEndian.Uint16(b[0:]) != 36 {
		return nil, statusInvalidParameter
	}
	count := binary.LittleEndian.Uint16(b[2:])
	clientSecurityMode := binary.LittleEndian.Uint16(b[4:])
	clientCapabilities := binary.LittleEndian.Uint32(b[8:])
	var clientGUID [16]byte
	copy(clientGUID[:], b[12:28])
	contextOffset := binary.LittleEndian.Uint32(b[28:])
	contextCount := binary.LittleEndian.Uint16(b[32:])
	if count == 0 || count > maxDialects {
		return nil, statusInvalidParameter
	}
	if len(b) < 36+int(count)*2 {
		return nil, statusInvalidParameter
	}
	chosen := uint16(0)
	for _, want := range serverDialects {
		for i := range int(count) {
			if binary.LittleEndian.Uint16(b[36+i*2:]) == want {
				chosen = want
				break
			}
		}
		if chosen != 0 {
			break
		}
	}
	if chosen == 0 {
		return nil, statusNotSupported
	}
	// A client that demands signing gets it. RequireSigning demands it the
	// other way round.
	if conn.s.RequireSigning && clientSecurityMode&(signingEnabled|signingRequired) == 0 {
		return nil, statusAccessDenied
	}

	signAlg := uint16(signHMACSHA256)
	var contexts []byte
	if chosen == dialect311 {
		var st uint32
		signAlg, contexts, st = conn.negotiateContexts(m, contextOffset, contextCount)
		if st != statusSuccess {
			return nil, st
		}
	}

	body := conn.s.negotiateResponse(chosen, contexts)

	conn.mu.Lock()
	conn.dialect, conn.signAlg = chosen, signAlg
	conn.clientSigning = clientSecurityMode&(signingEnabled|signingRequired) != 0
	conn.clientSecurityMode = clientSecurityMode
	conn.clientCapabilities = clientCapabilities
	conn.clientGUID = clientGUID
	conn.mu.Unlock()
	return body, statusSuccess
}

// negotiateResponse builds the NEGOTIATE response body ([MS-SMB2] section
// 2.2.4) for one dialect. The fixed part is 64 bytes and the security buffer
// follows the header and it, so the offsets are known before the body is
// built.
func (s *Server) negotiateResponse(dialect uint16, contexts []byte) []byte {
	securityMode := uint16(signingEnabled)
	if s.RequireSigning {
		securityMode |= signingRequired
	}
	const fixed = 64
	securityOffset := headerSize + fixed
	body := make([]byte, fixed)
	binary.LittleEndian.PutUint16(body[0:], 65)
	binary.LittleEndian.PutUint16(body[2:], securityMode)
	binary.LittleEndian.PutUint16(body[4:], dialect)
	binary.LittleEndian.PutUint16(body[6:], uint16(countContexts(contexts)))
	copy(body[8:24], s.guid[:])
	binary.LittleEndian.PutUint32(body[24:], capLargeMTU)
	binary.LittleEndian.PutUint32(body[28:], s.maxTransact())
	binary.LittleEndian.PutUint32(body[32:], s.maxRead())
	binary.LittleEndian.PutUint32(body[36:], s.maxWrite())
	binary.LittleEndian.PutUint64(body[40:], fileTime(time.Now()))
	binary.LittleEndian.PutUint64(body[48:], fileTime(s.startedAt))
	binary.LittleEndian.PutUint16(body[56:], uint16(securityOffset))
	binary.LittleEndian.PutUint16(body[58:], uint16(len(spnegoNegTokenInit)))
	body = append(body, spnegoNegTokenInit...)
	if len(contexts) != 0 {
		for (headerSize+len(body))%8 != 0 {
			body = append(body, 0)
		}
		binary.LittleEndian.PutUint32(body[60:], uint32(headerSize+len(body)))
		body = append(body, contexts...)
	}
	return body
}

// smb1Negotiate answers the one SMB1 message the server accepts: the first
// message of a connection, when it is a NEGOTIATE whose dialect list offers
// "SMB 2.???". The answer is an SMB2 NEGOTIATE response with the wildcard
// revision, which tells the client to negotiate again in SMB2 ([MS-SMB2]
// section 3.3.5.3.1). Every other SMB1 message gets STATUS_NOT_SUPPORTED and
// ends the connection. The step-up does not enter the pre-authentication
// hash: that chain starts at the SMB2 NEGOTIATE, as the specification
// requires.
func (conn *connection) smb1Negotiate(frame []byte) (reply []byte, stepUp bool) {
	conn.mu.Lock()
	stepUp = !conn.negotiated && !conn.smb1 && smb1OffersWildcard(frame)
	conn.smb1 = true
	conn.mu.Unlock()

	h := header{command: cmdNegotiate, credits: 1, flags: flagServerToRedir}
	if !stepUp {
		h.status = statusNotSupported
		return append(h.encode(), errorResponse()...), false
	}
	return append(h.encode(), conn.s.negotiateResponse(dialectSMB2Wildcard, nil)...), true
}

// smb1OffersWildcard reports whether an SMB1 frame is a NEGOTIATE whose
// dialect list offers "SMB 2.???". It is the only SMB1 parsing in the
// package: a header, a zero word count, a byte count, and a list of
// 0x02-prefixed NUL-terminated dialect strings.
func smb1OffersWildcard(frame []byte) bool {
	if len(frame) < smb1MinNegotiate || frame[4] != smb1CmdNegotiate || frame[smb1HeaderSize] != 0 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(frame[smb1HeaderSize+1:]))
	if smb1MinNegotiate+count > len(frame) {
		return false
	}
	dialects := frame[smb1MinNegotiate : smb1MinNegotiate+count]
	for len(dialects) > 0 {
		if dialects[0] != 0x02 {
			return false
		}
		end := bytes.IndexByte(dialects[1:], 0)
		if end < 0 {
			return false
		}
		if string(dialects[1:1+end]) == smb1DialectWildcard {
			return true
		}
		dialects = dialects[2+end:]
	}
	return false
}

// negotiateContexts reads the 3.1.1 contexts and builds the answering ones.
// A 3.1.1 negotiation without a pre-authentication integrity context is
// invalid: the session key derivation has nothing to bind to.
func (conn *connection) negotiateContexts(m *message, offset uint32, count uint16) (uint16, []byte, uint32) {
	if count == 0 || count > maxNegotiateContexts {
		return 0, nil, statusInvalidParameter
	}
	preauthOK := false
	signAlg := uint16(signAESCMAC)
	pos := offset
	for i := range int(count) {
		head, ok := m.slice(pos, 8, 8)
		if !ok {
			return 0, nil, statusInvalidParameter
		}
		ctype := binary.LittleEndian.Uint16(head[0:])
		length := uint32(binary.LittleEndian.Uint16(head[2:]))
		data, ok := m.slice(pos+8, length, maxSecurityBuffer)
		if !ok {
			return 0, nil, statusInvalidParameter
		}
		switch ctype {
		case contextPreauthIntegrity:
			if len(data) < 4 {
				return 0, nil, statusInvalidParameter
			}
			hashes := binary.LittleEndian.Uint16(data[0:])
			saltLen := binary.LittleEndian.Uint16(data[2:])
			if int(hashes)*2+4+int(saltLen) > len(data) {
				return 0, nil, statusInvalidParameter
			}
			for i := range int(hashes) {
				if binary.LittleEndian.Uint16(data[4+i*2:]) == hashSHA512 {
					preauthOK = true
				}
			}
		case contextSigning:
			if len(data) < 2 {
				return 0, nil, statusInvalidParameter
			}
			algs := binary.LittleEndian.Uint16(data[0:])
			if int(algs)*2+2 > len(data) {
				return 0, nil, statusInvalidParameter
			}
			for i := range int(algs) {
				// AES-CMAC is preferred; GMAC is not implemented, so it is
				// not chosen even when the client offers it.
				if binary.LittleEndian.Uint16(data[2+i*2:]) == signAESCMAC {
					signAlg = signAESCMAC
				}
			}
		default:
			// An encryption, compression, or transport context is ignored
			// rather than refused: the server simply does not answer one.
		}
		if i+1 < int(count) {
			next := uint64(align8(int(pos) + 8 + int(length)))
			if next <= uint64(pos) || next > uint64(len(m.raw)) {
				return 0, nil, statusInvalidParameter
			}
			pos = uint32(next)
		}
	}
	if !preauthOK {
		return 0, nil, statusInvalidParameter
	}

	var salt [preauthSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return 0, nil, statusInsufficientResources
	}
	contexts := appendContext(nil, contextPreauthIntegrity, func() []byte {
		d := make([]byte, 6)
		binary.LittleEndian.PutUint16(d[0:], 1)
		binary.LittleEndian.PutUint16(d[2:], preauthSaltSize)
		binary.LittleEndian.PutUint16(d[4:], hashSHA512)
		return append(d, salt[:]...)
	}())
	contexts = appendContext(contexts, contextSigning, func() []byte {
		d := make([]byte, 4)
		binary.LittleEndian.PutUint16(d[0:], 1)
		binary.LittleEndian.PutUint16(d[2:], signAlg)
		return d
	}())
	return signAlg, contexts, statusSuccess
}

// appendContext adds one negotiate context, padded to the 8-byte boundary the
// next one needs.
func appendContext(b []byte, ctype uint16, data []byte) []byte {
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	head := make([]byte, 8)
	binary.LittleEndian.PutUint16(head[0:], ctype)
	binary.LittleEndian.PutUint16(head[2:], uint16(len(data)))
	b = append(b, head...)
	return append(b, data...)
}

// countContexts reports how many contexts the built block holds. The block is
// built by this package, so walking it cannot fail.
func countContexts(b []byte) int {
	count, pos := 0, 0
	for pos+8 <= len(b) {
		length := int(binary.LittleEndian.Uint16(b[pos+2:]))
		count++
		pos = align8(pos + 8 + length)
	}
	return count
}
