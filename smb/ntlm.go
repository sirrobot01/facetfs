package smb

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
)

var ntlmSignature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

const (
	ntlmNegotiateUnicode                 = 0x00000001
	ntlmRequestTarget                    = 0x00000004
	ntlmNegotiateSign                    = 0x00000010
	ntlmNegotiateNTLM                    = 0x00000200
	ntlmNegotiateAlwaysSign              = 0x00008000
	ntlmTargetTypeServer                 = 0x00020000
	ntlmNegotiateExtendedSessionSecurity = 0x00080000
	ntlmNegotiateTargetInfo              = 0x00800000
	ntlmNegotiate128                     = 0x20000000
	ntlmNegotiateKeyExchange             = 0x40000000
	ntlmNegotiate56                      = 0x80000000
)

func ntlmToken(blob []byte) ([]byte, bool) {
	i := bytes.Index(blob, ntlmSignature)
	if i < 0 || len(blob)-i < 12 {
		return nil, false
	}
	return blob[i:], true
}

func ntlmType(token []byte) (uint32, bool) {
	if len(token) < 12 || !bytes.Equal(token[:8], ntlmSignature) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(token[8:]), true
}

func ntlmSecurityBuffer(token []byte, at int, max uint32) ([]byte, bool) {
	if at < 0 || at+8 > len(token) {
		return nil, false
	}
	n := uint32(binary.LittleEndian.Uint16(token[at:]))
	off := binary.LittleEndian.Uint32(token[at+4:])
	if n > max || uint64(off)+uint64(n) > uint64(len(token)) {
		return nil, false
	}
	return token[off : off+n], true
}

func appendAV(dst []byte, id uint16, value []byte) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, id)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

func ntlmChallenge(server string, challenge [8]byte) ([]byte, uint32) {
	flags := uint32(ntlmNegotiateUnicode | ntlmRequestTarget | ntlmNegotiateSign |
		ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmTargetTypeServer |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiateTargetInfo |
		ntlmNegotiate128 | ntlmNegotiateKeyExchange | ntlmNegotiate56)
	target := utf16Bytes(server)
	info := appendAV(nil, 1, target)
	info = appendAV(info, 2, target)
	var timestamp [8]byte
	binary.LittleEndian.PutUint64(timestamp[:], fileTime(time.Now()))
	info = appendAV(info, 7, timestamp[:])
	info = appendAV(info, 0, nil)
	const fixed = 48
	b := make([]byte, fixed)
	copy(b, ntlmSignature)
	binary.LittleEndian.PutUint32(b[8:], 2)
	putSecurityBuffer(b[12:], uint16(len(target)), fixed)
	binary.LittleEndian.PutUint32(b[20:], flags)
	copy(b[24:], challenge[:])
	putSecurityBuffer(b[40:], uint16(len(info)), fixed+len(target))
	b = append(b, target...)
	b = append(b, info...)
	return b, flags
}

func putSecurityBuffer(dst []byte, n uint16, offset int) {
	binary.LittleEndian.PutUint16(dst, n)
	binary.LittleEndian.PutUint16(dst[2:], n)
	binary.LittleEndian.PutUint32(dst[4:], uint32(offset))
}

type ntlmAuthResult struct {
	user, domain string
	key          []byte
}

func authenticateNTLM(ctx context.Context, auth Authenticator, token []byte, challenge [8]byte) (ntlmAuthResult, bool) {
	if typ, ok := ntlmType(token); !ok || typ != 3 || len(token) < 64 {
		return ntlmAuthResult{}, false
	}
	ntResp, ok := ntlmSecurityBuffer(token, 20, maxSecurityBuffer)
	if !ok || len(ntResp) < 16+28 {
		return ntlmAuthResult{}, false
	}
	domainWire, ok := ntlmSecurityBuffer(token, 28, maxSecurityBuffer)
	if !ok {
		return ntlmAuthResult{}, false
	}
	userWire, ok := ntlmSecurityBuffer(token, 36, maxSecurityBuffer)
	if !ok {
		return ntlmAuthResult{}, false
	}
	encrypted, ok := ntlmSecurityBuffer(token, 52, 32)
	if !ok {
		return ntlmAuthResult{}, false
	}
	domain, ok := decodeUTF16(domainWire)
	if !ok {
		return ntlmAuthResult{}, false
	}
	user, ok := decodeUTF16(userWire)
	if !ok || strings.TrimSpace(user) == "" {
		return ntlmAuthResult{}, false
	}
	blob := ntResp[16:]
	if len(blob) < 28 || binary.LittleEndian.Uint32(blob) != 0x00000101 {
		return ntlmAuthResult{}, false
	}
	hash, err := auth.NTHash(ctx, domain, user)
	if err != nil || len(hash) != 16 {
		return ntlmAuthResult{}, false
	}
	responseKey := ntlmResponseKey(hash, user, domain)
	expected := hmacMD5(responseKey, challenge[:], blob)
	if !hmac.Equal(ntResp[:16], expected) {
		return ntlmAuthResult{}, false
	}
	baseKey := hmacMD5(responseKey, expected)
	flags := binary.LittleEndian.Uint32(token[60:])
	key, ok := exportedSessionKey(baseKey, encrypted, flags)
	if !ok {
		return ntlmAuthResult{}, false
	}
	return ntlmAuthResult{user: user, domain: domain, key: key}, true
}

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xff {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func der(tag byte, content []byte) []byte {
	b := []byte{tag}
	b = append(b, derLength(len(content))...)
	return append(b, content...)
}

var ntlmOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

func spnegoChallenge(token []byte) []byte {
	state := der(0xa0, []byte{0x0a, 0x01, 0x01})
	mech := der(0xa1, ntlmOID)
	response := der(0xa2, der(0x04, token))
	return der(0xa1, der(0x30, append(append(state, mech...), response...)))
}

func spnegoComplete() []byte {
	return der(0xa1, der(0x30, der(0xa0, []byte{0x0a, 0x01, 0x00})))
}

func freshChallenge() ([8]byte, bool) {
	var c [8]byte
	_, err := rand.Read(c[:])
	return c, err == nil
}
