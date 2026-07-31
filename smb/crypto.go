package smb

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// NTHash derives the password-equivalent value expected by Authenticator.
// Callers should protect the result as carefully as the password itself.
func NTHash(password string) []byte {
	h := md4.New()
	h.Write(utf16Bytes(password))
	return h.Sum(nil)
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func ntlmResponseKey(ntHash []byte, user, domain string) []byte {
	return hmacMD5(ntHash, utf16Bytes(strings.ToUpper(user)+domain))
}

func exportedSessionKey(sessionBase, encrypted []byte, flags uint32) ([]byte, bool) {
	const negotiateKeyExchange = 0x40000000
	if flags&negotiateKeyExchange == 0 {
		return append([]byte(nil), sessionBase...), true
	}
	if len(encrypted) != 16 {
		return nil, false
	}
	c, err := rc4.NewCipher(sessionBase)
	if err != nil {
		return nil, false
	}
	key := make([]byte, 16)
	c.XORKeyStream(key, encrypted)
	return key, true
}

// smbKDF is SP 800-108 counter mode with HMAC-SHA256 and a 128-bit output.
func smbKDF(key []byte, label string, context []byte) []byte {
	h := hmac.New(sha256.New, key)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	h.Write(counter[:])
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(context)
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], 128)
	h.Write(bits[:])
	return h.Sum(nil)[:16]
}

func shiftBlock(in [16]byte) (out [16]byte) {
	var carry byte
	for i := 15; i >= 0; i-- {
		next := in[i] >> 7
		out[i] = in[i]<<1 | carry
		carry = next
	}
	if carry != 0 {
		out[15] ^= 0x87
	}
	return
}

// aesCMAC implements RFC 4493. SMB 3.1.1 uses the first 16 bytes, which is
// the complete CMAC output.
func aesCMAC(key, msg []byte) ([16]byte, bool) {
	var result [16]byte
	block, err := aes.NewCipher(key)
	if err != nil {
		return result, false
	}
	var zero, l [16]byte
	block.Encrypt(l[:], zero[:])
	k1 := shiftBlock(l)
	k2 := shiftBlock(k1)
	n := (len(msg) + 15) / 16
	complete := len(msg) > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last [16]byte
	if complete {
		copy(last[:], msg[(n-1)*16:])
		for i := range last {
			last[i] ^= k1[i]
		}
	} else {
		remain := msg[(n-1)*16:]
		copy(last[:], remain)
		last[len(remain)] = 0x80
		for i := range last {
			last[i] ^= k2[i]
		}
	}
	var x, y [16]byte
	for i := 0; i < n-1; i++ {
		copy(y[:], msg[i*16:(i+1)*16])
		for j := range y {
			y[j] ^= x[j]
		}
		block.Encrypt(x[:], y[:])
	}
	for i := range last {
		last[i] ^= x[i]
	}
	block.Encrypt(result[:], last[:])
	return result, true
}

func signature(key []byte, alg uint16, frame []byte) ([16]byte, bool) {
	if alg == signAESCMAC {
		return aesCMAC(key, frame)
	}
	var out [16]byte
	h := hmac.New(sha256.New, key)
	h.Write(frame)
	copy(out[:], h.Sum(nil))
	return out, true
}

// signMessage signs one message in place, over its header, its body, and the
// padding that follows it. Each message of a compound chain carries its own
// signature ([MS-SMB2] section 3.1.4.1).
func signMessage(key []byte, alg uint16, msg []byte) bool {
	if len(msg) < headerSize {
		return false
	}
	binary.LittleEndian.PutUint32(msg[16:], binary.LittleEndian.Uint32(msg[16:])|flagSigned)
	clear(msg[48:64])
	sig, ok := signature(key, alg, msg)
	if !ok {
		return false
	}
	copy(msg[48:64], sig[:])
	return true
}

// verifyMessage checks the signature of one message. A message without the
// signed flag fails: a signing session refuses an unsigned request.
func verifyMessage(key []byte, alg uint16, msg []byte) bool {
	if len(msg) < headerSize || binary.LittleEndian.Uint32(msg[16:])&flagSigned == 0 {
		return false
	}
	unsigned := append([]byte(nil), msg...)
	clear(unsigned[48:64])
	got, ok := signature(key, alg, unsigned)
	return ok && hmac.Equal(msg[48:64], got[:])
}
