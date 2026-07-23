package memfs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/sirrobot01/facetfs"
)

const cursorSignatureSize = 16

func (f *FS) cursor(revision uint64, name string) facetfs.DirCursor {
	b := make([]byte, 8, 8+len(name)+cursorSignatureSize)
	binary.BigEndian.PutUint64(b, revision)
	b = append(b, name...)
	mac := hmac.New(sha256.New, []byte(f.key))
	_, _ = mac.Write(b)
	b = append(b, mac.Sum(nil)[:cursorSignatureSize]...)
	return facetfs.DirCursor(base64.RawURLEncoding.EncodeToString(b))
}

func (f *FS) parseCursor(cursor facetfs.DirCursor) (uint64, string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(string(cursor))
	if err != nil || len(b) < 8+cursorSignatureSize {
		return 0, "", false
	}
	payload, signature := b[:len(b)-cursorSignatureSize], b[len(b)-cursorSignatureSize:]
	mac := hmac.New(sha256.New, []byte(f.key))
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)[:cursorSignatureSize]) {
		return 0, "", false
	}
	return binary.BigEndian.Uint64(payload[:8]), string(payload[8:]), true
}
