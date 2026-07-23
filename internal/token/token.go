package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const signatureSize = 16

type Codec struct {
	key [32]byte
}

func New() Codec {
	return Codec{key: sha256.Sum256([]byte(rand.Text()))}
}

func (c Codec) Seal(payload []byte) string {
	mac := hmac.New(sha256.New, c.key[:])
	_, _ = mac.Write(payload)
	sealed := make([]byte, 0, len(payload)+signatureSize)
	sealed = append(sealed, payload...)
	sealed = append(sealed, mac.Sum(nil)[:signatureSize]...)
	return base64.RawURLEncoding.EncodeToString(sealed)
}

func (c Codec) Open(sealed string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(b) < signatureSize {
		return nil, false
	}
	payload, signature := b[:len(b)-signatureSize], b[len(b)-signatureSize:]
	mac := hmac.New(sha256.New, c.key[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)[:signatureSize]) {
		return nil, false
	}
	return payload, true
}
