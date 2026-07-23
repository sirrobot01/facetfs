package token

import (
	"bytes"
	"testing"
)

func TestCodec(t *testing.T) {
	codec := New()
	payload := []byte("payload")
	sealed := codec.Seal(payload)
	got, ok := codec.Open(sealed)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("Open() = %q, %v", got, ok)
	}

	tampered := []byte(sealed)
	tampered[len(tampered)/2] ^= 1
	if _, ok := codec.Open(string(tampered)); ok {
		t.Fatal("Open() accepted a modified token")
	}
	if _, ok := New().Open(sealed); ok {
		t.Fatal("Open() accepted a token from another codec")
	}
}
