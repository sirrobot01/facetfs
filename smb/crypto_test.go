package smb

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNTHashKnownAnswer(t *testing.T) {
	want := "8846f7eaee8fb117ad06bdd830b7586c"
	if got := hex.EncodeToString(NTHash("password")); got != want {
		t.Fatalf("NTHash(password) = %s, want %s", got, want)
	}
}

func TestAESCMACKnownAnswers(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	tests := []struct{ msg, want string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
	}
	for _, tt := range tests {
		got, ok := aesCMAC(key, mustHex(t, tt.msg))
		if !ok || hex.EncodeToString(got[:]) != tt.want {
			t.Fatalf("CMAC(%s) = %x, %v; want %s", tt.msg, got, ok, tt.want)
		}
	}
}

// TestSigningKeyKnownAnswer pins the 3.1.1 signing key against a real
// client. The values come from one session of the Python smbprotocol client;
// the resulting derivation is also accepted by the Linux cifs client.
//
// A round-trip test cannot catch an error here, because both sides of it
// share the derivation. The label carries a terminating null and the KDF adds
// the SP 800-108 separator, so the derivation covers two null bytes; with one
// the server signs consistently and no real client accepts it.
func TestSigningKeyKnownAnswer(t *testing.T) {
	sessionKey := mustHex(t, "0115978ef7985dbaaa45f0b903668122")
	preauth := mustHex(t, "9eb9e35875a8d1cc7b23476d687d11d5f5c64926a21046db3117265d8c94ab0d"+
		"5221313a26bc48ee901dde7783814e3e03fb62273df9012f0c979614dee2ce1d")
	want := "afd6e5fe5ed80b3fbbc46eae6cdc7402"
	if got := hex.EncodeToString(smbKDF(sessionKey, signingKeyLabel, preauth)); got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

func TestMessageSignatureRoundTripAndTamper(t *testing.T) {
	msg := append(header{command: cmdEcho, messageID: 7}.encode(), echoRequest()...)
	key := []byte("0123456789abcdef")
	for _, alg := range []uint16{signHMACSHA256, signAESCMAC} {
		got := append([]byte(nil), msg...)
		if !signMessage(key, alg, got) || !verifyMessage(key, alg, got) {
			t.Fatalf("algorithm %d did not round trip", alg)
		}
		got[len(got)-1] ^= 1
		if verifyMessage(key, alg, got) {
			t.Fatalf("algorithm %d accepted a modified message", alg)
		}
	}
}
