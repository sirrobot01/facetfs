package nfs4

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
)

// A short handle sealed under a fixed key must unseal in a fresh codec with
// the same key. This is the restart guarantee behind Server.HandleKey: the
// path travels inside the handle, so no table has to survive.
func TestShortHandleSurvivesRestartWithFixedKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	fh := newFHCodec(key, nil).seal("/movies/short.mkv")
	path, st := newFHCodec(key, nil).unseal(fh)
	if st != nfs4OK || path != "/movies/short.mkv" {
		t.Fatalf("unseal after restart = %q, %d, want /movies/short.mkv, OK", path, st)
	}
}

// A long handle carries only sha256(path), and the sha→path table is
// in-memory: without a resolver a fresh codec must expire it, and with one it
// must resolve. Media libraries routinely exceed the short-form path bound,
// so this is the restart path that matters for them.
func TestLongHandleResolverCoversRestart(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	long := "/movies/" + strings.Repeat("Some.Release.2023.1080p.", 8) + "x264.mkv"
	fh := newFHCodec(key, nil).seal(long)

	if _, st := newFHCodec(key, nil).unseal(fh); st != nfs4ErrFHExpired {
		t.Fatalf("unseal without resolver = %d, want FHEXPIRED", st)
	}

	calls := 0
	c := newFHCodec(key, func(sum [32]byte) (string, bool) {
		calls++
		if sum != sha256.Sum256([]byte(long)) {
			t.Fatalf("resolver asked for unknown sum")
		}
		return long, true
	})
	path, st := c.unseal(fh)
	if st != nfs4OK || path != long {
		t.Fatalf("unseal with resolver = %q, %d, want the long path, OK", path, st)
	}
	// The resolved path must be remembered: a resolver consulted on every
	// lookup would put the caller's index on the hot path of each RPC.
	if _, st := c.unseal(fh); st != nfs4OK || calls != 1 {
		t.Fatalf("second unseal = %d with %d resolver calls, want OK with 1", st, calls)
	}
}

// FIFO eviction bounds the table, so a directory sweep wider than the bound
// churns out handles clients still hold. The resolver must cover that case
// too — eviction, not restart, is the common failure for large libraries.
func TestLongHandleResolverCoversEviction(t *testing.T) {
	long := "/movies/" + strings.Repeat("Some.Release.2023.1080p.", 8) + "x264.mkv"
	c := newFHCodec([]byte("k"), func(sum [32]byte) (string, bool) {
		if sum == sha256.Sum256([]byte(long)) {
			return long, true
		}
		return "", false
	})
	fh := c.seal(long)
	filler := strings.Repeat("f", shortPathMax+1)
	for i := range longTableMax {
		c.seal(filler + strconv.Itoa(i))
	}
	if _, ok := c.long[sha256.Sum256([]byte(long))]; ok {
		t.Fatal("path not evicted; the test no longer exercises a table miss")
	}
	path, st := c.unseal(fh)
	if st != nfs4OK || path != long {
		t.Fatalf("unseal after eviction = %q, %d, want the long path, OK", path, st)
	}
}

// A resolver answer that does not hash to the sealed sum must be ignored, or
// a buggy or hostile resolver could redirect a valid handle to another file.
func TestLongHandleRejectsMismatchedResolverPath(t *testing.T) {
	long := "/movies/" + strings.Repeat("Some.Release.2023.1080p.", 8) + "x264.mkv"
	sealer := newFHCodec([]byte("k"), nil)
	fh := sealer.seal(long)
	c := newFHCodec([]byte("k"), func(sum [32]byte) (string, bool) {
		return "/etc/passwd", true
	})
	if _, st := c.unseal(fh); st != nfs4ErrFHExpired {
		t.Fatalf("unseal with mismatched resolver path = %d, want FHEXPIRED", st)
	}
}
