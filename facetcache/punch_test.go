//go:build linux || darwin

package facetcache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	facetfs "github.com/sirrobot01/facetfs"
)

// TestPunchHoleDeallocates verifies the platform call actually releases
// blocks, not just that it returns nil.
func TestPunchHoleDeallocates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "punch")
	data := bytes.Repeat([]byte{0x5A}, 1<<20)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	before := allocatedBlocks(t, path)
	const off, size = 256 << 10, 512 << 10 // block-aligned on every platform
	if err := punchHole(f, off, size); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("filesystem cannot punch holes: %v", err)
		}
		t.Fatal(err)
	}
	if after := allocatedBlocks(t, path); after >= before {
		t.Fatalf("punch released nothing: %d blocks before, %d after", before, after)
	}
	// The punched region must read as zeros and the rest must survive.
	got := make([]byte, len(data))
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	for i, b := range got {
		want := byte(0x5A)
		if i >= off && i < off+size {
			want = 0
		}
		if b != want {
			t.Fatalf("byte %d = %#x, want %#x", i, b, want)
		}
	}
}

func allocatedBlocks(t *testing.T, path string) int64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Blocks
}

// TestPunchBehindRefetch drives the janitor's punch phase against an open
// stream and requires the read path to notice the hole and refill it, the
// re-validation the design relies on instead of a read-head contract.
func TestPunchBehindRefetch(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	data := pattern(2 << 20)
	writeBackendFile(t, backend, "/f", data)
	c, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	f, err := fsys.OpenFile(ctx, "/f", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, len(data))
	if _, err := f.(io.ReaderAt).ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}

	// Small files never sit punchBackWindow behind their own read head, so
	// push the head artificially: everything below 1 MiB becomes punchable.
	it := f.(*cachedFile).it
	it.readHead.Store(punchBackWindow + 1<<20)
	c.core.jan.punchItem(it)
	if err := punchProbe(t); err != nil {
		t.Skip(err)
	}
	if got := c.Stats().PunchedBytes; got == 0 {
		t.Fatal("janitor punched nothing")
	}
	if it.hasRange(rng{0, 4096}) {
		t.Fatal("punched range still claimed present")
	}

	// A read of the punched region must refetch, not serve zeros.
	before := backend.readBytes.Load()
	got := make([]byte, 64<<10)
	if _, err := f.(io.ReaderAt).ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[:len(got)]) {
		t.Fatal("read after punch returned wrong bytes")
	}
	if backend.readBytes.Load() == before {
		t.Fatal("read after punch did not refetch from the backend")
	}
}

// punchProbe reports whether the test filesystem supports hole punching, so
// the end-to-end test skips rather than fails on exotic setups.
func punchProbe(t *testing.T) error {
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return punchHole(f, 0, 4096)
}
