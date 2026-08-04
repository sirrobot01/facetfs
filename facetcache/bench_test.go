package facetcache

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	facetfs "github.com/sirrobot01/facetfs"
)

// The warm-path budgets from the design: ReadAt within 1.15x of a direct
// pread with zero allocations, Stat in nanoseconds with zero allocations,
// and a stateless-NFS-shaped OpenFile+Close in about a microsecond. Run
// with the direct benchmarks below for the baseline.

func benchSetup(b *testing.B, size int) (facetfs.FileSystem, string) {
	b.Helper()
	backend := facetfs.NewMemFS()
	f, err := backend.OpenFile(context.Background(), "/bench", os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.Write(make([]byte, size)); err != nil {
		b.Fatal(err)
	}
	f.Close()
	c := &Cache{Backend: backend, Dir: b.TempDir()}
	fsys, err := c.FileSystem()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	return fsys, "/bench"
}

func BenchmarkWarmReadAt64K(b *testing.B) {
	fsys, name := benchSetup(b, 8<<20)
	f, err := fsys.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	ra := f.(io.ReaderAt)
	buf := make([]byte, 64<<10)
	if _, err := ra.ReadAt(buf, 0); err != nil { // warm the range
		b.Fatal(err)
	}
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ra.ReadAt(buf, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDirectReadAt64K is the floor BenchmarkWarmReadAt64K is measured
// against: the same pread against the cache file without the cache.
func BenchmarkDirectReadAt64K(b *testing.B) {
	path := filepath.Join(b.TempDir(), "direct")
	if err := os.WriteFile(path, make([]byte, 8<<20), 0o600); err != nil {
		b.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := f.ReadAt(buf, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWarmStat(b *testing.B) {
	fsys, name := benchSetup(b, 4096)
	ctx := context.Background()
	if _, err := fsys.Stat(ctx, name); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fsys.Stat(ctx, name); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWarmOpenClose is the stateless NFS shape: the server opens and
// closes per READ, so this path must stay a map hit plus a refcount.
func BenchmarkWarmOpenClose(b *testing.B) {
	fsys, name := benchSetup(b, 4096)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		f, err := fsys.OpenFile(ctx, name, os.O_RDONLY, 0)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// slowFS injects backend latency so the cached-vs-uncached gap is visible
// end to end, the shape of an http or S3 backend behind facet.
type slowFS struct {
	facetfs.FileSystem
	delay time.Duration
}

func (s *slowFS) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	time.Sleep(s.delay)
	return s.FileSystem.Stat(ctx, name)
}

func BenchmarkStatSlowBackend(b *testing.B) {
	backend := &slowFS{FileSystem: facetfs.NewMemFS(), delay: 5 * time.Millisecond}
	f, err := backend.FileSystem.OpenFile(context.Background(), "/f", os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		b.Fatal(err)
	}
	f.Close()
	c := &Cache{Backend: backend, Dir: b.TempDir(), AttrTTL: time.Hour}
	fsys, err := c.FileSystem()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })
	ctx := context.Background()
	if _, err := fsys.Stat(ctx, "/f"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fsys.Stat(ctx, "/f"); err != nil {
			b.Fatal(err)
		}
	}
}
