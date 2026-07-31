package facetfs_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirrobot01/facetfs"
)

func benchStat(b *testing.B, fsys facetfs.FileSystem) {
	b.Helper()
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fsys.Stat(ctx, "/f"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDirStat(b *testing.B) {
	tmp := b.TempDir()
	os.WriteFile(filepath.Join(tmp, "f"), []byte("x"), 0o644)
	benchStat(b, facetfs.Dir(tmp))
}

func BenchmarkRootStat(b *testing.B) {
	tmp := b.TempDir()
	os.WriteFile(filepath.Join(tmp, "f"), []byte("x"), 0o644)
	root, err := facetfs.OpenDir(tmp)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	benchStat(b, root)
}

func BenchmarkOsStat(b *testing.B) {
	tmp := b.TempDir()
	name := filepath.Join(tmp, "f")
	os.WriteFile(name, []byte("x"), 0o644)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := os.Stat(name); err != nil {
			b.Fatal(err)
		}
	}
}
