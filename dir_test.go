package facetfs_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sirrobot01/facetfs"
)

func TestDirRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := facetfs.Dir(t.TempDir())

	if err := d.Mkdir(ctx, "/sub", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	f, err := d.OpenFile(ctx, "/sub/file.txt", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("content")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fi, err := d.Stat(ctx, "/sub/file.txt")
	if err != nil || fi.Size() != 7 {
		t.Fatalf("Stat = %v, %v", fi, err)
	}

	if err := d.Rename(ctx, "/sub/file.txt", "/renamed.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	f, err = d.OpenFile(ctx, "/renamed.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile after rename: %v", err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "content" {
		t.Fatalf("content = %q", got)
	}

	if err := d.RemoveAll(ctx, "/sub"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := d.Stat(ctx, "/sub"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat after RemoveAll: err = %v, want fs.ErrNotExist", err)
	}
}

func TestDirConfinesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	ctx := context.Background()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	d := facetfs.Dir(root)

	if err := d.Symlink(ctx, filepath.Join(outside, "secret"), "/escape"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := d.OpenFile(ctx, "/escape", os.O_RDONLY, 0); err == nil {
		t.Fatal("opening a symlink that escapes the root succeeded")
	}
	if _, err := d.Stat(ctx, "/../"+filepath.Base(outside)); !errors.Is(err, fs.ErrNotExist) {
		// path.Clean confines "..", so the lookup stays inside root.
		if err == nil {
			t.Fatal("Stat escaped the root via ..")
		}
	}
}
