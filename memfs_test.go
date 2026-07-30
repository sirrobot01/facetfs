package facetfs_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/sirrobot01/facetfs"
)

func TestMemFSFileRoundTrip(t *testing.T) {
	ctx := context.Background()
	fsys := facetfs.NewMemFS()

	f, err := fsys.OpenFile(ctx, "/hello.txt", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("hello world")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := fsys.OpenFile(ctx, "/hello.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("O_EXCL on existing file: err = %v, want fs.ErrExist", err)
	}

	f, err = fsys.OpenFile(ctx, "/hello.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile for read: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("content = %q, want %q", got, "hello world")
	}

	ra, ok := f.(io.ReaderAt)
	if !ok {
		t.Fatal("memFS file does not implement io.ReaderAt")
	}
	buf := make([]byte, 5)
	if _, err := ra.ReadAt(buf, 6); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("ReadAt = %q, want %q", buf, "world")
	}
	f.Close()
}

func TestMemFSDirectories(t *testing.T) {
	ctx := context.Background()
	fsys := facetfs.NewMemFS()

	if err := fsys.Mkdir(ctx, "/a", 0o755); err != nil {
		t.Fatalf("Mkdir /a: %v", err)
	}
	if err := fsys.Mkdir(ctx, "/a/b", 0o755); err != nil {
		t.Fatalf("Mkdir /a/b: %v", err)
	}
	if err := fsys.Mkdir(ctx, "/missing/child", 0o755); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Mkdir under missing parent: err = %v, want fs.ErrNotExist", err)
	}

	f, err := fsys.OpenFile(ctx, "/a/b/c.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	f.Close()

	dir, err := fsys.OpenFile(ctx, "/a", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	entries, err := dir.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	dir.Close()
	if len(entries) != 1 || entries[0].Name() != "b" || !entries[0].IsDir() {
		t.Fatalf("Readdir = %v", entries)
	}

	if err := fsys.Rename(ctx, "/a", "/a/b/inside"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Rename into own subtree: err = %v, want fs.ErrInvalid", err)
	}
	if err := fsys.Rename(ctx, "/a", "/z"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fsys.Stat(ctx, "/z/b/c.txt"); err != nil {
		t.Fatalf("Stat after rename: %v", err)
	}

	if err := fsys.RemoveAll(ctx, "/z"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := fsys.Stat(ctx, "/z"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat after RemoveAll: err = %v, want fs.ErrNotExist", err)
	}
	if err := fsys.RemoveAll(ctx, "/z"); err != nil {
		t.Fatalf("RemoveAll on missing path: %v", err)
	}
}

func TestMemFSSymlinks(t *testing.T) {
	ctx := context.Background()
	fsys := facetfs.NewMemFS().(facetfs.SymlinkFS)

	f, err := fsys.OpenFile(ctx, "/target.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	f.Write([]byte("data"))
	f.Close()

	if err := fsys.Symlink(ctx, "/target.txt", "/link"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	got, err := fsys.Readlink(ctx, "/link")
	if err != nil || got != "/target.txt" {
		t.Fatalf("Readlink = %q, %v", got, err)
	}
	fi, err := fsys.Stat(ctx, "/link")
	if err != nil || fi.Mode()&fs.ModeSymlink != 0 || fi.Size() != 4 {
		t.Fatalf("Stat follows link: %v, %v", fi, err)
	}
	fi, err = fsys.Lstat(ctx, "/link")
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat does not follow link: %v, %v", fi, err)
	}

	if err := fsys.Symlink(ctx, "/loop", "/loop"); err != nil {
		t.Fatalf("Symlink loop: %v", err)
	}
	if _, err := fsys.Stat(ctx, "/loop"); err == nil {
		t.Fatal("Stat on symlink loop succeeded")
	}
}

func TestMemFSSetStat(t *testing.T) {
	ctx := context.Background()
	fsys := facetfs.NewMemFS().(facetfs.SetStatFS)

	f, err := fsys.OpenFile(ctx, "/f", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	f.Write([]byte("0123456789"))
	f.Close()

	if err := fsys.Truncate(ctx, "/f", 4); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	fi, err := fsys.Stat(ctx, "/f")
	if err != nil || fi.Size() != 4 {
		t.Fatalf("Size after truncate = %d, %v", fi.Size(), err)
	}
	if err := fsys.Chmod(ctx, "/f", 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	fi, _ = fsys.Stat(ctx, "/f")
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("Mode = %v, want 0600", fi.Mode())
	}
}

func TestMemFSAppend(t *testing.T) {
	ctx := context.Background()
	fsys := facetfs.NewMemFS()

	for _, chunk := range []string{"one,", "two"} {
		f, err := fsys.OpenFile(ctx, "/log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, err := f.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		f.Close()
	}
	f, _ := fsys.OpenFile(ctx, "/log", os.O_RDONLY, 0)
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "one,two" {
		t.Fatalf("content = %q, want %q", got, "one,two")
	}
}
