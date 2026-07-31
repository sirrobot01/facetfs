package nfs4

import (
	"os"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// renameAtRoot renames within the root directory.
func renameAtRoot(t *testing.T, tc *testClient, from, to string) nfsStat {
	t.Helper()
	st, _ := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opSaveFH)
		e.Uint32(opPutRootFH)
		e.Uint32(opRename)
		encodeName(e, from)
		encodeName(e, to)
		return 4
	})
	return st
}

// RENAME must refuse to replace an object with one of a different type. The
// underlying Rename replaces its target, so an unchecked rename destroyed a
// directory or a file's contents and answered NFS4_OK.
func TestRenameRefusesTypeMismatch(t *testing.T) {
	fsys := facetfs.NewMemFS()
	ctx := t.Context()
	write := func(name, data string) {
		f, err := fsys.OpenFile(ctx, name, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(data))
		f.Close()
	}
	write("/file", "file contents")
	if err := fsys.Mkdir(ctx, "/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	write("/dir/keep", "child")
	write("/other", "other contents")
	if err := fsys.Mkdir(ctx, "/emptydir", 0o755); err != nil {
		t.Fatal(err)
	}
	tc := newTestClient(t, fsys)

	// POSIX: a non-directory onto a directory is EISDIR, a directory onto a
	// non-directory is ENOTDIR.
	if st := renameAtRoot(t, tc, "file", "emptydir"); st != nfs4ErrIsDir {
		t.Fatalf("rename of a file onto a directory = %d, want ISDIR", st)
	}
	if fi, err := fsys.Stat(ctx, "/emptydir"); err != nil || !fi.IsDir() {
		t.Fatalf("the directory was replaced by a file: %v %v", fi, err)
	}

	if st := renameAtRoot(t, tc, "emptydir", "other"); st != nfs4ErrNotDir {
		t.Fatalf("rename of a directory onto a file = %d, want NOTDIR", st)
	}
	if got := readAll(t, fsys, "/other"); string(got) != "other contents" {
		t.Fatalf("the file's contents were destroyed: %q", got)
	}

	if st := renameAtRoot(t, tc, "emptydir", "dir"); st != nfs4ErrNotEmpty {
		t.Fatalf("rename onto a non-empty directory = %d, want NOTEMPTY", st)
	}
	if _, err := fsys.Stat(ctx, "/dir/keep"); err != nil {
		t.Fatalf("the non-empty target lost its child: %v", err)
	}

	// The legal cases still work: onto an empty directory, onto a file, and
	// onto a free name.
	if st := renameAtRoot(t, tc, "dir", "emptydir"); st != nfs4OK {
		t.Fatalf("rename of a directory onto an empty directory = %d, want OK", st)
	}
	if _, err := fsys.Stat(ctx, "/emptydir/keep"); err != nil {
		t.Fatalf("the moved directory lost its child: %v", err)
	}
	if st := renameAtRoot(t, tc, "file", "other"); st != nfs4OK {
		t.Fatalf("rename of a file onto a file = %d, want OK", st)
	}
	if got := readAll(t, fsys, "/other"); string(got) != "file contents" {
		t.Fatalf("content after replacing rename = %q", got)
	}
	if st := renameAtRoot(t, tc, "other", "fresh"); st != nfs4OK {
		t.Fatalf("rename onto a free name = %d, want OK", st)
	}
}
