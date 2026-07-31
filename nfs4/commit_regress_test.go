package nfs4

import (
	"context"
	"os"
	"testing"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// syncCountingFS counts the Sync calls its files receive.
type syncCountingFS struct {
	facetfs.FileSystem
	syncs *int
}

type syncCountingFile struct {
	facetfs.File
	syncs *int
}

func (f syncCountingFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (facetfs.File, error) {
	file, err := f.FileSystem.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	return syncCountingFile{File: file, syncs: f.syncs}, nil
}

func (f syncCountingFile) Sync() error {
	*f.syncs++
	return nil
}

// COMMIT and a stable WRITE must succeed on a FileSystem whose File cannot
// sync. Both once answered NFS4ERR_NOTSUPP, which is not a legal status for
// either operation and left clients unable to complete a write at all.
func TestCommitWithoutSyncSucceeds(t *testing.T) {
	fsys := facetfs.NewMemFS()
	f, err := fsys.OpenFile(t.Context(), "/c", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	tc := newTestClient(t, fsys)

	writeAt := func(stable uint32, data string) (nfsStat, uint32) {
		st, d := tc.compound(func(e *xdr.Encoder) uint32 {
			e.Uint32(opPutRootFH)
			e.Uint32(opLookup)
			encodeName(e, "c")
			e.Uint32(opWrite)
			encodeStateid(e, 0, [12]byte{})
			e.Uint64(0)
			e.Uint32(stable)
			e.Opaque([]byte(data))
			return 3
		})
		if st != nfs4OK {
			return st, 0
		}
		expectOp(t, d, opPutRootFH, nfs4OK)
		expectOp(t, d, opLookup, nfs4OK)
		expectOp(t, d, opWrite, nfs4OK)
		d.Uint32() // count
		return st, d.Uint32()
	}

	st, committed := writeAt(fileSync4, "durable")
	if st != nfs4OK {
		t.Fatalf("stable WRITE without Sync = %d, want OK", st)
	}
	if committed != unstable4 {
		t.Fatalf("committed = %d, want UNSTABLE4: the server cannot flush this filesystem", committed)
	}

	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opLookup)
		encodeName(e, "c")
		e.Uint32(opCommit)
		e.Uint64(0)
		e.Uint32(0)
		return 3
	})
	if st != nfs4OK {
		t.Fatalf("COMMIT without Sync = %d, want OK", st)
	}
	if got := readAll(t, fsys, "/c"); string(got) != "durable" {
		t.Fatalf("content = %q", got)
	}
}

// A stable WRITE reports FILE_SYNC4 only when the file really was flushed,
// and COMMIT flushes the file the client wrote through.
func TestCommitFlushesTheOpenFile(t *testing.T) {
	syncs := 0
	fsys := syncCountingFS{FileSystem: facetfs.NewMemFS(), syncs: &syncs}
	f, err := fsys.OpenFile(t.Context(), "/s", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	tc := newTestClient(t, fsys)
	clientID := tc.setClientID()

	st, opened := openAtRoot(t, tc, clientID, "sync-owner", 0, shareBoth, denyNone, "s", nil, nil, nil)
	if st != nfs4OK {
		t.Fatalf("OPEN status = %d", st)
	}
	opened.state = confirmOpen(t, tc, opened.fh, opened.state, 1)

	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opWrite)
		putStateid(e, opened.state)
		e.Uint64(0)
		e.Uint32(fileSync4)
		e.Opaque([]byte("data"))
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("stable WRITE = %d", st)
	}
	expectOp(t, d, opPutFH, nfs4OK)
	expectOp(t, d, opWrite, nfs4OK)
	d.Uint32()
	if committed := d.Uint32(); committed != fileSync4 {
		t.Fatalf("committed = %d, want FILE_SYNC4 on a filesystem that can sync", committed)
	}
	if syncs == 0 {
		t.Fatal("a stable WRITE reported FILE_SYNC4 without calling Sync")
	}

	before := syncs
	st, _ = tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutFH)
		e.Opaque(opened.fh)
		e.Uint32(opCommit)
		e.Uint64(0)
		e.Uint32(0)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("COMMIT = %d", st)
	}
	if syncs == before {
		t.Fatal("COMMIT did not flush the file the client wrote through")
	}
}
