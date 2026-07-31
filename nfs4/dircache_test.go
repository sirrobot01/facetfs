package nfs4

import (
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

func dirOfSize(t *testing.T, n int) facetfs.FileSystem {
	t.Helper()
	fsys := facetfs.NewMemFS()
	for i := range n {
		f, err := fsys.OpenFile(t.Context(), fmt.Sprintf("/e%03d", i), os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	return fsys
}

// readdirPage sends one READDIR and returns the names, the last cookie, the
// verifier, and whether the listing ended.
func readdirPage(t *testing.T, tc *testClient, cookie uint64, verf []byte, maxcount uint32) ([]string, uint64, []byte, bool) {
	t.Helper()
	var attrs bitmap
	attrs.set(attrType)
	st, d := tc.compound(func(e *xdr.Encoder) uint32 {
		e.Uint32(opPutRootFH)
		e.Uint32(opReadDir)
		e.Uint64(cookie)
		e.OpaqueFixed(verf)
		e.Uint32(1 << 20)
		e.Uint32(maxcount)
		encodeBitmap(e, attrs)
		return 2
	})
	if st != nfs4OK {
		t.Fatalf("READDIR status = %d", st)
	}
	expectOp(t, d, opPutRootFH, nfs4OK)
	expectOp(t, d, opReadDir, nfs4OK)
	outVerf := append([]byte(nil), d.OpaqueFixed(8)...)
	var names []string
	for d.Bool() {
		cookie = d.Uint64()
		names = append(names, d.String(maxNameBytes))
		decodeBitmap(d)
		d.Opaque(1 << 16)
	}
	eof := d.Bool()
	if d.Err() != nil {
		t.Fatalf("decode: %v", d.Err())
	}
	return names, cookie, outVerf, eof
}

// A listing is served from the snapshot taken when it started, so entries
// added or removed part way through do not disturb it.
func TestReaddirListingIsStable(t *testing.T) {
	fsys := dirOfSize(t, 40)
	tc := newTestClient(t, fsys)

	first, cookie, verf, eof := readdirPage(t, tc, 0, make([]byte, 8), 700)
	if eof || len(first) == 0 {
		t.Fatalf("first page returned %d entries, eof=%v", len(first), eof)
	}

	// Remove an entry that has not been sent yet and add a new one.
	if err := fsys.RemoveAll(t.Context(), "/e039"); err != nil {
		t.Fatal(err)
	}
	f, err := fsys.OpenFile(t.Context(), "/zzz-new", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	seen := append([]string(nil), first...)
	for !eof {
		var page []string
		page, cookie, verf, eof = readdirPage(t, tc, cookie, verf, 700)
		seen = append(seen, page...)
		if len(seen) > 100 {
			t.Fatal("listing did not finish")
		}
	}
	if len(seen) != 40 {
		t.Fatalf("listing returned %d entries, want the 40 present when it started", len(seen))
	}
	for _, name := range seen {
		if name == "zzz-new" {
			t.Fatal("an entry created mid-listing appeared in the snapshot")
		}
	}
	if seen[39] != "e039" {
		t.Fatalf("last entry = %q, want the one removed mid-listing to remain in the snapshot", seen[39])
	}
}

// A resume naming a snapshot the server no longer holds still completes, by
// reading the directory again.
func TestReaddirResumeWithoutSnapshot(t *testing.T) {
	tc := newTestClient(t, dirOfSize(t, 30))

	first, cookie, _, eof := readdirPage(t, tc, 0, make([]byte, 8), 700)
	if eof {
		t.Fatal("the whole listing fitted in one page")
	}
	unknown := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	seen := len(first)
	for !eof {
		var page []string
		page, cookie, _, eof = readdirPage(t, tc, cookie, unknown, 700)
		seen += len(page)
		if seen > 60 {
			t.Fatal("listing did not finish")
		}
	}
	if seen != 30 {
		t.Fatalf("listing returned %d entries, want 30", seen)
	}
}

func TestDirCacheBounds(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newDirCache(func() time.Time { return now }, time.Minute, 10)
	entries := func(n int) []fs.FileInfo { return make([]fs.FileInfo, n) }

	c.put("/a", 1, entries(4))
	c.put("/b", 2, entries(4))
	if _, ok := c.lookup("/a", 1); !ok {
		t.Fatal("/a was dropped early")
	}

	// The third listing does not fit, so the oldest goes.
	c.put("/c", 3, entries(4))
	if _, ok := c.lookup("/a", 1); ok {
		t.Fatal("the oldest snapshot was not evicted")
	}
	if _, ok := c.lookup("/c", 3); !ok {
		t.Fatal("the newest snapshot was evicted instead")
	}
	if c.total > c.max {
		t.Fatalf("cache holds %d entries, above the bound of %d", c.total, c.max)
	}

	// A listing larger than the whole bound is not held at all.
	c.put("/big", 4, entries(11))
	if _, ok := c.lookup("/big", 4); ok {
		t.Fatal("an oversized listing was cached")
	}

	// Snapshots expire.
	now = now.Add(2 * time.Minute)
	if _, ok := c.lookup("/c", 3); ok {
		t.Fatal("an expired snapshot was returned")
	}
	c.put("/d", 5, entries(4))
	if c.total != 4 {
		t.Fatalf("expired snapshots were not reclaimed: total = %d", c.total)
	}
	if len(c.order) != 1 {
		t.Fatalf("eviction order holds %d keys, want 1", len(c.order))
	}
}
