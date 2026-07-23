package memfs

import (
	"encoding/binary"

	"github.com/sirrobot01/facetfs"
)

func (f *FS) cursor(revision uint64, name string) facetfs.DirCursor {
	b := make([]byte, 8, 8+len(name))
	binary.BigEndian.PutUint64(b, revision)
	b = append(b, name...)
	return facetfs.DirCursor(f.cursors.Seal(b))
}

func (f *FS) parseCursor(cursor facetfs.DirCursor) (uint64, string, bool) {
	b, ok := f.cursors.Open(string(cursor))
	if !ok || len(b) < 8 {
		return 0, "", false
	}
	return binary.BigEndian.Uint64(b[:8]), string(b[8:]), true
}
