package nfs4

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// readDir implements READDIR (RFC 7530 §16.24). Entry i is issued cookie i+3;
// 0 starts a listing and 1 and 2 are reserved.
//
// A listing is served from a snapshot of the directory taken when it starts,
// which the cookie verifier names. That keeps one listing stable and keeps a
// resume from re-reading the whole directory to find where it left off. When
// the snapshot has been dropped the server reads the directory again and the
// entries may shift, the volatility index cookies always admit (§16.24.4).
func (c *compound) readDir(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	cookie := d.Uint64()
	verfBytes := d.OpaqueFixed(8)
	dircount := d.Uint32()
	maxcount := d.Uint32()
	requested := decodeBitmap(d)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	switch {
	case cookie == 1 || cookie == 2:
		return status(e, nfs4ErrBadCookie)
	case cookie == 0 && [8]byte(verfBytes) != [8]byte{}:
		return status(e, nfs4ErrBadCookie)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}

	verf := binary.BigEndian.Uint64(verfBytes)
	var entries []fs.FileInfo
	held := false
	if cookie != 0 {
		entries, held = c.s.dirs.lookup(c.fh, verf)
	}
	if !held {
		var st nfsStat
		if entries, st = c.readAllEntries(); st != nfs4OK {
			return status(e, st)
		}
		if cookie == 0 {
			verf = c.s.dirs.mint()
		}
		c.s.dirs.put(c.fh, verf, entries)
	}

	from := 0
	if cookie != 0 {
		// Entry i carries cookie i+3, so a resume starts one past it.
		if resume := cookie - 2; resume < uint64(len(entries)) {
			from = int(resume)
		} else {
			from = len(entries)
		}
	}

	mark := e.Len()
	sizeBudget := min(int(maxcount), c.s.responseCap()-mark-128)
	nameBudget := int(dircount)

	e.Uint32(uint32(nfs4OK))
	binary.BigEndian.PutUint64(verfBytes[:], verf)
	e.OpaqueFixed(verfBytes)
	body := e.Len()

	eof := true
	emitted := 0
	for i := from; i < len(entries); i++ {
		fi := entries[i]
		// The entry is encoded into the reply and rolled back if it does not
		// fit, which keeps a large listing from allocating a buffer per entry.
		entryAt := e.Len()
		e.Bool(true) // another entry follows
		e.Uint64(uint64(i) + 3)
		e.String(fi.Name())
		encodeFattr(e, requested, &attrCtx{c: c, path: path.Join(c.fh, fi.Name()), fi: fi})
		nameBudget -= len(fi.Name()) + 8
		if e.Len()-body > sizeBudget-8 || nameBudget < 0 {
			e.Truncate(entryAt)
			if emitted == 0 {
				e.Truncate(mark)
				return status(e, nfs4ErrTooSmall)
			}
			eof = false
			break
		}
		emitted++
	}
	e.Bool(false) // end of entries
	e.Bool(eof)
	return nfs4OK
}

// readAllEntries reads a directory in full. Reading it once per listing costs
// less than the repeated walks a paged resume would otherwise need.
func (c *compound) readAllEntries() ([]fs.FileInfo, nfsStat) {
	dir, err := c.s.FileSystem.OpenFile(c.ctx, c.fh, os.O_RDONLY, 0)
	if err != nil {
		return nil, fhErr(err)
	}
	defer dir.Close()

	limit := c.s.maxDirEntries()
	var entries []fs.FileInfo
	for {
		page, err := dir.Readdir(256)
		entries = append(entries, page...)
		if len(entries) > limit {
			return nil, nfs4ErrResource
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return entries, nfs4OK
			}
			return nil, fhErr(err)
		}
		if len(page) == 0 {
			return entries, nfs4OK
		}
	}
}
