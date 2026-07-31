package nfs4

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

// readDir implements READDIR (RFC 7530 §16.24). Entry i is issued cookie i+3
// (0 starts a listing; 1 and 2 are reserved) and a resume re-walks the
// directory, skipping already-sent entries. The cookie verifier is the
// directory's change value but is not enforced on resume: with index cookies
// a concurrent mutation can only skip or repeat entries, the volatility the
// change-derived attributes already admit (§16.24.4).
func (c *compound) readDir(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	cookie := d.Uint64()
	verf := d.OpaqueFixed(8)
	dircount := d.Uint32()
	maxcount := d.Uint32()
	requested := decodeBitmap(d)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	switch {
	case cookie == 1 || cookie == 2:
		return status(e, nfs4ErrBadCookie)
	case cookie == 0 && [8]byte(verf) != [8]byte{}:
		return status(e, nfs4ErrBadCookie)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	dirInfo, err := c.s.FileSystem.Stat(c.ctx, c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	dir, err := c.s.FileSystem.OpenFile(c.ctx, c.fh, os.O_RDONLY, 0)
	if err != nil {
		return status(e, fhErr(err))
	}
	defer dir.Close()

	sizeBudget := min(int(maxcount), c.s.responseCap()-e.Len()-128)
	nameBudget := int(dircount)

	e.Uint32(uint32(nfs4OK))
	var cookieVerf [8]byte
	binary.BigEndian.PutUint64(cookieVerf[:], changeOf(dirInfo))
	e.OpaqueFixed(cookieVerf[:])

	start := e.Len()
	var skip uint64
	if cookie > 0 {
		skip = cookie - 2 // resume after entry index cookie-3
	}
	index := uint64(0)
	eof := true
	emitted := 0
listing:
	for {
		page, err := dir.Readdir(256)
		if err != nil && !errors.Is(err, io.EOF) {
			e.Truncate(start - 12)
			return status(e, fhErr(err))
		}
		for _, fi := range page {
			if index >= uint64(c.s.maxDirEntries()) {
				e.Truncate(start - 12)
				return status(e, nfs4ErrResource)
			}
			i := index
			index++
			if i < skip {
				continue
			}
			// The entry is encoded into the reply and rolled back if it does
			// not fit, which keeps a large listing from allocating a buffer
			// per entry.
			mark := e.Len()
			e.Bool(true) // another entry follows
			e.Uint64(i + 3)
			e.String(fi.Name())
			encodeFattr(e, requested, &attrCtx{c: c, path: path.Join(c.fh, fi.Name()), fi: fi})
			nameBudget -= len(fi.Name()) + 8
			if e.Len() > start+sizeBudget-8 || nameBudget < 0 {
				e.Truncate(mark)
				if emitted == 0 {
					e.Truncate(start - 12)
					return status(e, nfs4ErrTooSmall)
				}
				eof = false
				break listing
			}
			emitted++
		}
		if len(page) == 0 || errors.Is(err, io.EOF) {
			break
		}
	}
	e.Bool(false) // end of entries
	e.Bool(eof)
	return nfs4OK
}
