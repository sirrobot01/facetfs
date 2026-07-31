package nfs4

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

const (
	unstable4 = 0
	dataSync4 = 1
	fileSync4 = 2
)

func (c *compound) ioState(stateSeq uint32, other [12]byte, write bool) (*openFile, bool, nfsStat) {
	if !c.hasFH {
		return nil, false, nfs4ErrNoFilehandle
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return nil, false, fhErr(err)
	}
	if fi.IsDir() {
		return nil, false, nfs4ErrIsDir
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, false, nfs4ErrSymlink
	}
	file, access, special, st := c.s.state.resolveIOStateid(stateSeq, other, c.fh)
	if st != nfs4OK {
		return nil, false, st
	}
	if !special {
		needed := uint32(shareRead)
		if write {
			needed = shareWrite
		}
		if access&needed == 0 {
			return nil, false, nfs4ErrOpenMode
		}
		if file != nil {
			return file, false, nfs4OK
		}
		// A delegation stateid resolves with no open file behind it; it is
		// served like the special stateids, for the length of the request.
	}
	if c.s.state.denyBlocksAnonymous(c.fh, write) {
		return nil, false, nfs4ErrLocked
	}
	flags := os.O_RDONLY
	if write {
		flags = os.O_WRONLY
	}
	f, err := c.s.FileSystem.OpenFile(c.ctx, c.fh, flags, 0)
	if err != nil {
		return nil, false, fhErr(err)
	}
	return newOpenFile(f), true, nfs4OK
}

func (c *compound) read(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	stateSeq, other := decodeStateid(d)
	offset := d.Uint64()
	count := d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if offset > math.MaxInt64 || uint64(count) > uint64(math.MaxInt64)-offset {
		return status(e, nfs4ErrInval)
	}
	// A READ may return fewer bytes than asked for (RFC 7530 §16.23.3), which
	// is friendlier than refusing a client that did not read maxread first.
	count = min(count, c.s.maxRead())
	f, temporary, st := c.ioState(stateSeq, other, false)
	if st != nfs4OK {
		return status(e, st)
	}
	if temporary {
		defer f.Close()
	}
	// The data is read straight into the reply buffer: staging it elsewhere
	// would copy every byte again on the way out.
	mark := e.Len()
	e.Uint32(uint32(nfs4OK))
	eofAt := e.Len()
	e.Bool(false)
	lengthAt := e.Len()
	e.Uint32(0)
	n, err := f.ReadAt(e.Reserve(count), int64(offset))
	if n < 0 || n > int(count) {
		e.Truncate(mark)
		return status(e, nfs4ErrServerFault)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		e.Truncate(mark)
		return status(e, fhErr(err))
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		e.Truncate(mark)
		return status(e, fhErr(statErr))
	}
	if offset+uint64(n) >= uint64(max(fi.Size(), 0)) {
		e.PatchUint32(eofAt, 1)
	}
	e.PatchUint32(lengthAt, uint32(n))
	e.Truncate(lengthAt + 4 + n + int(xdr.Padding(uint32(n))))
	return nfs4OK
}

func (c *compound) write(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	stateSeq, other := decodeStateid(d)
	offset := d.Uint64()
	stable := d.Uint32()
	data := d.Opaque(uint32(c.s.requestCap()))
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	// A WRITE larger than maxwrite is answered with a short write, which the
	// reply's count already reports, rather than a framing error.
	if uint32(len(data)) > c.s.maxWrite() {
		data = data[:c.s.maxWrite()]
	}
	if offset > math.MaxInt64 || uint64(len(data)) > uint64(math.MaxInt64)-offset {
		return status(e, nfs4ErrInval)
	}
	if stable > fileSync4 {
		return status(e, nfs4ErrInval)
	}
	// A write makes every other client's delegation false; recall before the
	// data lands. The writer's own delegations are left alone.
	if c.hasFH {
		if st := c.s.recallDelegations(c.fh, c.s.state.clientForStateid(other)); st != nfs4OK {
			return status(e, st)
		}
	}
	f, temporary, st := c.ioState(stateSeq, other, true)
	if st != nfs4OK {
		return status(e, st)
	}
	if temporary {
		defer f.Close()
	}
	n, err := f.WriteAt(data, int64(offset))
	if n < 0 || n > len(data) {
		return status(e, nfs4ErrServerFault)
	}
	if err != nil {
		return status(e, fhErr(err))
	}
	// Report FILE_SYNC4 only for a write this server actually flushed. A
	// FileSystem whose File cannot sync gets UNSTABLE4, which asks the client
	// for a COMMIT rather than claiming durability the server cannot provide.
	committed := uint32(unstable4)
	if stable != unstable4 && len(data) != 0 {
		flushed, err := f.sync()
		if err != nil {
			return status(e, fhErr(err))
		}
		if flushed {
			committed = fileSync4
		}
	}
	e.Uint32(uint32(nfs4OK))
	e.Uint32(uint32(n))
	e.Uint32(committed)
	e.OpaqueFixed(c.s.verifier[:])
	return nfs4OK
}

func (c *compound) commit(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	offset := d.Uint64()
	count := d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	if offset > math.MaxInt64 || count != 0 && uint64(count) > uint64(math.MaxInt64)-offset {
		return status(e, nfs4ErrInval)
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	if fi.IsDir() {
		return status(e, nfs4ErrIsDir)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return status(e, nfs4ErrSymlink)
	}
	// Flush the files the client actually wrote through: a FileSystem may
	// buffer inside the File, so a fresh handle would flush nothing.
	opens := c.s.state.openFilesFor(c.fh)
	for _, open := range opens {
		if _, err := open.sync(); err != nil {
			return status(e, fhErr(err))
		}
	}
	if len(opens) == 0 {
		// The data was written without an open stateid, so nothing this
		// server holds is buffered, but a native filesystem may still have
		// the file's own pages dirty. The handle must be writable: Windows
		// refuses FlushFileBuffers on a read-only one.
		f, err := c.s.FileSystem.OpenFile(c.ctx, c.fh, os.O_WRONLY, 0)
		if err != nil {
			return status(e, fhErr(err))
		}
		open := newOpenFile(f)
		_, syncErr := open.sync()
		open.Close()
		if syncErr != nil {
			return status(e, fhErr(syncErr))
		}
	}
	// A FileSystem with no sync at all still answers OK: the write verifier
	// changes when the server restarts, which is what tells a client its
	// unstable writes must be sent again.
	e.Uint32(uint32(nfs4OK))
	e.OpaqueFixed(c.s.verifier[:])
	return nfs4OK
}
