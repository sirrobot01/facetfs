package nfs4

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

type setTimeValue struct {
	server bool
	value  time.Time
}

type setAttrValues struct {
	size    *int64
	mode    *fs.FileMode
	atime   *setTimeValue
	mtime   *setTimeValue
	applied bitmap
}

// decodeSetAttrs reads the attributes a request wants to change. An
// attribute the server reports but cannot set is read-only and gets
// NFS4ERR_INVAL; NFS4ERR_ATTRNOTSUPP is reserved for one the server does not
// have at all (RFC 7530 §16.32.4).
func decodeSetAttrs(supported bitmap, mask bitmap, vals []byte) (*setAttrValues, nfsStat) {
	a := &setAttrValues{}
	d := xdr.NewDecoder(vals)
	for i := 0; i < maxBitmapWords*32; i++ {
		if !mask.has(i) {
			continue
		}
		switch i {
		case attrSize:
			n := d.Uint64()
			if n > math.MaxInt64 {
				return a, nfs4ErrFBig
			}
			v := int64(n)
			a.size = &v
		case attrMode:
			v := fs.FileMode(d.Uint32() & 0o7777)
			a.mode = &v
		case attrTimeAccessSet:
			v, st := decodeSetTime(d)
			if st != nfs4OK {
				return a, st
			}
			a.atime = &v
		case attrTimeModifySet:
			v, st := decodeSetTime(d)
			if st != nfs4OK {
				return a, st
			}
			a.mtime = &v
		default:
			if supported.has(i) {
				return a, nfs4ErrInval
			}
			return a, nfs4ErrAttrNotSupp
		}
	}
	if d.Err() != nil || d.Remaining() != 0 {
		return a, nfs4ErrBadXDR
	}
	return a, nfs4OK
}

func decodeSetTime(d *xdr.Decoder) (setTimeValue, nfsStat) {
	switch d.Uint32() {
	case 0: // SET_TO_SERVER_TIME4
		return setTimeValue{server: true}, nfs4OK
	case 1: // SET_TO_CLIENT_TIME4
		sec := int64(d.Uint64())
		nsec := d.Uint32()
		if nsec >= 1_000_000_000 {
			return setTimeValue{}, nfs4ErrInval
		}
		return setTimeValue{value: time.Unix(sec, int64(nsec))}, nfs4OK
	default:
		return setTimeValue{}, nfs4ErrInval
	}
}

func (c *compound) applySetAttrs(p string, a *setAttrValues, named bool) nfsStat {
	if a.size == nil && a.mode == nil && a.atime == nil && a.mtime == nil {
		return nfs4OK
	}
	setfs, ok := c.s.FileSystem.(facetfs.SetStatFS)
	if !ok {
		return nfs4ErrNotSupp
	}
	if a.size != nil {
		if err := setfs.Truncate(c.ctx, p, *a.size); err != nil {
			return mutationErr(err, named)
		}
		a.applied.set(attrSize)
	}
	if a.mode != nil {
		if err := setfs.Chmod(c.ctx, p, *a.mode); err != nil {
			return mutationErr(err, named)
		}
		a.applied.set(attrMode)
	}
	if a.atime != nil || a.mtime != nil {
		fi, err := c.lstatOrStat(p)
		if err != nil {
			return mutationErr(err, named)
		}
		atime, mtime := fi.ModTime(), fi.ModTime()
		now := c.s.state.now()
		if a.atime != nil {
			atime = a.atime.value
			if a.atime.server {
				atime = now
			}
		}
		if a.mtime != nil {
			mtime = a.mtime.value
			if a.mtime.server {
				mtime = now
			}
		}
		if err := setfs.Chtimes(c.ctx, p, atime, mtime); err != nil {
			return mutationErr(err, named)
		}
		if a.atime != nil {
			a.applied.set(attrTimeAccessSet)
		}
		if a.mtime != nil {
			a.applied.set(attrTimeModifySet)
		}
	}
	return nfs4OK
}

func mutationErr(err error, named bool) nfsStat {
	if named {
		return nameErr(err)
	}
	return fhErr(err)
}

func (c *compound) setAttr(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	stateSeq, other := decodeStateid(d)
	mask := decodeBitmap(d)
	vals := d.Opaque(uint32(c.s.requestCap()))
	if d.Err() != nil {
		e.Uint32(uint32(nfs4ErrBadXDR))
		encodeBitmap(e, nil)
		return nfs4ErrBadXDR
	}
	a, st := decodeSetAttrs(c.s.supported, mask, vals)
	if st == nfs4OK && !c.hasFH {
		st = nfs4ErrNoFilehandle
	}
	if st == nfs4OK && a.size != nil {
		// A directory has no size to set (RFC 7530 §16.32.4).
		fi, err := c.lstatOrStat(c.fh)
		switch {
		case err != nil:
			st = fhErr(err)
		case fi.IsDir():
			st = nfs4ErrIsDir
		}
	}
	// A size or time change makes other clients' delegations false
	// (RFC 7530 §10.4.3); a bare mode change does not.
	if st == nfs4OK && (a.size != nil || a.atime != nil || a.mtime != nil) {
		st = c.s.recallDelegations(c.fh, c.s.state.clientForStateid(other))
	}
	var access uint32
	if st == nfs4OK {
		_, access, _, st = c.s.state.resolveIOStateid(stateSeq, other, c.fh)
	}
	if st == nfs4OK && a.size != nil && other != ([12]byte{}) && other != allOnesOther && access&shareWrite == 0 {
		st = nfs4ErrOpenMode
	}
	if st == nfs4OK {
		st = c.applySetAttrs(c.fh, a, false)
	}
	e.Uint32(uint32(st))
	encodeBitmap(e, a.applied)
	return st
}

func (c *compound) create(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	typ := d.Uint32()
	var linkTarget string
	switch typ {
	case nf4Lnk:
		linkTarget = d.String(maxLinkData)
	case nf4Blk, nf4Chr:
		d.Uint32()
		d.Uint32()
	case nf4Sock, nf4Fifo, nf4Dir:
	default:
		// Unknown discriminants have no arm.
	}
	name, nameStatus := decodeName(d)
	mask := decodeBitmap(d)
	vals := d.Opaque(uint32(c.s.requestCap()))
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if nameStatus != nfs4OK {
		return status(e, nameStatus)
	}
	attrs, st := decodeSetAttrs(c.s.supported, mask, vals)
	if st != nfs4OK {
		return status(e, st)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	switch typ {
	case nf4Reg:
		return status(e, nfs4ErrInval)
	case nf4Blk, nf4Chr, nf4Sock, nf4Fifo:
		return status(e, nfs4ErrBadType)
	case nf4Lnk:
		if len(linkTarget) > maxLinkData {
			return status(e, nfs4ErrNameTooLong)
		}
		if _, ok := c.s.FileSystem.(facetfs.SymlinkFS); !ok {
			return status(e, nfs4ErrNotSupp)
		}
	case nf4Dir:
		if attrs.size != nil {
			return status(e, nfs4ErrInval)
		}
	default:
		return status(e, nfs4ErrBadType)
	}
	target := path.Join(c.fh, name)
	if _, err := c.lstatOrStat(target); err == nil {
		return status(e, nfs4ErrExist)
	} else if nameErr(err) != nfs4ErrNoEnt {
		return status(e, nameErr(err))
	}
	before := c.changeOfDir(c.fh)
	perm := fs.FileMode(0o755)
	if attrs.mode != nil {
		perm = *attrs.mode
	}
	var err error
	if typ == nf4Dir {
		err = c.s.FileSystem.Mkdir(c.ctx, target, perm)
	} else {
		err = c.s.FileSystem.(facetfs.SymlinkFS).Symlink(c.ctx, linkTarget, target)
	}
	if err != nil {
		return status(e, nameErr(err))
	}
	createdMode := attrs.mode
	if typ == nf4Dir && createdMode != nil {
		attrs.mode = nil
		attrs.applied.set(attrMode)
	}
	// SetStatFS operates by path and follows symlinks. For a newly created
	// symlink, leave createattrs unset and report that honestly in attrset.
	if typ != nf4Lnk {
		st = c.applySetAttrs(target, attrs, true)
	}
	if st != nfs4OK {
		attrs.mode = createdMode
		_ = c.s.FileSystem.RemoveAll(c.ctx, target)
		return status(e, st)
	}
	attrs.mode = createdMode
	parent := c.fh
	c.fh = target
	e.Uint32(uint32(nfs4OK))
	encodeChangeInfo(e, before, c.changeOfDir(parent))
	encodeBitmap(e, attrs.applied)
	return nfs4OK
}

func (c *compound) remove(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	name, st := decodeName(d)
	if st != nfs4OK {
		return status(e, st)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	target := path.Join(c.fh, name)
	fi, err := c.lstatOrStat(target)
	if err != nil {
		return status(e, nameErr(err))
	}
	// REMOVE names no client, so every delegation on the path is recalled,
	// the caller's own included.
	if st := c.s.recallDelegations(target, nil); st != nfs4OK {
		return status(e, st)
	}
	before := c.changeOfDir(c.fh)
	// A non-recursive remove refuses a directory holding entries by itself.
	// Falling back to checking and then calling the recursive RemoveAll would
	// delete whatever was created in between.
	if remover, ok := c.s.FileSystem.(facetfs.RemoveFS); ok {
		if err := remover.Remove(c.ctx, target); err != nil {
			return status(e, nameErr(err))
		}
	} else {
		if fi.IsDir() {
			if st := c.requireEmptyDir(target); st != nfs4OK {
				return status(e, st)
			}
		}
		if err := c.s.FileSystem.RemoveAll(c.ctx, target); err != nil {
			return status(e, nameErr(err))
		}
	}
	e.Uint32(uint32(nfs4OK))
	encodeChangeInfo(e, before, c.changeOfDir(c.fh))
	return nfs4OK
}

// requireEmptyDir reports NFS4ERR_NOTEMPTY unless the directory is empty.
// Callers must use it before any removal, because FileSystem.RemoveAll
// deletes a subtree.
func (c *compound) requireEmptyDir(p string) nfsStat {
	dir, err := c.s.FileSystem.OpenFile(c.ctx, p, os.O_RDONLY, 0)
	if err != nil {
		return nameErr(err)
	}
	entries, readErr := dir.Readdir(1)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nameErr(readErr)
	}
	if len(entries) != 0 {
		return nfs4ErrNotEmpty
	}
	return nfs4OK
}

func (c *compound) rename(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	oldName, oldStatus := decodeName(d)
	newName, newStatus := decodeName(d)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if oldStatus != nfs4OK {
		return status(e, oldStatus)
	}
	if newStatus != nfs4OK {
		return status(e, newStatus)
	}
	if !c.hasSaved || !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	if st := c.dirAt(c.saved); st != nfs4OK {
		return status(e, st)
	}
	if st := c.dirAt(c.fh); st != nfs4OK {
		return status(e, st)
	}
	oldPath, newPath := path.Join(c.saved, oldName), path.Join(c.fh, newName)
	fi, err := c.lstatOrStat(oldPath)
	if err != nil {
		return status(e, nameErr(err))
	}
	if fi.IsDir() && (newPath == oldPath || strings.HasPrefix(newPath, oldPath+"/")) && newPath != oldPath {
		return status(e, nfs4ErrInval)
	}
	// FileSystem.Rename replaces the target, so the type rules POSIX enforces
	// are this layer's to apply: without them a file silently replaces a
	// directory, or a directory replaces a file and its contents.
	if newPath != oldPath {
		switch target, err := c.lstatOrStat(newPath); {
		case err != nil && nameErr(err) != nfs4ErrNoEnt:
			return status(e, nameErr(err))
		case err != nil:
		case fi.IsDir() && !target.IsDir():
			return status(e, nfs4ErrNotDir)
		case !fi.IsDir() && target.IsDir():
			return status(e, nfs4ErrIsDir)
		case target.IsDir():
			if st := c.requireEmptyDir(newPath); st != nfs4OK {
				return status(e, st)
			}
		}
	}
	oldBefore, newBefore := c.changeOfDir(c.saved), c.changeOfDir(c.fh)
	if oldPath != newPath {
		// A rename disturbs delegations on either name (RFC 7530 §10.4.3).
		if st := c.s.recallDelegations(oldPath, nil); st != nfs4OK {
			return status(e, st)
		}
		if st := c.s.recallDelegations(newPath, nil); st != nfs4OK {
			return status(e, st)
		}
		if err := c.s.FileSystem.Rename(c.ctx, oldPath, newPath); err != nil {
			return status(e, nameErr(err))
		}
		c.s.state.renamePath(oldPath, newPath)
	}
	e.Uint32(uint32(nfs4OK))
	encodeChangeInfo(e, oldBefore, c.changeOfDir(c.saved))
	encodeChangeInfo(e, newBefore, c.changeOfDir(c.fh))
	return nfs4OK
}

func (c *compound) link(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	name, st := decodeName(d)
	if st != nfs4OK {
		return status(e, st)
	}
	linkfs, ok := c.s.FileSystem.(facetfs.LinkFS)
	if !ok {
		return status(e, nfs4ErrNotSupp)
	}
	if !c.hasSaved || !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	if st := c.dirAt(c.fh); st != nfs4OK {
		return status(e, st)
	}
	fi, err := c.lstatOrStat(c.saved)
	if err != nil {
		return status(e, fhErr(err))
	}
	if fi.IsDir() {
		return status(e, nfs4ErrIsDir)
	}
	before := c.changeOfDir(c.fh)
	// A new link changes the file's link count, which a delegated client
	// caches with the rest of its attributes.
	if st := c.s.recallDelegations(c.saved, nil); st != nfs4OK {
		return status(e, st)
	}
	if err := linkfs.Link(c.ctx, c.saved, path.Join(c.fh, name)); err != nil {
		return status(e, nameErr(err))
	}
	e.Uint32(uint32(nfs4OK))
	encodeChangeInfo(e, before, c.changeOfDir(c.fh))
	return nfs4OK
}

func (c *compound) dirAt(p string) nfsStat {
	fi, err := c.lstatOrStat(p)
	if err != nil {
		return fhErr(err)
	}
	if fi.IsDir() {
		return nfs4OK
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nfs4ErrSymlink
	}
	return nfs4ErrNotDir
}
