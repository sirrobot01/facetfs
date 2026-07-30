package nfs4

import (
	"bytes"
	"io/fs"
	"path"
	"strings"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

// status encodes an op result that carries no body beyond its status.
func status(e *xdr.Encoder, st nfsStat) nfsStat {
	e.Uint32(uint32(st))
	return st
}

// decodeName decodes a component4 and applies the RFC 7530 §12 name rules.
func decodeName(d *xdr.Decoder) (string, nfsStat) {
	raw := d.Opaque(4 * maxNameBytes)
	switch {
	case d.Err() != nil:
		return "", nfs4ErrBadXDR
	case len(raw) == 0:
		return "", nfs4ErrInval
	case len(raw) > maxNameBytes:
		return "", nfs4ErrNameTooLong
	}
	name := string(raw)
	if name == "." || name == ".." {
		return "", nfs4ErrBadName
	}
	if err := names.Validate(name); err != nil {
		return "", nfs4ErrInval
	}
	return name, nfs4OK
}

// lstatOrStat reports the object itself: the symlink, not its target, when
// the filesystem can tell them apart.
func (c *compound) lstatOrStat(p string) (fs.FileInfo, error) {
	if symlinks, ok := c.s.FileSystem.(facetfs.SymlinkFS); ok {
		return symlinks.Lstat(c.ctx, p)
	}
	return c.s.FileSystem.Stat(c.ctx, p)
}

func (c *compound) putRootFH(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	c.fh, c.hasFH = "/", true
	return status(e, nfs4OK)
}

func (c *compound) putFH(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	fh := d.Opaque(maxFHBytes)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	p, st := c.s.fh.unseal(fh)
	if st != nfs4OK {
		return status(e, st)
	}
	// A sealed path is clean by construction; re-validate anyway so a leaked
	// key cannot smuggle traversal segments.
	if p != "/" {
		for segment := range strings.SplitSeq(p[1:], "/") {
			if names.Validate(segment) != nil {
				return status(e, nfs4ErrBadHandle)
			}
		}
	}
	c.fh, c.hasFH = p, true
	return status(e, nfs4OK)
}

func (c *compound) getFH(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	e.Uint32(uint32(nfs4OK))
	e.Opaque(c.s.fh.seal(c.fh))
	return nfs4OK
}

func (c *compound) saveFH(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	c.saved, c.hasSaved = c.fh, true
	return status(e, nfs4OK)
}

func (c *compound) restoreFH(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	if !c.hasSaved {
		return status(e, nfs4ErrRestoreFH)
	}
	c.fh, c.hasFH = c.saved, true
	return status(e, nfs4OK)
}

// dirFH verifies the current filehandle references a directory, the
// precondition shared by every name-consuming op.
func (c *compound) dirFH() nfsStat {
	if !c.hasFH {
		return nfs4ErrNoFilehandle
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return fhErr(err)
	}
	switch {
	case fi.IsDir():
		return nfs4OK
	case fi.Mode()&fs.ModeSymlink != 0:
		return nfs4ErrSymlink
	default:
		return nfs4ErrNotDir
	}
}

func (c *compound) lookup(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	name, st := decodeName(d)
	if st != nfs4OK {
		return status(e, st)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	child := path.Join(c.fh, name)
	if _, err := c.lstatOrStat(child); err != nil {
		return status(e, nameErr(err))
	}
	c.fh = child
	return status(e, nfs4OK)
}

func (c *compound) lookupP(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	if c.fh == "/" {
		return status(e, nfs4ErrNoEnt)
	}
	c.fh = path.Dir(c.fh)
	return status(e, nfs4OK)
}

func (c *compound) getAttr(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	requested := decodeBitmap(d)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	e.Uint32(uint32(nfs4OK))
	encodeFattr(e, requested, &attrCtx{c: c, path: c.fh, fi: fi})
	return nfs4OK
}

// ACCESS4 bits.
const (
	accessRead    = 1
	accessLookup  = 2
	accessModify  = 4
	accessExtend  = 8
	accessDelete  = 16
	accessExecute = 32
)

func (c *compound) access(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	requested := d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	// Rights derive from permission bits alone: the trusted-network model has
	// no principal to evaluate against.
	mode := fi.Mode()
	var supported, granted uint32
	if fi.IsDir() {
		supported = accessRead | accessLookup | accessModify | accessExtend | accessDelete
		if mode&0o444 != 0 {
			granted |= accessRead
		}
		if mode&0o111 != 0 {
			granted |= accessLookup
		}
		if mode&0o222 != 0 {
			granted |= accessModify | accessExtend | accessDelete
		}
	} else {
		supported = accessRead | accessModify | accessExtend | accessExecute
		if mode&0o444 != 0 {
			granted |= accessRead
		}
		if mode&0o222 != 0 {
			granted |= accessModify | accessExtend
		}
		if mode&0o111 != 0 {
			granted |= accessExecute
		}
	}
	e.Uint32(uint32(nfs4OK))
	e.Uint32(supported & requested)
	e.Uint32(granted & requested)
	return nfs4OK
}

func (c *compound) readLink(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	symlinks, ok := c.s.FileSystem.(facetfs.SymlinkFS)
	if !ok {
		return status(e, nfs4ErrNotSupp)
	}
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	target, err := symlinks.Readlink(c.ctx, c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	if len(target) > maxLinkData {
		return status(e, nfs4ErrServerFault)
	}
	e.Uint32(uint32(nfs4OK))
	e.String(target)
	return nfs4OK
}

func (c *compound) secInfo(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	name, st := decodeName(d)
	if st != nfs4OK {
		return status(e, st)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}
	if _, err := c.lstatOrStat(path.Join(c.fh, name)); err != nil {
		return status(e, nameErr(err))
	}
	e.Uint32(uint32(nfs4OK))
	e.Uint32(2)
	e.Uint32(authSys)
	e.Uint32(authNone)
	return nfs4OK
}

func (c *compound) verify(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	return c.verifyCompare(d, e, true)
}

func (c *compound) nVerify(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	return c.verifyCompare(d, e, false)
}

// verifyCompare implements VERIFY and NVERIFY by re-encoding the requested
// attributes and byte-comparing against the client's fattr4 (§16.37.4).
func (c *compound) verifyCompare(d *xdr.Decoder, e *xdr.Encoder, wantSame bool) nfsStat {
	requested := decodeBitmap(d)
	vals := d.Opaque(uint32(c.s.requestCap()))
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	if !c.hasFH {
		return status(e, nfs4ErrNoFilehandle)
	}
	if requested.has(attrTimeAccessSet) || requested.has(attrTimeModifySet) {
		return status(e, nfs4ErrInval)
	}
	for i := 0; i <= maxBitmapWords*32; i++ {
		if requested.has(i) && !c.s.supported.has(i) {
			return status(e, nfs4ErrAttrNotSupp)
		}
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return status(e, fhErr(err))
	}
	var ours xdr.Encoder
	a := &attrCtx{c: c, path: c.fh, fi: fi}
	for i := 0; i <= attrMountedOnFileID; i++ {
		if requested.has(i) {
			encodeAttrValue(&ours, i, a)
		}
	}
	same := bytes.Equal(vals, ours.Bytes())
	switch {
	case wantSame && !same:
		return status(e, nfs4ErrNotSame)
	case !wantSame && same:
		return status(e, nfs4ErrSame)
	default:
		return status(e, nfs4OK)
	}
}
