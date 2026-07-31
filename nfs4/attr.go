package nfs4

import (
	"hash/fnv"
	"io/fs"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/xdr"
)

type bitmap []uint32

func (b bitmap) has(n int) bool {
	w := n / 32
	return w < len(b) && b[w]&(1<<(n%32)) != 0
}

func (b *bitmap) set(n int) {
	for n/32 >= len(*b) {
		*b = append(*b, 0)
	}
	(*b)[n/32] |= 1 << (n % 32)
}

// maxBitmapWords bounds a decoded bitmap4; attrs stop at 55, so two words
// carry everything and anything longer is a hostile or garbage request.
const maxBitmapWords = 8

func decodeBitmap(d *xdr.Decoder) bitmap {
	n := d.Uint32()
	if n > maxBitmapWords {
		d.Fail(xdr.ErrBound)
		return nil
	}
	b := make(bitmap, n)
	for i := range b {
		b[i] = d.Uint32()
	}
	return b
}

func encodeBitmap(e *xdr.Encoder, b bitmap) {
	e.Uint32(uint32(len(b)))
	for _, w := range b {
		e.Uint32(w)
	}
}

// attrCtx carries one object's identity through fattr4 encoding. The
// StatVFS result is fetched once, lazily, and zeros stand in on failure: the
// bitmap has already promised the attribute by then.
type attrCtx struct {
	c    *compound
	path string
	fi   fs.FileInfo
	vfs  *facetfs.FSStat
}

func (a *attrCtx) statVFS() *facetfs.FSStat {
	if a.vfs == nil {
		a.vfs = &facetfs.FSStat{}
		if statfs, ok := a.c.s.FileSystem.(facetfs.StatVFSFS); ok {
			if st, err := statfs.StatVFS(a.c.ctx, a.path); err == nil {
				*a.vfs = st
			}
		}
	}
	return a.vfs
}

func (s *Server) supportedAttrs() bitmap {
	var b bitmap
	for _, n := range []int{
		attrSupportedAttrs, attrType, attrFHExpireType, attrChange, attrSize,
		attrLinkSupport, attrSymlinkSupport, attrNamedAttr, attrFSID,
		attrUniqueHandles, attrLeaseTime, attrRdattrError, attrACLSupport,
		attrCanSetTime, attrCaseInsensitive, attrCasePreserving,
		attrChownRestricted, attrFilehandle, attrFileID, attrHomogeneous,
		attrMaxFileSize, attrMaxLink, attrMaxName, attrMaxRead, attrMaxWrite,
		attrMode, attrNoTrunc, attrNumLinks, attrOwner, attrOwnerGroup,
		attrRawDev, attrSpaceUsed, attrTimeAccess, attrTimeDelta,
		attrTimeMetadata, attrTimeModify, attrMountedOnFileID,
	} {
		b.set(n)
	}
	if _, ok := s.FileSystem.(facetfs.StatVFSFS); ok {
		for _, n := range []int{attrFilesAvail, attrFilesFree, attrFilesTotal, attrSpaceAvail, attrSpaceFree, attrSpaceTotal} {
			b.set(n)
		}
	}
	if _, ok := s.FileSystem.(facetfs.SetStatFS); ok {
		b.set(attrTimeAccessSet)
		b.set(attrTimeModifySet)
	}
	return b
}

func fileID(path string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(path))
	return h.Sum64()
}

// change derives the change attribute the way webdav derives entity tags; a
// FileSystem with coarse ModTime yields correspondingly weak change
// detection.
func changeOf(fi fs.FileInfo) uint64 {
	return uint64(fi.ModTime().UnixNano()) ^ uint64(fi.Size())<<1
}

func fileType(fi fs.FileInfo) uint32 {
	switch {
	case fi.IsDir():
		return nf4Dir
	case fi.Mode()&fs.ModeSymlink != 0:
		return nf4Lnk
	default:
		return nf4Reg
	}
}

func encodeTime(e *xdr.Encoder, fi fs.FileInfo) {
	t := fi.ModTime()
	e.Uint64(uint64(t.Unix()))
	e.Uint32(uint32(t.Nanosecond()))
}

// encodeFattr writes a fattr4 for requested ∩ supported. Unsupported bits are
// silently dropped per RFC 7530 §16.7.
func encodeFattr(e *xdr.Encoder, requested bitmap, a *attrCtx) {
	s := a.c.s
	supported := s.supported
	granted := make(bitmap, 0, 2)
	for i := 0; i <= attrMountedOnFileID; i++ {
		if requested.has(i) && supported.has(i) {
			granted.set(i)
		}
	}
	encodeBitmap(e, granted)
	// The values are written in place and their length filled in afterwards.
	// Every attribute encodes to a multiple of four bytes, so the opaque
	// needs no padding.
	lengthAt := e.Len()
	e.Uint32(0)
	from := e.Len()
	for i := 0; i <= attrMountedOnFileID; i++ {
		if !granted.has(i) {
			continue
		}
		encodeAttrValue(e, i, a)
	}
	e.PatchUint32(lengthAt, uint32(e.Len()-from))
}

func encodeAttrValue(e *xdr.Encoder, attr int, a *attrCtx) {
	s := a.c.s
	switch attr {
	case attrSupportedAttrs:
		encodeBitmap(e, s.supported)
	case attrType:
		e.Uint32(fileType(a.fi))
	case attrFHExpireType:
		e.Uint32(fh4VolatileAny)
	case attrChange:
		e.Uint64(changeOf(a.fi))
	case attrSize:
		e.Uint64(uint64(a.fi.Size()))
	case attrLinkSupport:
		_, ok := s.FileSystem.(facetfs.LinkFS)
		e.Bool(ok)
	case attrSymlinkSupport:
		_, ok := s.FileSystem.(facetfs.SymlinkFS)
		e.Bool(ok)
	case attrNamedAttr:
		e.Bool(false)
	case attrFSID:
		e.Uint64(0x66616365)
		e.Uint64(0)
	case attrUniqueHandles:
		e.Bool(false)
	case attrLeaseTime:
		e.Uint32(uint32(s.lease().Seconds()))
	case attrRdattrError:
		e.Uint32(uint32(nfs4OK))
	case attrACLSupport:
		e.Uint32(0)
	case attrCanSetTime:
		_, ok := s.FileSystem.(facetfs.SetStatFS)
		e.Bool(ok)
	case attrCaseInsensitive:
		e.Bool(false)
	case attrCasePreserving:
		e.Bool(true)
	case attrChownRestricted:
		e.Bool(true)
	case attrFilehandle:
		e.Opaque(s.fh.seal(a.path))
	case attrFileID:
		e.Uint64(fileID(a.path))
	case attrFilesAvail:
		e.Uint64(a.statVFS().FreeFiles)
	case attrFilesFree:
		e.Uint64(a.statVFS().FreeFiles)
	case attrFilesTotal:
		e.Uint64(a.statVFS().TotalFiles)
	case attrHomogeneous:
		e.Bool(true)
	case attrMaxFileSize:
		e.Uint64(1 << 62)
	case attrMaxLink:
		e.Uint32(255)
	case attrMaxName:
		e.Uint32(maxNameBytes)
	case attrMaxRead:
		e.Uint64(uint64(s.maxRead()))
	case attrMaxWrite:
		e.Uint64(uint64(s.maxWrite()))
	case attrMode:
		e.Uint32(uint32(a.fi.Mode().Perm()))
	case attrNoTrunc:
		e.Bool(true)
	case attrNumLinks:
		e.Uint32(1)
	case attrOwner:
		e.String("0")
	case attrOwnerGroup:
		e.String("0")
	case attrRawDev:
		e.Uint32(0)
		e.Uint32(0)
	case attrSpaceAvail:
		e.Uint64(a.statVFS().AvailBytes)
	case attrSpaceFree:
		e.Uint64(a.statVFS().FreeBytes)
	case attrSpaceTotal:
		e.Uint64(a.statVFS().TotalBytes)
	case attrSpaceUsed:
		e.Uint64(uint64(a.fi.Size()))
	case attrTimeAccess, attrTimeMetadata, attrTimeModify:
		encodeTime(e, a.fi)
	case attrTimeDelta:
		e.Uint64(0)
		e.Uint32(1)
	case attrMountedOnFileID:
		e.Uint64(fileID(a.path))
	}
}
