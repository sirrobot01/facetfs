package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"

	"github.com/sirrobot01/facetfs"
)

func fileAttributes(info fs.FileInfo) uint32 {
	if info == nil {
		return 0
	}
	var a uint32
	if info.IsDir() {
		a |= 0x10
	} else {
		a |= 0x20
	}
	if info.Mode().Perm()&0o222 == 0 {
		a |= 0x01
	}
	return a
}

func (conn *connection) treeSession(m *message) (*session, uint32) {
	s := conn.authSession(m)
	if s == nil {
		return nil, statusUserSessionDeleted
	}
	conn.s.state.mu.Lock()
	t := s.trees[m.hdr.treeID]
	conn.s.state.mu.Unlock()
	if t == nil {
		// Windows reacts to this status by reconnecting the tree, where an
		// invalid-parameter answer fails the operation outright.
		return nil, statusNetworkNameDeleted
	}
	return s, statusSuccess
}

func desiredOpenFlags(access uint32) int {
	r, w, _ := accessKinds(access)
	switch {
	case r && w:
		return os.O_RDWR
	case w:
		return os.O_WRONLY
	default:
		return os.O_RDONLY
	}
}

func dispositionFlags(disposition uint32) (flags int, action uint32, ok bool) {
	switch disposition {
	case fileOpen:
		return 0, 1, true
	case fileCreate:
		return os.O_CREATE | os.O_EXCL, 2, true
	case fileOpenIf:
		return os.O_CREATE, 1, true
	case fileOverwrite:
		return os.O_TRUNC, 3, true
	case fileOverwriteIf, fileSupersede:
		return os.O_CREATE | os.O_TRUNC, 3, true
	default:
		return 0, 0, false
	}
}

func (conn *connection) create(ctx context.Context, m *message) ([]byte, uint32) {
	sess, st := conn.treeSession(m)
	if st != statusSuccess {
		return nil, st
	}
	if len(m.body) < 56 || binary.LittleEndian.Uint16(m.body) != 57 {
		return nil, statusInvalidParameter
	}
	access := binary.LittleEndian.Uint32(m.body[24:])
	share := binary.LittleEndian.Uint32(m.body[32:])
	disposition := binary.LittleEndian.Uint32(m.body[36:])
	options := binary.LittleEndian.Uint32(m.body[40:])
	nameOff := uint32(binary.LittleEndian.Uint16(m.body[44:]))
	nameLen := uint32(binary.LittleEndian.Uint16(m.body[46:]))
	contextsOff := binary.LittleEndian.Uint32(m.body[48:])
	contextsLen := binary.LittleEndian.Uint32(m.body[52:])
	nameWire, ok := m.slice(nameOff, nameLen, maxPathBytes)
	if !ok {
		return nil, statusInvalidParameter
	}
	name, err := smbPath(nameWire)
	if err != nil {
		return nil, pathStatus(err)
	}
	if contextsLen != 0 {
		contexts, ok := m.slice(contextsOff, contextsLen, maxSecurityBuffer)
		if !ok || !validCreateContexts(contexts) {
			return nil, statusInvalidParameter
		}
	}
	flags, action, ok := dispositionFlags(disposition)
	if !ok {
		return nil, statusInvalidParameter
	}
	info, statErr := conn.s.FileSystem.Stat(ctx, name)
	existed := statErr == nil
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return nil, fsStatus(statErr)
	}
	if existed {
		switch disposition {
		case fileCreate:
			return nil, statusObjectNameCollision
		case fileOpenIf:
			action = 1
		}
	} else {
		switch disposition {
		case fileOpen, fileOverwrite:
			return nil, statusObjectNameNotFound
		default:
			action = 2
		}
	}
	if existed && options&fileDirectoryFile != 0 && !info.IsDir() {
		return nil, statusNotADirectory
	}
	if existed && options&fileNonDirectoryFile != 0 && info.IsDir() {
		return nil, statusFileIsADirectory
	}
	if existed && info.IsDir() && (disposition == fileOverwrite || disposition == fileOverwriteIf || disposition == fileSupersede) {
		return nil, statusFileIsADirectory
	}
	if options&fileDeleteOnClose != 0 {
		_, _, canDelete := accessKinds(access)
		if !canDelete {
			return nil, statusAccessDenied
		}
		if (existed && info.IsDir()) || (!existed && options&fileDirectoryFile != 0) {
			if _, ok := conn.s.FileSystem.(facetfs.RemoveFS); !ok {
				return nil, statusNotSupported
			}
		}
	}
	h := &openHandle{session: sess, treeID: m.hdr.treeID, path: name, access: access, share: share, options: options, deleteOnClose: options&fileDeleteOnClose != 0}
	if st := conn.s.state.addHandle(sess, h); st != statusSuccess {
		return nil, st
	}
	reserved := true
	defer func() {
		if reserved {
			conn.s.state.abortHandle(h)
		}
	}()
	openFlags := desiredOpenFlags(access) | flags
	if !existed && options&fileDirectoryFile != 0 {
		if err := conn.s.FileSystem.Mkdir(ctx, name, 0o755); err != nil {
			return nil, fsStatus(err)
		}
		openFlags = os.O_RDONLY
	} else if existed && info.IsDir() {
		openFlags = os.O_RDONLY
	}
	f, err := conn.s.FileSystem.OpenFile(ctx, name, openFlags, 0o666)
	if err != nil {
		return nil, fsStatus(err)
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, fsStatus(err)
	}
	if options&fileDirectoryFile != 0 && !info.IsDir() {
		f.Close()
		return nil, statusNotADirectory
	}
	if options&fileNonDirectoryFile != 0 && info.IsDir() {
		f.Close()
		return nil, statusFileIsADirectory
	}
	if !conn.s.state.commitHandle(h, f, info) {
		f.Close()
		return nil, statusUserSessionDeleted
	}
	reserved = false
	m.resultFileID = &h.id
	return createResponse(h, action), statusSuccess
}

func validCreateContexts(b []byte) bool {
	count := 0
	for pos := 0; pos < len(b); {
		if count >= maxCreateContexts || len(b)-pos < 16 {
			return false
		}
		next := int(binary.LittleEndian.Uint32(b[pos:]))
		nameOff := int(binary.LittleEndian.Uint16(b[pos+4:]))
		nameLen := int(binary.LittleEndian.Uint16(b[pos+6:]))
		dataOff := int(binary.LittleEndian.Uint16(b[pos+10:]))
		dataLen := int(binary.LittleEndian.Uint32(b[pos+12:]))
		end := len(b)
		if next != 0 {
			if next%8 != 0 || next < 16 || pos+next > len(b) {
				return false
			}
			end = pos + next
		}
		if nameOff < 16 || pos+nameOff+nameLen > end || (dataLen != 0 && (dataOff < 16 || pos+dataOff+dataLen > end)) {
			return false
		}
		count++
		if next == 0 {
			return true
		}
		pos += next
	}
	return count > 0
}

func createResponse(h *openHandle, action uint32) []byte {
	b := make([]byte, 88)
	binary.LittleEndian.PutUint16(b, 89)
	binary.LittleEndian.PutUint32(b[4:], action)
	t := fileTime(h.info.ModTime())
	for _, off := range []int{8, 16, 24, 32} {
		binary.LittleEndian.PutUint64(b[off:], t)
	}
	if h.info.Size() > 0 {
		binary.LittleEndian.PutUint64(b[40:], uint64((h.info.Size()+4095)&^4095))
		binary.LittleEndian.PutUint64(b[48:], uint64(h.info.Size()))
	}
	binary.LittleEndian.PutUint32(b[56:], fileAttributes(h.info))
	copy(b[64:], h.id[:])
	return b
}

func requestFileID(m *message, bodyOffset int) ([16]byte, bool) {
	var id [16]byte
	if bodyOffset < 0 || bodyOffset+16 > len(m.body) {
		return id, false
	}
	copy(id[:], m.body[bodyOffset:bodyOffset+16])
	allOnes := true
	for _, b := range id {
		allOnes = allOnes && b == 0xff
	}
	if allOnes {
		if m.relatedFileID == nil {
			return id, false
		}
		return *m.relatedFileID, true
	}
	return id, true
}

func (conn *connection) openFor(m *message, bodyOffset int) (*openHandle, uint32) {
	sess, st := conn.treeSession(m)
	if st != statusSuccess {
		return nil, st
	}
	id, ok := requestFileID(m, bodyOffset)
	if !ok {
		return nil, statusInvalidParameter
	}
	h := conn.s.state.handle(sess, m.hdr.treeID, id)
	if h == nil {
		return nil, statusFileClosed
	}
	return h, statusSuccess
}

func (conn *connection) closeOpen(h *openHandle) error {
	name, remove := conn.s.state.handleMeta(h)
	conn.s.state.closeHandle(h)
	if !remove {
		return nil
	}
	if rfs, ok := conn.s.FileSystem.(facetfs.RemoveFS); ok {
		return rfs.Remove(context.Background(), name)
	}
	return conn.s.FileSystem.RemoveAll(context.Background(), name)
}

// close serves CLOSE. The pending delete inside closeOpen deliberately runs
// on the background context: the client is done with the handle either way.
func (conn *connection) close(m *message) ([]byte, uint32) {
	if len(m.body) < 24 || binary.LittleEndian.Uint16(m.body) != 24 {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 8)
	if st != statusSuccess {
		return nil, st
	}
	info, _ := h.file.Stat()
	if err := conn.closeOpen(h); err != nil {
		return nil, fsStatus(err)
	}
	b := make([]byte, 60)
	binary.LittleEndian.PutUint16(b, 60)
	if binary.LittleEndian.Uint16(m.body[2:])&1 != 0 && info != nil {
		binary.LittleEndian.PutUint16(b[2:], 1)
		t := fileTime(info.ModTime())
		for _, off := range []int{8, 16, 24, 32} {
			binary.LittleEndian.PutUint64(b[off:], t)
		}
		if info.Size() > 0 {
			binary.LittleEndian.PutUint64(b[40:], uint64((info.Size()+4095)&^4095))
			binary.LittleEndian.PutUint64(b[48:], uint64(info.Size()))
		}
		binary.LittleEndian.PutUint32(b[56:], fileAttributes(info))
	}
	return b, statusSuccess
}

func positionedRead(h *openHandle, p []byte, off int64) (int, error) {
	if r, ok := h.file.(io.ReaderAt); ok {
		return r.ReadAt(p, off)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.file.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	// A single Read may return short mid-file, but a client reads a short
	// READ as end-of-file, so give the guarantee ReadAt gives.
	n, err := io.ReadFull(h.file, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

func positionedWrite(h *openHandle, p []byte, off int64) (int, error) {
	if w, ok := h.file.(io.WriterAt); ok {
		return w.WriteAt(p, off)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.file.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return h.file.Write(p)
}

func (conn *connection) read(m *message) ([]byte, uint32) {
	if len(m.body) < 48 || binary.LittleEndian.Uint16(m.body) != 49 {
		return nil, statusInvalidParameter
	}
	n := binary.LittleEndian.Uint32(m.body[4:])
	off := binary.LittleEndian.Uint64(m.body[8:])
	if n > conn.s.maxRead() || off > math.MaxInt64 {
		return nil, statusInvalidParameter
	}
	charge := uint32(m.hdr.creditCharge)
	if charge == 0 {
		charge = 1
	}
	if need := max((n+65535)/65536, uint32(1)); charge < need {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 16)
	if st != statusSuccess {
		return nil, st
	}
	if h.info.IsDir() {
		return nil, statusFileIsADirectory
	}
	readable, _, _ := accessKinds(h.access)
	if !readable {
		return nil, statusAccessDenied
	}
	data := make([]byte, n)
	got, err := positionedRead(h, data, int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fsStatus(err)
	}
	if got == 0 && errors.Is(err, io.EOF) {
		return nil, statusEndOfFile
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b, 17)
	b[2] = headerSize + 16
	binary.LittleEndian.PutUint32(b[4:], uint32(got))
	return append(b, data[:got]...), statusSuccess
}

func (conn *connection) write(m *message) ([]byte, uint32) {
	if len(m.body) < 48 || binary.LittleEndian.Uint16(m.body) != 49 {
		return nil, statusInvalidParameter
	}
	dataOff := uint32(binary.LittleEndian.Uint16(m.body[2:]))
	n := binary.LittleEndian.Uint32(m.body[4:])
	off := binary.LittleEndian.Uint64(m.body[8:])
	if n > conn.s.maxWrite() || off > math.MaxInt64 {
		return nil, statusInvalidParameter
	}
	charge := uint32(m.hdr.creditCharge)
	if charge == 0 {
		charge = 1
	}
	if need := max((n+65535)/65536, uint32(1)); charge < need {
		return nil, statusInvalidParameter
	}
	data, ok := m.slice(dataOff, n, conn.s.maxWrite())
	if !ok {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 16)
	if st != statusSuccess {
		return nil, st
	}
	if h.info.IsDir() {
		return nil, statusFileIsADirectory
	}
	_, writable, _ := accessKinds(h.access)
	if !writable {
		return nil, statusAccessDenied
	}
	written, err := positionedWrite(h, data, int64(off))
	if err != nil {
		return nil, fsStatus(err)
	}
	if written != len(data) {
		return nil, statusDiskFull
	}
	flags := binary.LittleEndian.Uint32(m.body[44:])
	if flags&1 != 0 || h.options&fileWriteThrough != 0 {
		if syncer, ok := h.file.(interface{ Sync() error }); ok {
			if err := syncer.Sync(); err != nil {
				return nil, fsStatus(err)
			}
		}
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b, 17)
	binary.LittleEndian.PutUint32(b[4:], uint32(written))
	return b, statusSuccess
}

func (conn *connection) flush(m *message) ([]byte, uint32) {
	if len(m.body) < 24 || binary.LittleEndian.Uint16(m.body) != 24 {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 8)
	if st != statusSuccess {
		return nil, st
	}
	if syncer, ok := h.file.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			return nil, fsStatus(err)
		}
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, 4)
	return b, statusSuccess
}
