package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
	"time"

	"github.com/sirrobot01/facetfs"
)

const (
	infoFile       = 1
	infoFilesystem = 2
	infoSecurity   = 3

	fsctlValidateNegotiateInfo = 0x00140204
)

func queryInfoResponse(data []byte, max uint32) ([]byte, uint32) {
	if uint32(len(data)) > max {
		return nil, statusInfoLengthMismatch
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[2:], headerSize+8)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	return append(b, data...), statusSuccess
}

func (conn *connection) queryInfo(ctx context.Context, m *message) ([]byte, uint32) {
	if len(m.body) < 40 || binary.LittleEndian.Uint16(m.body) != 41 {
		return nil, statusInvalidParameter
	}
	maxOut := min(binary.LittleEndian.Uint32(m.body[4:]), conn.s.maxTransact())
	infoType, class := m.body[2], m.body[3]
	h, st := conn.openFor(m, 24)
	if st != statusSuccess {
		return nil, st
	}
	if infoType == infoSecurity {
		return queryInfoResponse(fixedSecurityDescriptor(), maxOut)
	}
	info, err := h.file.Stat()
	if err != nil {
		return nil, fsStatus(err)
	}
	var data []byte
	name, pendingDelete := conn.s.state.handleMeta(h)
	switch infoType {
	case infoFile:
		data, st = fileInfo(class, h, info, name, pendingDelete)
	case infoFilesystem:
		data, st = conn.filesystemInfo(ctx, class, name)
	default:
		return nil, statusInvalidInfoClass
	}
	if st != statusSuccess {
		return nil, st
	}
	return queryInfoResponse(data, maxOut)
}

func putTimes(b []byte, info fs.FileInfo) {
	t := fileTime(info.ModTime())
	for _, off := range []int{0, 8, 16, 24} {
		binary.LittleEndian.PutUint64(b[off:], t)
	}
}

// fileIndex is the stable identifier exposed in file information and
// directory entries. It is separate from the per-open FileId used to address
// a handle on the wire: a client may compare this value before and after it
// opens a path and treats a mismatch as a stale file handle.
func fileIndex(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}

func fileInfo(class byte, h *openHandle, info fs.FileInfo, pathName string, pendingDelete bool) ([]byte, uint32) {
	name := utf16Bytes(strings.ReplaceAll(pathName, "/", "\\"))
	switch class {
	case 4: // FileBasicInformation
		b := make([]byte, 40)
		putTimes(b, info)
		binary.LittleEndian.PutUint32(b[32:], fileAttributes(info))
		return b, statusSuccess
	case 5: // FileStandardInformation
		b := make([]byte, 24)
		if info.Size() > 0 {
			binary.LittleEndian.PutUint64(b, uint64((info.Size()+4095)&^4095))
			binary.LittleEndian.PutUint64(b[8:], uint64(info.Size()))
		}
		binary.LittleEndian.PutUint32(b[16:], 1)
		if pendingDelete {
			b[20] = 1
		}
		if info.IsDir() {
			b[21] = 1
		}
		return b, statusSuccess
	case 6: // FileInternalInformation
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, fileIndex(pathName))
		return b, statusSuccess
	case 7: // FileEaInformation
		return make([]byte, 4), statusSuccess
	case 8: // FileAccessInformation
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, h.access)
		return b, statusSuccess
	case 9, 48: // FileNameInformation / FileNormalizedNameInformation
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(len(name)))
		return append(b, name...), statusSuccess
	case 14: // FilePositionInformation
		return make([]byte, 8), statusSuccess
	case 16: // FileModeInformation
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, h.options)
		return b, statusSuccess
	case 17: // FileAlignmentInformation
		return make([]byte, 4), statusSuccess
	case 18: // FileAllInformation
		b := make([]byte, 100)
		putTimes(b, info)
		binary.LittleEndian.PutUint32(b[32:], fileAttributes(info))
		if info.Size() > 0 {
			binary.LittleEndian.PutUint64(b[40:], uint64((info.Size()+4095)&^4095))
			binary.LittleEndian.PutUint64(b[48:], uint64(info.Size()))
		}
		binary.LittleEndian.PutUint32(b[56:], 1)
		if pendingDelete {
			b[60] = 1
		}
		if info.IsDir() {
			b[61] = 1
		}
		binary.LittleEndian.PutUint64(b[64:], fileIndex(pathName))
		binary.LittleEndian.PutUint32(b[76:], h.access)
		binary.LittleEndian.PutUint32(b[88:], h.options)
		binary.LittleEndian.PutUint32(b[96:], uint32(len(name)))
		return append(b, name...), statusSuccess
	case 34: // FileNetworkOpenInformation
		b := make([]byte, 56)
		putTimes(b, info)
		if info.Size() > 0 {
			binary.LittleEndian.PutUint64(b[32:], uint64((info.Size()+4095)&^4095))
			binary.LittleEndian.PutUint64(b[40:], uint64(info.Size()))
		}
		binary.LittleEndian.PutUint32(b[48:], fileAttributes(info))
		return b, statusSuccess
	case 35: // FileAttributeTagInformation
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, fileAttributes(info))
		return b, statusSuccess
	default:
		return nil, statusInvalidInfoClass
	}
}

func (conn *connection) filesystemInfo(ctx context.Context, class byte, name string) ([]byte, uint32) {
	var stat facetfs.FSStat
	vfs, hasVFS := conn.s.FileSystem.(facetfs.StatVFSFS)
	if hasVFS {
		var err error
		stat, err = vfs.StatVFS(ctx, name)
		if err != nil {
			return nil, fsStatus(err)
		}
	} else {
		stat = facetfs.FSStat{NameMax: 255}
	}
	const sector = uint64(512)
	switch class {
	case 1: // FileFsVolumeInformation
		label := utf16Bytes(conn.s.shareName())
		b := make([]byte, 18)
		binary.LittleEndian.PutUint64(b, fileTime(conn.s.startedAt))
		binary.LittleEndian.PutUint32(b[8:], binary.LittleEndian.Uint32(conn.s.guid[:]))
		binary.LittleEndian.PutUint32(b[12:], uint32(len(label)))
		return append(b, label...), statusSuccess
	case 3: // FileFsSizeInformation
		if !hasVFS {
			return nil, statusNotSupported
		}
		b := make([]byte, 24)
		binary.LittleEndian.PutUint64(b, stat.TotalBytes/sector)
		binary.LittleEndian.PutUint64(b[8:], stat.AvailBytes/sector)
		binary.LittleEndian.PutUint32(b[16:], 1)
		binary.LittleEndian.PutUint32(b[20:], uint32(sector))
		return b, statusSuccess
	case 4: // FileFsDeviceInformation
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, 7)
		return b, statusSuccess
	case 5: // FileFsAttributeInformation
		name := utf16Bytes("FACETFS")
		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b, 0x00000002|0x00000004|0x00040000)
		binary.LittleEndian.PutUint32(b[4:], max(stat.NameMax, 255))
		binary.LittleEndian.PutUint32(b[8:], uint32(len(name)))
		return append(b, name...), statusSuccess
	case 7: // FileFsFullSizeInformation
		if !hasVFS {
			return nil, statusNotSupported
		}
		b := make([]byte, 32)
		binary.LittleEndian.PutUint64(b, stat.TotalBytes/sector)
		binary.LittleEndian.PutUint64(b[8:], stat.AvailBytes/sector)
		binary.LittleEndian.PutUint64(b[16:], stat.FreeBytes/sector)
		binary.LittleEndian.PutUint32(b[24:], 1)
		binary.LittleEndian.PutUint32(b[28:], uint32(sector))
		return b, statusSuccess
	case 11: // FileFsSectorSizeInformation
		b := make([]byte, 28)
		for _, off := range []int{0, 4, 8, 12} {
			binary.LittleEndian.PutUint32(b[off:], uint32(sector))
		}
		return b, statusSuccess
	default:
		return nil, statusInvalidInfoClass
	}
}

func fixedSecurityDescriptor() []byte {
	// Self-relative descriptor with owner/group S-1-5-18 and a null DACL.
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:], 0x8004) // SELF_RELATIVE | DACL_PRESENT
	binary.LittleEndian.PutUint32(b[4:], 20)
	binary.LittleEndian.PutUint32(b[8:], uint32(20+len(sid)))
	b = append(b, sid...)
	return append(b, sid...)
}

func windowsTime(v uint64) time.Time {
	if v == 0 || v == ^uint64(0) || v < fileTimeEpoch {
		return time.Time{}
	}
	return time.Unix(0, int64(v-fileTimeEpoch)*100)
}

func (conn *connection) setInfo(ctx context.Context, m *message) ([]byte, uint32) {
	if len(m.body) < 32 || binary.LittleEndian.Uint16(m.body) != 33 || m.body[2] != infoFile {
		return nil, statusInvalidParameter
	}
	class := m.body[3]
	n := binary.LittleEndian.Uint32(m.body[4:])
	off := uint32(binary.LittleEndian.Uint16(m.body[8:]))
	data, ok := m.slice(off, n, conn.s.maxTransact())
	if !ok {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 16)
	if st != statusSuccess {
		return nil, st
	}
	setfs, hasSet := conn.s.FileSystem.(facetfs.SetStatFS)
	pathName, _ := conn.s.state.handleMeta(h)
	switch class {
	case 4: // FileBasicInformation
		if len(data) < 40 || !hasSet {
			return nil, statusNotSupported
		}
		atime, mtime := windowsTime(binary.LittleEndian.Uint64(data[8:])), windowsTime(binary.LittleEndian.Uint64(data[16:]))
		if atime.IsZero() {
			atime = h.info.ModTime()
		}
		if mtime.IsZero() {
			mtime = h.info.ModTime()
		}
		if err := setfs.Chtimes(ctx, pathName, atime, mtime); err != nil {
			return nil, fsStatus(err)
		}
		attrs := binary.LittleEndian.Uint32(data[32:])
		if attrs != 0 {
			mode := h.info.Mode().Perm()
			if attrs&1 != 0 {
				mode &^= 0o222
			} else {
				mode |= 0o200
			}
			if err := setfs.Chmod(ctx, pathName, mode); err != nil {
				return nil, fsStatus(err)
			}
		}
	case 10, 65: // FileRenameInformation[/Ex]
		_, _, canDelete := accessKinds(h.access)
		if !canDelete {
			return nil, statusAccessDenied
		}
		if len(data) < 20 {
			return nil, statusInvalidParameter
		}
		nameLen := binary.LittleEndian.Uint32(data[16:])
		if uint64(20)+uint64(nameLen) > uint64(len(data)) {
			return nil, statusInvalidParameter
		}
		newName, err := smbPath(data[20 : 20+nameLen])
		if err != nil {
			return nil, pathStatus(err)
		}
		if data[0] == 0 {
			if _, err := conn.s.FileSystem.Stat(ctx, newName); err == nil {
				return nil, statusObjectNameCollision
			}
		}
		if err := conn.s.FileSystem.Rename(ctx, pathName, newName); err != nil {
			return nil, fsStatus(err)
		}
		conn.s.state.mu.Lock()
		oldName := pathName
		opened := conn.s.state.opens[oldName]
		delete(conn.s.state.opens, oldName)
		if conn.s.state.opens[newName] == nil {
			conn.s.state.opens[newName] = make(map[*openHandle]struct{})
		}
		for openedHandle := range opened {
			openedHandle.path = newName
			conn.s.state.opens[newName][openedHandle] = struct{}{}
		}
		if held := conn.s.state.locks[oldName]; len(held) != 0 {
			conn.s.state.locks[newName] = append(conn.s.state.locks[newName], held...)
			delete(conn.s.state.locks, oldName)
		}
		conn.s.state.mu.Unlock()
	case 13, 64: // FileDispositionInformation[/Ex]
		_, _, canDelete := accessKinds(h.access)
		if !canDelete {
			return nil, statusAccessDenied
		}
		if len(data) < 1 {
			return nil, statusInvalidParameter
		}
		pending := data[0]&1 != 0
		if pending && h.info.IsDir() {
			if _, ok := conn.s.FileSystem.(facetfs.RemoveFS); !ok {
				return nil, statusNotSupported
			}
		}
		conn.s.state.mu.Lock()
		h.deleteOnClose = pending
		conn.s.state.mu.Unlock()
	case 20: // FileEndOfFileInformation
		if len(data) < 8 || !hasSet {
			return nil, statusNotSupported
		}
		size := binary.LittleEndian.Uint64(data)
		if size > math.MaxInt64 {
			return nil, statusInvalidParameter
		}
		if err := setfs.Truncate(ctx, pathName, int64(size)); err != nil {
			return nil, fsStatus(err)
		}
	default:
		return nil, statusInvalidInfoClass
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 2)
	return b, statusSuccess
}

func dosMatch(pattern, name string) bool {
	p, n := []rune(strings.ToUpper(pattern)), []rune(strings.ToUpper(name))
	// The one-backtrack-point walk: on a mismatch after a star, the star
	// consumes one more rune and the walk resumes there. The pattern is
	// client-controlled, and the recursive form is exponential in its stars.
	i, j := 0, 0
	star, mark := -1, 0
	for j < len(n) {
		switch {
		case i < len(p) && (p[i] == '?' || p[i] == n[j]):
			i++
			j++
		case i < len(p) && p[i] == '*':
			star, mark = i, j
			i++
		case star >= 0:
			mark++
			i, j = star+1, mark
		default:
			return false
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}

type syntheticInfo struct {
	n   string
	dir bool
}

func (i syntheticInfo) Name() string { return i.n }
func (i syntheticInfo) Size() int64  { return 0 }
func (i syntheticInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (i syntheticInfo) ModTime() time.Time { return time.Time{} }
func (i syntheticInfo) IsDir() bool        { return i.dir }
func (i syntheticInfo) Sys() any           { return nil }

var errDirectoryLimit = errors.New("smb: directory entry limit exceeded")

func readDirectoryBounded(f interfaceFile, limit int) ([]fs.FileInfo, error) {
	var entries []fs.FileInfo
	for {
		want := min(1024, limit+1-len(entries))
		batch, err := f.Readdir(want)
		entries = append(entries, batch...)
		if len(entries) > limit {
			return nil, errDirectoryLimit
		}
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

func (conn *connection) queryDirectory(ctx context.Context, m *message) ([]byte, uint32) {
	if len(m.body) < 32 || binary.LittleEndian.Uint16(m.body) != 33 {
		return nil, statusInvalidParameter
	}
	class, flags := m.body[2], m.body[3]
	if class != 1 && class != 2 && class != 3 && class != 12 && class != 37 && class != 38 {
		return nil, statusInvalidInfoClass
	}
	h, st := conn.openFor(m, 8)
	if st != statusSuccess {
		return nil, st
	}
	if !h.info.IsDir() {
		return nil, statusNotADirectory
	}
	nameOff := uint32(binary.LittleEndian.Uint16(m.body[24:]))
	nameLen := uint32(binary.LittleEndian.Uint16(m.body[26:]))
	patternWire, ok := m.slice(nameOff, nameLen, maxPathBytes)
	if !ok {
		return nil, statusInvalidParameter
	}
	pattern := "*"
	if len(patternWire) > 0 {
		pattern, ok = decodeUTF16(patternWire)
		if !ok {
			return nil, statusInvalidParameter
		}
	}
	conn.s.state.mu.Lock()
	snap := h.session.snapshots[h.id]
	restart := flags&(0x01|0x10) != 0 || snap == nil || !strings.EqualFold(snap.pattern, pattern)
	conn.s.state.mu.Unlock()
	directory, _ := conn.s.state.handleMeta(h)
	if restart {
		maxEntries := conn.s.MaxDirectoryEntries
		if maxEntries <= 0 {
			maxEntries = defaultDirEntries
		}
		f, err := conn.s.FileSystem.OpenFile(ctx, directory, 0, 0)
		if err != nil {
			return nil, fsStatus(err)
		}
		entries, err := readDirectoryBounded(f, maxEntries)
		f.Close()
		if errors.Is(err, errDirectoryLimit) {
			return nil, statusInsufficientResources
		}
		if err != nil {
			return nil, fsStatus(err)
		}
		all := []fs.FileInfo{syntheticInfo{n: ".", dir: true}, syntheticInfo{n: "..", dir: true}}
		all = append(all, entries...)
		filtered := all[:0]
		for _, e := range all {
			if dosMatch(pattern, e.Name()) {
				filtered = append(filtered, e)
			}
		}
		snap = &dirSnapshot{entries: filtered, pattern: pattern}
		conn.s.state.mu.Lock()
		if len(h.session.snapshots) >= maxDirectorySnapshots && h.session.snapshots[h.id] == nil {
			conn.s.state.mu.Unlock()
			return nil, statusInsufficientResources
		}
		h.session.snapshots[h.id] = snap
		conn.s.state.mu.Unlock()
	}
	snap.mu.Lock()
	defer snap.mu.Unlock()
	if flags&0x04 != 0 {
		// The wire index is 32 bits, which can exceed what an int holds on a
		// 32-bit platform. Past the end means there is nothing to resume.
		idx := uint64(binary.LittleEndian.Uint32(m.body[4:]))
		if idx > uint64(len(snap.entries)) {
			idx = uint64(len(snap.entries))
		}
		snap.index = int(idx)
	}
	maxOut := min(binary.LittleEndian.Uint32(m.body[28:]), conn.s.maxTransact())
	var out []byte
	start := snap.index
	wasStarted := snap.started
	prevStart := -1
	for snap.index < len(snap.entries) {
		info := snap.entries[snap.index]
		entry := encodeDirectoryEntry(class, uint32(snap.index), info, fileIndex(path.Join(directory, info.Name())))
		pad := align8(len(entry))
		if len(out)+pad > int(maxOut) {
			break
		}
		entry = append(entry, make([]byte, pad-len(entry))...)
		if prevStart >= 0 {
			binary.LittleEndian.PutUint32(out[prevStart:], uint32(len(out)-prevStart))
		}
		prevStart = len(out)
		out = append(out, entry...)
		snap.index++
		if flags&0x02 != 0 {
			break
		}
	}
	snap.started = true
	if len(out) == 0 {
		if !wasStarted && len(snap.entries) == 0 {
			return nil, statusNoSuchFile
		}
		if start < len(snap.entries) {
			return nil, statusBufferOverflow
		}
		return nil, statusNoMoreFiles
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[2:], headerSize+8)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(out)))
	return append(b, out...), statusSuccess
}

func encodeDirectoryEntry(class byte, index uint32, info fs.FileInfo, id uint64) []byte {
	name := utf16Bytes(info.Name())
	var fixed int
	switch class {
	case 1:
		fixed = 64
	case 2:
		fixed = 68
	case 3:
		fixed = 94
	case 12:
		fixed = 12
	case 37:
		fixed = 102
	case 38:
		fixed = 80
	}
	b := make([]byte, fixed)
	binary.LittleEndian.PutUint32(b[4:], index)
	if class == 12 {
		binary.LittleEndian.PutUint32(b[8:], uint32(len(name)))
		return append(b, name...)
	}
	t := fileTime(info.ModTime())
	for _, off := range []int{8, 16, 24, 32} {
		binary.LittleEndian.PutUint64(b[off:], t)
	}
	if info.Size() > 0 {
		binary.LittleEndian.PutUint64(b[40:], uint64(info.Size()))
		binary.LittleEndian.PutUint64(b[48:], uint64((info.Size()+4095)&^4095))
	}
	binary.LittleEndian.PutUint32(b[56:], fileAttributes(info))
	binary.LittleEndian.PutUint32(b[60:], uint32(len(name)))
	if class == 37 {
		binary.LittleEndian.PutUint64(b[94:], id)
	}
	if class == 38 {
		binary.LittleEndian.PutUint64(b[72:], id)
	}
	return append(b, name...)
}

func (conn *connection) ioctl(m *message) ([]byte, uint32) {
	if len(m.body) < 56 || binary.LittleEndian.Uint16(m.body) != 57 {
		return nil, statusInvalidParameter
	}
	if binary.LittleEndian.Uint32(m.body[4:]) != fsctlValidateNegotiateInfo {
		return nil, statusNotSupported
	}
	if conn.authSession(m) == nil {
		return nil, statusUserSessionDeleted
	}
	inOff := binary.LittleEndian.Uint32(m.body[24:])
	inLen := binary.LittleEndian.Uint32(m.body[28:])
	in, ok := m.slice(inOff, inLen, conn.s.maxTransact())
	if !ok || len(in) < 24 {
		return nil, statusInvalidParameter
	}
	count := binary.LittleEndian.Uint16(in[22:])
	if count == 0 || 24+int(count)*2 > len(in) {
		return nil, statusInvalidParameter
	}
	wantDialect := false
	for i := range int(count) {
		if binary.LittleEndian.Uint16(in[24+i*2:]) == conn.dialect {
			wantDialect = true
		}
	}
	if binary.LittleEndian.Uint32(in) != conn.clientCapabilities || [16]byte(in[4:20]) != conn.clientGUID || binary.LittleEndian.Uint16(in[20:]) != conn.clientSecurityMode || !wantDialect {
		return nil, statusAccessDenied
	}
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out, capLargeMTU)
	copy(out[4:], conn.s.guid[:])
	mode := uint16(signingEnabled)
	if conn.s.RequireSigning {
		mode |= signingRequired
	}
	binary.LittleEndian.PutUint16(out[20:], mode)
	binary.LittleEndian.PutUint16(out[22:], conn.dialect)
	b := make([]byte, 48)
	binary.LittleEndian.PutUint16(b, 49)
	binary.LittleEndian.PutUint32(b[4:], fsctlValidateNegotiateInfo)
	copy(b[8:24], m.body[8:24])
	binary.LittleEndian.PutUint32(b[32:], headerSize+48)
	binary.LittleEndian.PutUint32(b[36:], uint32(len(out)))
	return append(b, out...), statusSuccess
}

func (conn *connection) lock(m *message) ([]byte, uint32) {
	if len(m.body) < 48 || binary.LittleEndian.Uint16(m.body) != 48 {
		return nil, statusInvalidParameter
	}
	count := int(binary.LittleEndian.Uint16(m.body[2:]))
	if count == 0 || count > maxLockElements || 24+count*24 > len(m.body) {
		return nil, statusInvalidParameter
	}
	h, st := conn.openFor(m, 8)
	if st != statusSuccess {
		return nil, st
	}
	conn.s.state.mu.Lock()
	defer conn.s.state.mu.Unlock()
	original := append([]byteLock(nil), conn.s.state.locks[h.path]...)
	locks := conn.s.state.locks[h.path]
	sessionLocks := 0
	for _, ranges := range conn.s.state.locks {
		for _, held := range ranges {
			if held.handle.session == h.session {
				sessionLocks++
			}
		}
	}
	for i := range count {
		e := m.body[24+i*24:]
		start, length := binary.LittleEndian.Uint64(e), binary.LittleEndian.Uint64(e[8:])
		flags := binary.LittleEndian.Uint32(e[16:])
		if flags&^uint32(0x17) != 0 || (flags&0x04 != 0 && flags&0x03 != 0) || (flags&0x04 == 0 && (flags&0x03 == 0 || flags&0x03 == 0x03)) {
			conn.s.state.locks[h.path] = original
			return nil, statusInvalidParameter
		}
		if length == 0 || start+length < start {
			conn.s.state.locks[h.path] = original
			return nil, statusInvalidParameter
		}
		end := start + length
		if flags&0x04 != 0 {
			found := -1
			for j, l := range locks {
				if l.handle == h && l.start == start && l.end == end {
					found = j
					break
				}
			}
			if found < 0 {
				conn.s.state.locks[h.path] = original
				return nil, statusRangeNotLocked
			}
			locks = append(locks[:found], locks[found+1:]...)
			sessionLocks--
			continue
		}
		write := flags&0x02 != 0
		if !write && flags&0x01 == 0 {
			conn.s.state.locks[h.path] = original
			return nil, statusInvalidParameter
		}
		for _, l := range locks {
			if l.handle != h && start < l.end && l.start < end && (write || l.write) {
				conn.s.state.locks[h.path] = original
				return nil, statusLockNotGranted
			}
		}
		if sessionLocks >= maxLocksPerSession {
			conn.s.state.locks[h.path] = original
			return nil, statusInsufficientResources
		}
		locks = append(locks, byteLock{handle: h, start: start, end: end, write: write})
		sessionLocks++
	}
	conn.s.state.locks[h.path] = locks
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, 4)
	return b, statusSuccess
}
