package smb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"io/fs"
	"sync"

	"github.com/sirrobot01/facetfs"
)

type serverState struct {
	mu       sync.Mutex
	s        *Server
	nextID   uint64
	sessions map[uint64]*session
	opens    map[string]map[*openHandle]struct{}
	locks    map[string][]byteLock
}

type session struct {
	mu             sync.Mutex
	id             uint64
	conn           *connection
	user           string
	authenticated  bool
	authenticating bool
	sign           bool
	signingKey     []byte
	preauth        [preauthHashSize]byte
	challenge      [8]byte
	ntlmFlags      uint32
	trees          map[uint32]*tree
	handles        map[[16]byte]*openHandle
	snapshots      map[[16]byte]*dirSnapshot
	nextTree       uint32
	nextHandle     uint64
	handleSeal     uint64
}

type tree struct {
	id uint32
}

type openHandle struct {
	mu            sync.Mutex
	id            [16]byte
	session       *session
	treeID        uint32
	path          string
	file          interfaceFile
	info          fs.FileInfo
	access        uint32
	share         uint32
	options       uint32
	deleteOnClose bool
}

// interfaceFile mirrors facetfs.File locally and keeps state.go independent
// of an otherwise unnecessary package-qualified field declaration.
type interfaceFile interface {
	io.Closer
	io.Reader
	io.Seeker
	io.Writer
	Readdir(int) ([]fs.FileInfo, error)
	Stat() (fs.FileInfo, error)
}

type byteLock struct {
	handle *openHandle
	start  uint64
	end    uint64
	write  bool
}

type dirSnapshot struct {
	mu      sync.Mutex
	entries []fs.FileInfo
	pattern string
	index   int
	started bool
}

func newServerState(s *Server) *serverState {
	return &serverState{
		s:        s,
		sessions: make(map[uint64]*session),
		opens:    make(map[string]map[*openHandle]struct{}),
		locks:    make(map[string][]byteLock),
	}
}

func (st *serverState) newSession(conn *connection) (*session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	count := 0
	for _, s := range st.sessions {
		if s.conn == conn {
			count++
		}
	}
	if count >= maxSessionsPerConnection {
		return nil, false
	}
	for range 8 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, false
		}
		id := binary.LittleEndian.Uint64(b[:])
		if id == 0 || st.sessions[id] != nil {
			continue
		}
		s := &session{id: id, conn: conn, handleSeal: id, trees: make(map[uint32]*tree), handles: make(map[[16]byte]*openHandle), snapshots: make(map[[16]byte]*dirSnapshot)}
		st.sessions[id] = s
		return s, true
	}
	return nil, false
}

func (st *serverState) session(id uint64, conn *connection) *session {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.sessions[id]
	if s == nil || s.conn != conn {
		return nil
	}
	return s
}

func (st *serverState) closeSession(s *session) {
	if s == nil {
		return
	}
	st.mu.Lock()
	if st.sessions[s.id] != s {
		st.mu.Unlock()
		return
	}
	delete(st.sessions, s.id)
	handles := make([]*openHandle, 0, len(s.handles))
	for _, h := range s.handles {
		handles = append(handles, h)
	}
	st.mu.Unlock()
	for _, h := range handles {
		path, remove := st.handleMeta(h)
		st.closeHandle(h)
		if remove {
			if rfs, ok := st.s.FileSystem.(facetfs.RemoveFS); ok {
				_ = rfs.Remove(context.Background(), path)
			} else {
				_ = st.s.FileSystem.RemoveAll(context.Background(), path)
			}
		}
	}
}

func (st *serverState) handleMeta(h *openHandle) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return h.path, h.deleteOnClose
}

func (st *serverState) closeConnection(conn *connection) {
	st.mu.Lock()
	var sessions []*session
	for _, s := range st.sessions {
		if s.conn == conn {
			sessions = append(sessions, s)
		}
	}
	st.mu.Unlock()
	for _, s := range sessions {
		st.closeSession(s)
	}
}

func accessKinds(access uint32) (read, write, delete bool) {
	read = access&(accessReadData|accessGenericRead|accessGenericAll) != 0
	write = access&(accessWriteData|accessAppendData|accessGenericWrite|accessGenericAll) != 0
	delete = access&(accessDelete|accessGenericAll) != 0
	return
}

func shareConflict(aAccess, aShare, bAccess, bShare uint32) bool {
	ar, aw, ad := accessKinds(aAccess)
	br, bw, bd := accessKinds(bAccess)
	return (ar && bShare&shareRead == 0) || (aw && bShare&shareWrite == 0) ||
		(ad && bShare&shareDelete == 0) || (br && aShare&shareRead == 0) ||
		(bw && aShare&shareWrite == 0) || (bd && aShare&shareDelete == 0)
}

func (st *serverState) addHandle(s *session, h *openHandle) uint32 {
	st.mu.Lock()
	defer st.mu.Unlock()
	// The session may have been closed by a concurrent LOGOFF or disconnect
	// after the caller resolved it. A handle added past that point would
	// never be closed.
	if st.sessions[s.id] != s {
		return statusUserSessionDeleted
	}
	if len(s.handles) >= maxHandlesPerSession {
		return statusInsufficientResources
	}
	for other := range st.opens[h.path] {
		if other.deleteOnClose {
			return statusDeletePending
		}
		if shareConflict(h.access, h.share, other.access, other.share) {
			return statusSharingViolation
		}
	}
	s.nextHandle++
	if s.nextHandle == 0 {
		s.nextHandle++
	}
	sealed := s.nextHandle ^ s.handleSeal
	if sealed == 0 {
		sealed = s.nextHandle
	}
	binary.LittleEndian.PutUint64(h.id[0:8], sealed)
	binary.LittleEndian.PutUint64(h.id[8:16], sealed)
	s.handles[h.id] = h
	if st.opens[h.path] == nil {
		st.opens[h.path] = make(map[*openHandle]struct{})
	}
	st.opens[h.path][h] = struct{}{}
	return statusSuccess
}

// commitHandle attaches the opened file to a reserved handle. It reports
// false when a concurrent LOGOFF or disconnect closed the session while the
// open was in flight; the caller still owns the file and must close it.
func (st *serverState) commitHandle(h *openHandle, f interfaceFile, info fs.FileInfo) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sessions[h.session.id] != h.session {
		return false
	}
	h.file, h.info = f, info
	return true
}

func (st *serverState) abortHandle(h *openHandle) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(h.session.handles, h.id)
	delete(st.opens[h.path], h)
	if len(st.opens[h.path]) == 0 {
		delete(st.opens, h.path)
	}
}

func (st *serverState) handle(s *session, treeID uint32, id [16]byte) *openHandle {
	st.mu.Lock()
	defer st.mu.Unlock()
	h := s.handles[id]
	// A handle without a file is a reservation whose CREATE is still in
	// flight; it is not visible to any other request.
	if h == nil || h.treeID != treeID || h.file == nil {
		return nil
	}
	return h
}

func (st *serverState) closeHandle(h *openHandle) {
	st.mu.Lock()
	delete(h.session.handles, h.id)
	delete(h.session.snapshots, h.id)
	delete(st.opens[h.path], h)
	if len(st.opens[h.path]) == 0 {
		delete(st.opens, h.path)
	}
	locks := st.locks[h.path][:0]
	for _, l := range st.locks[h.path] {
		if l.handle != h {
			locks = append(locks, l)
		}
	}
	if len(locks) == 0 {
		delete(st.locks, h.path)
	} else {
		st.locks[h.path] = locks
	}
	st.mu.Unlock()
	if h.file != nil {
		h.file.Close()
	}
}
