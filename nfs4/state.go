package nfs4

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"time"
)

// stateStore holds all NFSv4 state in memory. Nothing survives a restart:
// clients discover this through stale clientids and volatile filehandles.
//
// Locking: an owner's mutex is taken before the store mutex, never the other
// way round, and the store mutex is never held across a FileSystem call.
type stateStore struct {
	mu        sync.Mutex
	now       func() time.Time
	lease     time.Duration
	epoch     [4]byte
	lastSweep time.Time

	nextClient  uint64
	nextOther   uint64
	confirmed   map[uint64]*client
	unconfirmed map[uint64]*client
	byOwner     map[string]*client // confirmed records by nfs_client_id4.id
	opens       map[[12]byte]*openState
	stateOwners map[[12]byte]*owner
	byPath      map[string][]*openState
	locks       map[[12]byte]*lockState
	locksByPath map[string][]*lockState
	expired     map[[12]byte]time.Time
	expiredIDs  map[uint64]time.Time
}

type client struct {
	id          uint64
	ownerID     string
	verifier    [8]byte // client's boot verifier from SETCLIENTID
	confirmVerf [8]byte // server-issued setclientid_confirm
	principal   string
	cb          callbackPath
	cbUp        bool // the callback path answered CB_NULL; guarded by st.mu
	lastRenew   time.Time
	openOwners  map[string]*owner
	lockOwners  map[string]*owner
	// opens counts the client's live open states. Each holds a file open, so
	// this is what bounds its share of the file descriptors.
	opens int
}

// owner is an open-owner or lock-owner: the unit of sequence-id discipline
// (RFC 7530 §9.1.7). Its mutex serializes the client's ops on it, which is
// what makes the replay cache a correct one-slot cache.
type owner struct {
	mu        sync.Mutex
	key       string
	client    *client
	seqid     uint32
	fresh     bool // no seqid accepted yet: adopt whatever the first op sends
	confirmed bool // OPEN_CONFIRM done
	lastOp    uint32
	lastReply []byte
	lastFH    string // current FH produced by a successful replayable OPEN
}

// openState is one open stateid: an open-owner's reservation over a path,
// backed by a live File.
type openState struct {
	other  [12]byte
	seq    uint32
	client *client
	owner  *owner
	path   string
	access uint32
	deny   uint32
	file   *openFile
	flag   int
}

// lockState is the byte-range state for one lock-owner on one open file.
// Its ranges are canonical: sorted, non-overlapping, and adjacent ranges of
// the same type are merged.
type lockState struct {
	other  [12]byte
	seq    uint32
	client *client
	owner  *owner
	open   *openState
	path   string
	ranges []lockRange
}

func (o *openState) stateid() ([12]byte, uint32) { return o.other, o.seq }

func newStateStore(lease time.Duration) *stateStore {
	st := &stateStore{
		now:         time.Now,
		lease:       lease,
		confirmed:   map[uint64]*client{},
		unconfirmed: map[uint64]*client{},
		byOwner:     map[string]*client{},
		opens:       map[[12]byte]*openState{},
		stateOwners: map[[12]byte]*owner{},
		byPath:      map[string][]*openState{},
		locks:       map[[12]byte]*lockState{},
		locksByPath: map[string][]*lockState{},
		expired:     map[[12]byte]time.Time{},
		expiredIDs:  map[uint64]time.Time{},
	}
	rand.Read(st.epoch[:])
	return st
}

func principalOf(cred *authSysCred) string {
	if cred == nil {
		return "none"
	}
	return "sys:" + strconv.FormatUint(uint64(cred.uid), 10)
}

// setClientID implements SETCLIENTID (RFC 7530 §16.33): it records an
// unconfirmed client and returns the id and confirmation verifier the client
// must echo. A confirmed record for the same owner under another principal is
// protected by NFS4ERR_CLID_INUSE.
func (st *stateStore) setClientID(ownerID string, verifier [8]byte, principal string, cb callbackPath) (uint64, [8]byte, nfsStat) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if held, ok := st.byOwner[ownerID]; ok && held.principal != principal {
		return 0, [8]byte{}, nfs4ErrClidInUse
	}
	// One pending record per owner: a new SETCLIENTID supersedes it.
	for id, c := range st.unconfirmed {
		if c.ownerID == ownerID {
			delete(st.unconfirmed, id)
		}
	}
	st.nextClient++
	c := &client{
		id:         st.nextClient,
		ownerID:    ownerID,
		verifier:   verifier,
		principal:  principal,
		cb:         cb,
		lastRenew:  st.now(),
		openOwners: map[string]*owner{},
		lockOwners: map[string]*owner{},
	}
	rand.Read(c.confirmVerf[:])
	st.unconfirmed[c.id] = c
	return c.id, c.confirmVerf, nfs4OK
}

// confirmClientID implements SETCLIENTID_CONFIRM. Confirming replaces any
// previously confirmed record for the same owner — the client rebooted — and
// releases that record's state. Re-confirming an already confirmed pair is
// idempotent because clients retry over connection loss.
//
// A fresh confirmation returns the client so the caller can probe its
// callback path outside the store mutex. A repeat returns nil: the probe
// already ran.
func (st *stateStore) confirmClientID(id uint64, confirmVerf [8]byte) (*client, nfsStat) {
	st.mu.Lock()
	if c, ok := st.unconfirmed[id]; ok && c.confirmVerf == confirmVerf {
		delete(st.unconfirmed, id)
		var files []*openFile
		if old, ok := st.byOwner[c.ownerID]; ok {
			// The client rebooted: its previous incarnation's state goes.
			files = st.releaseLocked(old)
		}
		st.confirmed[c.id] = c
		st.byOwner[c.ownerID] = c
		c.lastRenew = st.now()
		st.mu.Unlock()
		for _, f := range files {
			f.Close()
		}
		return c, nfs4OK
	}
	if c, ok := st.confirmed[id]; ok && c.confirmVerf == confirmVerf {
		c.lastRenew = st.now()
		st.mu.Unlock()
		return nil, nfs4OK
	}
	st.mu.Unlock()
	return nil, nfs4ErrStaleClientID
}

func (st *stateStore) renew(id uint64) nfsStat {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.confirmed[id]
	if !ok {
		if _, expired := st.expiredIDs[id]; expired {
			return nfs4ErrExpired
		}
		return nfs4ErrStaleClientID
	}
	c.lastRenew = st.now()
	return nfs4OK
}

// releaseLocked drops a client and all its state, returning the files to
// close. Callers hold st.mu and close the files after releasing it.
func (st *stateStore) releaseLocked(c *client) []*openFile {
	delete(st.confirmed, c.id)
	if st.byOwner[c.ownerID] == c {
		delete(st.byOwner, c.ownerID)
	}
	var files []*openFile
	for other, o := range st.opens {
		if o.client != c {
			continue
		}
		delete(st.opens, other)
		delete(st.stateOwners, other)
		st.removePathLocked(o)
		if o.file != nil {
			files = append(files, o.file)
		}
	}
	c.opens = 0
	for other, o := range st.stateOwners {
		if o.client == c {
			delete(st.stateOwners, other)
		}
	}
	for other, l := range st.locks {
		if l.client == c {
			delete(st.locks, other)
			st.removeLockStateLocked(l)
		}
	}
	return files
}

func (st *stateStore) removeLockStateLocked(l *lockState) {
	states := st.locksByPath[l.path]
	for i, held := range states {
		if held == l {
			states = append(states[:i], states[i+1:]...)
			break
		}
	}
	if len(states) == 0 {
		delete(st.locksByPath, l.path)
	} else {
		st.locksByPath[l.path] = states
	}
}

func (st *stateStore) locksBlockCloseLocked(opened *openState) bool {
	for _, locked := range st.locksByPath[opened.path] {
		if locked.open == opened && len(locked.ranges) != 0 {
			return true
		}
	}
	return false
}

func (st *stateStore) locksBlockDowngradeLocked(opened *openState, access uint32) bool {
	for _, locked := range st.locksByPath[opened.path] {
		if locked.open != opened {
			continue
		}
		for _, r := range locked.ranges {
			if r.write && access&shareWrite == 0 || !r.write && access&shareRead == 0 {
				return true
			}
		}
	}
	return false
}

func (st *stateStore) removeEmptyLocksForOpenLocked(opened *openState) {
	for other, locked := range st.locks {
		if locked.open == opened && len(locked.ranges) == 0 {
			delete(st.locks, other)
			delete(st.stateOwners, other)
			st.removeLockStateLocked(locked)
		}
	}
}

func (st *stateStore) removePathLocked(o *openState) {
	opens := st.byPath[o.path]
	for i, held := range opens {
		if held == o {
			opens = append(opens[:i], opens[i+1:]...)
			break
		}
	}
	if len(opens) == 0 {
		delete(st.byPath, o.path)
	} else {
		st.byPath[o.path] = opens
	}
}

// ownerOf returns the client's open-owner for key, creating it fresh.
func (st *stateStore) ownerOf(clientID uint64, key string) (*owner, nfsStat) {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.confirmed[clientID]
	if !ok {
		if _, expired := st.expiredIDs[clientID]; expired {
			return nil, nfs4ErrExpired
		}
		return nil, nfs4ErrStaleClientID
	}
	c.lastRenew = st.now()
	o, ok := c.openOwners[key]
	if !ok {
		if len(c.openOwners) >= maxOwnersPerClient {
			return nil, nfs4ErrResource
		}
		o = &owner{key: key, client: c, fresh: true}
		c.openOwners[key] = o
	}
	return o, nfs4OK
}

func (st *stateStore) lockOwnerOf(clientID uint64, key string) (*owner, nfsStat) {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.confirmed[clientID]
	if !ok {
		if _, expired := st.expiredIDs[clientID]; expired {
			return nil, nfs4ErrExpired
		}
		return nil, nfs4ErrStaleClientID
	}
	c.lastRenew = st.now()
	o, ok := c.lockOwners[key]
	if !ok {
		if len(c.lockOwners) >= maxOwnersPerClient {
			return nil, nfs4ErrResource
		}
		o = &owner{key: key, client: c, fresh: true}
		c.lockOwners[key] = o
	}
	return o, nfs4OK
}

func (st *stateStore) newOther() [12]byte {
	var other [12]byte
	copy(other[:4], st.epoch[:])
	st.nextOther++
	binary.BigEndian.PutUint64(other[4:], st.nextOther)
	return other
}

// ownerForStateid finds the sequencing owner for a real stateid. The mapping
// intentionally outlives CLOSE's open-state entry so an exact CLOSE replay
// can still reach the owner's one-slot reply cache.
func (st *stateStore) ownerForStateid(other [12]byte) (*owner, nfsStat) {
	if other == ([12]byte{}) || other == allOnesOther {
		return nil, nfs4ErrBadStateID
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if [4]byte(other[:4]) != st.epoch {
		return nil, nfs4ErrStaleStateID
	}
	if _, expired := st.expired[other]; expired {
		return nil, nfs4ErrExpired
	}
	o, ok := st.stateOwners[other]
	if !ok {
		return nil, nfs4ErrBadStateID
	}
	o.client.lastRenew = st.now()
	return o, nfs4OK
}

// renamePath moves open and lock state to follow a renamed object, including
// everything under a renamed directory. Without it a byte-range lock would
// keep guarding the old name, so a second client could lock the same file
// through its new name, and a file later created at the old name would
// inherit a lock nobody holds.
func (st *stateStore) renamePath(from, to string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	moved := func(p string) (string, bool) {
		switch {
		case p == from:
			return to, true
		case strings.HasPrefix(p, from+"/"):
			return to + p[len(from):], true
		default:
			return p, false
		}
	}
	for key, opens := range st.byPath {
		target, ok := moved(key)
		if !ok {
			continue
		}
		delete(st.byPath, key)
		for _, open := range opens {
			open.path, _ = moved(open.path)
		}
		st.byPath[target] = append(st.byPath[target], opens...)
	}
	for key, locks := range st.locksByPath {
		target, ok := moved(key)
		if !ok {
			continue
		}
		delete(st.locksByPath, key)
		for _, locked := range locks {
			locked.path, _ = moved(locked.path)
		}
		st.locksByPath[target] = append(st.locksByPath[target], locks...)
	}
}

// denyBlocksAnonymous reports whether an owner's deny bits refuse the access
// a special stateid asks for. RFC 7530 §9.1.4.3 requires the check: a client
// must not reach through the anonymous stateid what its own OPEN would be
// refused.
func (st *stateStore) denyBlocksAnonymous(path string, write bool) bool {
	needed := uint32(shareRead)
	if write {
		needed = shareWrite
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, held := range st.byPath[path] {
		if held.deny&needed != 0 {
			return true
		}
	}
	return false
}

// openFilesFor returns the live open files for a path, which COMMIT flushes.
func (st *stateStore) openFilesFor(p string) []*openFile {
	st.mu.Lock()
	defer st.mu.Unlock()
	var files []*openFile
	for _, held := range st.byPath[p] {
		if held.file != nil {
			files = append(files, held.file)
		}
	}
	return files
}

// openOwnerForStateid resolves the open-owner behind an open stateid. Unlike
// ownerForStateid it refuses a lock stateid, so a client cannot name one owner
// through both stateid slots of a LOCK and make the server take a single
// mutex twice.
func (st *stateStore) openOwnerForStateid(other [12]byte) (*owner, nfsStat) {
	if other == ([12]byte{}) || other == allOnesOther {
		return nil, nfs4ErrBadStateID
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if [4]byte(other[:4]) != st.epoch {
		return nil, nfs4ErrStaleStateID
	}
	if _, expired := st.expired[other]; expired {
		return nil, nfs4ErrExpired
	}
	opened, ok := st.opens[other]
	if !ok {
		return nil, nfs4ErrBadStateID
	}
	opened.client.lastRenew = st.now()
	return opened.owner, nfs4OK
}

// shareConflict reports whether an open of (access, deny) on path collides
// with a reservation held by another owner (RFC 7530 §9.9).
func (st *stateStore) shareConflictLocked(path string, o *owner, access, deny uint32) bool {
	for _, held := range st.byPath[path] {
		if held.owner == o {
			continue
		}
		if access&held.deny != 0 || deny&held.access != 0 {
			return true
		}
	}
	return false
}

// resolveStateid validates a stateid against the open table (§9.1.3). The
// zero and all-ones special stateids resolve to a nil openState: the caller
// opens the file for the duration of the request.
func (st *stateStore) resolveStateid(seq uint32, other [12]byte, path string) (*openState, nfsStat) {
	if other == ([12]byte{}) || other == allOnesOther {
		if other == ([12]byte{}) && seq != 0 || other == allOnesOther && seq != ^uint32(0) {
			return nil, nfs4ErrBadStateID
		}
		return nil, nfs4OK
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if [4]byte(other[:4]) != st.epoch {
		return nil, nfs4ErrStaleStateID
	}
	if _, expired := st.expired[other]; expired {
		return nil, nfs4ErrExpired
	}
	o, ok := st.opens[other]
	if ok {
		o.client.lastRenew = st.now()
	}
	switch {
	case !ok:
		return nil, nfs4ErrBadStateID
	case seq < o.seq:
		return nil, nfs4ErrOldStateID
	case seq > o.seq:
		return nil, nfs4ErrBadStateID
	case o.path != path:
		return nil, nfs4ErrBadStateID
	case !o.owner.confirmed:
		return nil, nfs4ErrBadStateID
	}
	return o, nfs4OK
}

// resolveIOStateid snapshots the fields needed by READ, WRITE, and SETATTR
// while holding the store lock, avoiding races with OPEN_DOWNGRADE.
func (st *stateStore) resolveIOStateid(seq uint32, other [12]byte, path string) (*openFile, uint32, bool, nfsStat) {
	if other == ([12]byte{}) || other == allOnesOther {
		if other == ([12]byte{}) && seq != 0 || other == allOnesOther && seq != ^uint32(0) {
			return nil, 0, false, nfs4ErrBadStateID
		}
		return nil, 0, true, nfs4OK
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if [4]byte(other[:4]) != st.epoch {
		return nil, 0, false, nfs4ErrStaleStateID
	}
	if _, expired := st.expired[other]; expired {
		return nil, 0, false, nfs4ErrExpired
	}
	o, ok := st.opens[other]
	if !ok {
		if l, lockOK := st.locks[other]; lockOK {
			l.client.lastRenew = st.now()
			switch {
			case seq < l.seq:
				return nil, 0, false, nfs4ErrOldStateID
			case seq > l.seq, l.path != path:
				return nil, 0, false, nfs4ErrBadStateID
			}
			return l.open.file, l.open.access, false, nfs4OK
		}
	}
	if ok {
		o.client.lastRenew = st.now()
	}
	switch {
	case !ok:
		return nil, 0, false, nfs4ErrBadStateID
	case seq < o.seq:
		return nil, 0, false, nfs4ErrOldStateID
	case seq > o.seq, o.path != path, !o.owner.confirmed:
		return nil, 0, false, nfs4ErrBadStateID
	}
	return o.file, o.access, false, nfs4OK
}

var allOnesOther = [12]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}
