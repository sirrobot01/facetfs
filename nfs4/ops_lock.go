package nfs4

import (
	"encoding/binary"
	"io/fs"
	"math"
	"slices"
	"sort"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

const maxLockOwnerID = 1024

// How one owner's sequence id relates to the request being processed.
const (
	seqFresh = iota
	seqReplay
	seqNext
)

const (
	readLT   = 1
	writeLT  = 2
	readWLT  = 3
	writeWLT = 4
)

type lockRange struct {
	start uint64
	end   uint64 // exclusive when toEOF is false
	toEOF bool
	write bool
}

func makeLockRange(offset, length uint64, write bool) (lockRange, nfsStat) {
	switch {
	case length == 0:
		return lockRange{}, nfs4ErrInval
	case length == math.MaxUint64:
		return lockRange{start: offset, toEOF: true, write: write}, nfs4OK
	case length > math.MaxUint64-offset:
		return lockRange{}, nfs4ErrInval
	default:
		return lockRange{start: offset, end: offset + length, write: write}, nfs4OK
	}
}

func lockType(t uint32) (bool, nfsStat) {
	switch t {
	case readLT, readWLT:
		return false, nfs4OK
	case writeLT, writeWLT:
		return true, nfs4OK
	default:
		return false, nfs4ErrInval
	}
}

func rangesOverlap(a, b lockRange) bool {
	aAfterBStart := a.toEOF || a.end > b.start
	bAfterAStart := b.toEOF || b.end > a.start
	return aAfterBStart && bAfterAStart
}

func subtractRange(held []lockRange, cut lockRange) []lockRange {
	out := make([]lockRange, 0, len(held)+1)
	for _, r := range held {
		if !rangesOverlap(r, cut) {
			out = append(out, r)
			continue
		}
		if r.start < cut.start {
			out = append(out, lockRange{start: r.start, end: cut.start, write: r.write})
		}
		if !cut.toEOF && (r.toEOF || r.end > cut.end) {
			out = append(out, lockRange{start: cut.end, end: r.end, toEOF: r.toEOF, write: r.write})
		}
	}
	return canonicalRanges(out)
}

func setLockRange(held []lockRange, add lockRange) []lockRange {
	held = subtractRange(held, add)
	held = append(held, add)
	return canonicalRanges(held)
}

func canonicalRanges(ranges []lockRange) []lockRange {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	out := ranges[:0]
	for _, r := range ranges {
		if len(out) == 0 {
			out = append(out, r)
			continue
		}
		last := &out[len(out)-1]
		if last.write == r.write && (last.toEOF || last.end >= r.start) {
			if r.toEOF {
				last.toEOF = true
				last.end = 0
			} else if !last.toEOF && r.end > last.end {
				last.end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func lockRangeLength(r lockRange) uint64 {
	if r.toEOF {
		return math.MaxUint64
	}
	return r.end - r.start
}

func (st *stateStore) findLockStateLocked(path string, owner *owner) *lockState {
	for _, held := range st.locksByPath[path] {
		if held.owner == owner {
			return held
		}
	}
	return nil
}

func (st *stateStore) lockConflictLocked(path string, owner *owner, requested lockRange) (*lockState, lockRange) {
	for _, state := range st.locksByPath[path] {
		if state.owner == owner {
			continue
		}
		for _, held := range state.ranges {
			if rangesOverlap(held, requested) && (held.write || requested.write) {
				return state, held
			}
		}
	}
	return nil, lockRange{}
}

func (st *stateStore) resolveLockStateid(seq uint32, other [12]byte, path string) (*lockState, nfsStat) {
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
	l, ok := st.locks[other]
	if ok {
		l.client.lastRenew = st.now()
	}
	switch {
	case !ok:
		return nil, nfs4ErrBadStateID
	case seq < l.seq:
		return nil, nfs4ErrOldStateID
	case seq > l.seq, l.path != path:
		return nil, nfs4ErrBadStateID
	}
	return l, nfs4OK
}

func encodeDenied(e *xdr.Encoder, state *lockState, held lockRange) nfsStat {
	e.Uint32(uint32(nfs4ErrDenied))
	e.Uint64(held.start)
	e.Uint64(lockRangeLength(held))
	if held.write {
		e.Uint32(writeLT)
	} else {
		e.Uint32(readLT)
	}
	e.Uint64(state.client.id)
	e.Opaque([]byte(state.owner.key))
	return nfs4ErrDenied
}

// withTwoSeqids handles the first LOCK for a lock-owner, which consumes the
// open-owner and lock-owner sequence streams atomically.
//
// The two owners are always distinct objects: open-owners and lock-owners live
// in separate per-client tables, and the caller resolves the open stateid
// through openOwnerForStateid, which never yields a lock-owner. Taking the
// open-owner first is therefore a consistent order.
func withTwoSeqids(openOwner, lockOwner *owner, openSeq, lockSeq uint32, e *xdr.Encoder, fn func(*xdr.Encoder) nfsStat) nfsStat {
	openOwner.mu.Lock()
	defer openOwner.mu.Unlock()
	lockOwner.mu.Lock()
	defer lockOwner.mu.Unlock()

	type snapshot struct {
		o     *owner
		seq   uint32
		fresh bool
		want  uint32
		state int
	}
	owners := []snapshot{{o: openOwner, seq: openOwner.seqid, fresh: openOwner.fresh, want: openSeq}, {o: lockOwner, seq: lockOwner.seqid, fresh: lockOwner.fresh, want: lockSeq}}
	replaying, advancing := 0, 0
	for i := range owners {
		s := &owners[i]
		switch {
		case s.o.fresh:
			s.state = seqFresh
			advancing++
		case s.want == s.o.seqid:
			if s.o.lastOp != opLock || s.o.lastReply == nil {
				return status(e, nfs4ErrBadSeqID)
			}
			s.state = seqReplay
			replaying++
		case s.want == s.o.seqid+1:
			s.state = seqNext
			advancing++
		default:
			return status(e, nfs4ErrBadSeqID)
		}
	}
	// A retransmission repeats both sequence ids. A request that repeats one
	// and advances the other is not a retry of anything, so answering it from
	// either cache would report a lock the client does not hold.
	if replaying > 0 && advancing > 0 {
		return status(e, nfs4ErrBadSeqID)
	}
	if replaying == len(owners) {
		reply := owners[0].o.lastReply
		e.OpaqueFixed(reply)
		return nfsStat(binary.BigEndian.Uint32(reply))
	}
	for _, s := range owners {
		s.o.fresh = false
		s.o.seqid = s.want
	}
	var result xdr.Encoder
	st := fn(&result)
	if noAdvance(st) {
		for _, s := range owners {
			s.o.seqid, s.o.fresh = s.seq, s.fresh
		}
		return status(e, st)
	}
	for _, s := range owners {
		s.o.lastOp = opLock
		s.o.lastReply = slices.Clone(result.Bytes())
	}
	e.OpaqueFixed(result.Bytes())
	return st
}

func (c *compound) lockFH() nfsStat {
	if !c.hasFH {
		return nfs4ErrNoFilehandle
	}
	fi, err := c.lstatOrStat(c.fh)
	if err != nil {
		return fhErr(err)
	}
	if fi.IsDir() {
		return nfs4ErrIsDir
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nfs4ErrSymlink
	}
	return nfs4OK
}

func (c *compound) lock(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	typ := d.Uint32()
	reclaim := d.Bool()
	offset, length := d.Uint64(), d.Uint64()
	newOwner := d.Bool()
	var openSeq, lockSeq, stateSeq uint32
	var openOther, lockOther [12]byte
	var clientID uint64
	var ownerID []byte
	if newOwner {
		openSeq = d.Uint32()
		stateSeq, openOther = decodeStateid(d)
		lockSeq = d.Uint32()
		clientID = d.Uint64()
		ownerID = d.Opaque(maxLockOwnerID)
	} else {
		stateSeq, lockOther = decodeStateid(d)
		lockSeq = d.Uint32()
	}
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	write, typeStatus := lockType(typ)
	rng, rangeStatus := makeLockRange(offset, length, write)

	if newOwner {
		openOwner, st := c.s.state.openOwnerForStateid(openOther)
		if st != nfs4OK {
			return status(e, st)
		}
		lockOwner, st := c.s.state.lockOwnerOf(clientID, string(ownerID))
		if st != nfs4OK {
			return status(e, st)
		}
		return withTwoSeqids(openOwner, lockOwner, openSeq, lockSeq, e, func(result *xdr.Encoder) nfsStat {
			if typeStatus != nfs4OK {
				return status(result, typeStatus)
			}
			if rangeStatus != nfs4OK {
				return status(result, rangeStatus)
			}
			if reclaim {
				return status(result, nfs4ErrNoGrace)
			}
			if st := c.lockFH(); st != nfs4OK {
				return status(result, st)
			}
			opened, st := c.s.state.resolveStateid(stateSeq, openOther, c.fh)
			if st != nfs4OK {
				return status(result, st)
			}
			if opened.owner != openOwner || opened.client != lockOwner.client {
				return status(result, nfs4ErrBadStateID)
			}
			state := c.s.state
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.opens[opened.other] != opened {
				return status(result, nfs4ErrBadStateID)
			}
			if write && opened.access&shareWrite == 0 || !write && opened.access&shareRead == 0 {
				return status(result, nfs4ErrOpenMode)
			}
			// The lock-owner already has state for this file, so the client
			// should have used the existing-owner form. NFS4ERR_BAD_SEQID
			// would roll the sequence ids back and wedge the stream, leaving
			// the client no way forward.
			if state.findLockStateLocked(c.fh, lockOwner) != nil {
				return status(result, nfs4ErrInval)
			}
			if conflictState, held := state.lockConflictLocked(c.fh, lockOwner, rng); conflictState != nil {
				return encodeDenied(result, conflictState, held)
			}
			locked := &lockState{
				other: state.newOther(), seq: 1, client: opened.client, owner: lockOwner,
				open: opened, path: c.fh, ranges: []lockRange{rng},
			}
			state.locks[locked.other] = locked
			state.stateOwners[locked.other] = lockOwner
			state.locksByPath[locked.path] = append(state.locksByPath[locked.path], locked)
			result.Uint32(uint32(nfs4OK))
			encodeStateid(result, locked.seq, locked.other)
			return nfs4OK
		})
	}

	lockOwner, st := c.s.state.ownerForStateid(lockOther)
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(lockOwner, opLock, lockSeq, e, nil, func(result *xdr.Encoder) nfsStat {
		if typeStatus != nfs4OK {
			return status(result, typeStatus)
		}
		if rangeStatus != nfs4OK {
			return status(result, rangeStatus)
		}
		if reclaim {
			return status(result, nfs4ErrNoGrace)
		}
		if st := c.lockFH(); st != nfs4OK {
			return status(result, st)
		}
		locked, st := c.s.state.resolveLockStateid(stateSeq, lockOther, c.fh)
		if st != nfs4OK {
			return status(result, st)
		}
		state := c.s.state
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.locks[lockOther] != locked || state.opens[locked.open.other] != locked.open {
			return status(result, nfs4ErrBadStateID)
		}
		// The open's access bits are read here, not before taking the lock:
		// OPEN_DOWNGRADE runs under the open-owner's mutex, which this path
		// does not hold, so a check outside could grant a write lock on an
		// open that has just become read-only.
		if write && locked.open.access&shareWrite == 0 || !write && locked.open.access&shareRead == 0 {
			return status(result, nfs4ErrOpenMode)
		}
		if conflictState, held := state.lockConflictLocked(c.fh, lockOwner, rng); conflictState != nil {
			return encodeDenied(result, conflictState, held)
		}
		locked.ranges = setLockRange(locked.ranges, rng)
		locked.seq++
		locked.client.lastRenew = state.now()
		result.Uint32(uint32(nfs4OK))
		encodeStateid(result, locked.seq, locked.other)
		return nfs4OK
	})
}

func (c *compound) lockT(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	typ := d.Uint32()
	offset, length := d.Uint64(), d.Uint64()
	clientID := d.Uint64()
	ownerID := d.Opaque(maxLockOwnerID)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	owner, st := c.s.state.lockTestOwner(clientID, string(ownerID))
	if st != nfs4OK {
		return status(e, st)
	}
	write, st := lockType(typ)
	if st != nfs4OK {
		return status(e, st)
	}
	rng, st := makeLockRange(offset, length, write)
	if st != nfs4OK {
		return status(e, st)
	}
	if st := c.lockFH(); st != nfs4OK {
		return status(e, st)
	}
	state := c.s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if conflictState, held := state.lockConflictLocked(c.fh, owner, rng); conflictState != nil {
		return encodeDenied(e, conflictState, held)
	}
	return status(e, nfs4OK)
}

func (st *stateStore) lockTestOwner(clientID uint64, key string) (*owner, nfsStat) {
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
	if owner := c.lockOwners[key]; owner != nil {
		return owner, nfs4OK
	}
	// An unregistered identity is enough for LOCKT's same-owner exclusion.
	return &owner{key: key, client: c}, nfs4OK
}

func (c *compound) lockU(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	typ := d.Uint32()
	seqid := d.Uint32()
	stateSeq, other := decodeStateid(d)
	offset, length := d.Uint64(), d.Uint64()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	_, typeStatus := lockType(typ)
	rng, rangeStatus := makeLockRange(offset, length, false)
	owner, st := c.s.state.ownerForStateid(other)
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(owner, opLockU, seqid, e, nil, func(result *xdr.Encoder) nfsStat {
		if typeStatus != nfs4OK {
			return status(result, typeStatus)
		}
		if rangeStatus != nfs4OK {
			return status(result, rangeStatus)
		}
		if st := c.lockFH(); st != nfs4OK {
			return status(result, st)
		}
		locked, st := c.s.state.resolveLockStateid(stateSeq, other, c.fh)
		if st != nfs4OK {
			return status(result, st)
		}
		state := c.s.state
		state.mu.Lock()
		if state.locks[other] != locked || state.opens[locked.open.other] != locked.open {
			state.mu.Unlock()
			return status(result, nfs4ErrBadStateID)
		}
		locked.ranges = subtractRange(locked.ranges, rng)
		locked.seq++
		locked.client.lastRenew = state.now()
		newSeq := locked.seq
		state.mu.Unlock()
		result.Uint32(uint32(nfs4OK))
		encodeStateid(result, newSeq, other)
		return nfs4OK
	})
}

func (c *compound) releaseLockOwner(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	clientID := d.Uint64()
	ownerID := d.Opaque(maxLockOwnerID)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	state := c.s.state
	state.mu.Lock()
	client, ok := state.confirmed[clientID]
	if !ok {
		if _, expired := state.expiredIDs[clientID]; expired {
			state.mu.Unlock()
			return status(e, nfs4ErrExpired)
		}
		state.mu.Unlock()
		return status(e, nfs4ErrStaleClientID)
	}
	client.lastRenew = state.now()
	key := string(ownerID)
	owner := client.lockOwners[key]
	if owner == nil {
		state.mu.Unlock()
		return status(e, nfs4OK)
	}
	state.mu.Unlock()

	owner.mu.Lock()
	defer owner.mu.Unlock()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.confirmed[clientID] != client || client.lockOwners[key] != owner {
		if _, expired := state.expiredIDs[clientID]; expired {
			return status(e, nfs4ErrExpired)
		}
		return status(e, nfs4OK)
	}
	client.lastRenew = state.now()
	for _, locked := range state.locks {
		if locked.owner == owner && len(locked.ranges) != 0 {
			return status(e, nfs4ErrLocksHeld)
		}
	}
	for other, locked := range state.locks {
		if locked.owner == owner {
			delete(state.locks, other)
			delete(state.stateOwners, other)
			state.removeLockStateLocked(locked)
		}
	}
	delete(client.lockOwners, key)
	return status(e, nfs4OK)
}
