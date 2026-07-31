package nfs4

import (
	"os"
	"path"
	"slices"

	"github.com/sirrobot01/facetfs/internal/xdr"
)

const (
	maxClientOwnerID = 1024
	maxOpenOwnerID   = 1024

	shareRead  = 1
	shareWrite = 2
	shareBoth  = 3

	denyNone  = 0
	denyRead  = 1
	denyWrite = 2
	denyBoth  = 3

	openNoCreate = 0
	openCreate   = 1

	createUnchecked = 0
	createGuarded   = 1
	createExclusive = 2

	claimNull         = 0
	claimPrevious     = 1
	claimDelegCur     = 2
	claimDelegPrev    = 3
	openResultConfirm = 2

	openDelegateNone = 0
)

// noAdvance lists the statuses that leave an owner's sequence id untouched
// and uncached (RFC 7530 §9.1.7).
func noAdvance(st nfsStat) bool {
	switch st {
	case nfs4ErrBadSeqID, nfs4ErrStaleClientID, nfs4ErrStaleStateID,
		nfs4ErrBadStateID, nfs4ErrBadXDR, nfs4ErrResource,
		nfs4ErrNoFilehandle, nfs4ErrMoved:
		return true
	}
	return false
}

// withSeqid applies an owner's sequence discipline to one op: it replays the
// cached reply for a repeat of the last request, rejects anything out of
// order, and caches the encoded result of a fresh one.
func withSeqid(o *owner, opnum, seqid uint32, e *xdr.Encoder, replay func(), fn func(*xdr.Encoder) nfsStat) nfsStat {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case o.fresh:
		o.fresh = false
		o.seqid = seqid
	case seqid == o.seqid:
		if o.lastOp != opnum || o.lastReply == nil {
			return status(e, nfs4ErrBadSeqID)
		}
		e.OpaqueFixed(o.lastReply)
		st := nfsStat(uint32(o.lastReply[0])<<24 | uint32(o.lastReply[1])<<16 |
			uint32(o.lastReply[2])<<8 | uint32(o.lastReply[3]))
		if replay != nil && st == nfs4OK {
			replay()
		}
		return st
	case seqid == o.seqid+1:
		o.seqid = seqid
	default:
		return status(e, nfs4ErrBadSeqID)
	}

	var result xdr.Encoder
	st := fn(&result)
	if noAdvance(st) {
		o.seqid--
		if o.lastReply == nil {
			o.fresh = true
		}
		return status(e, st)
	}
	o.lastOp = opnum
	o.lastReply = slices.Clone(result.Bytes())
	e.OpaqueFixed(result.Bytes())
	return st
}

func encodeStateid(e *xdr.Encoder, seq uint32, other [12]byte) {
	e.Uint32(seq)
	e.OpaqueFixed(other[:])
}

func decodeStateid(d *xdr.Decoder) (uint32, [12]byte) {
	seq := d.Uint32()
	var other [12]byte
	copy(other[:], d.OpaqueFixed(12))
	return seq, other
}

// changeInfo reports a directory's change attribute before and after a
// mutation. Atomicity is never claimed: the two reads bracket a separate
// FileSystem call.
func (c *compound) changeOfDir(p string) uint64 {
	fi, err := c.s.FileSystem.Stat(c.ctx, p)
	if err != nil {
		return 0
	}
	return changeOf(fi)
}

func encodeChangeInfo(e *xdr.Encoder, before, after uint64) {
	e.Bool(false)
	e.Uint64(before)
	e.Uint64(after)
}

func openFlags(access uint32) int {
	switch access & shareBoth {
	case shareRead:
		return os.O_RDONLY
	case shareWrite:
		return os.O_WRONLY
	default:
		return os.O_RDWR
	}
}

// open implements OPEN (RFC 7530 §16.18) for CLAIM_NULL only: with no
// persistent state there is nothing to reclaim, so reclaim claims are
// refused rather than pretended.
func (c *compound) open(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	seqid := d.Uint32()
	access := d.Uint32()
	deny := d.Uint32()
	clientID := d.Uint64()
	ownerID := d.Opaque(maxOpenOwnerID)
	openType := d.Uint32()
	var (
		createMode uint32
		createAttr bitmap
		createVals []byte
		createVerf [8]byte
		name       string
		argStatus  = nfs4OK
	)
	if openType == openCreate {
		createMode = d.Uint32()
		switch createMode {
		case createUnchecked, createGuarded:
			createAttr = decodeBitmap(d)
			createVals = d.Opaque(uint32(c.s.requestCap()))
		case createExclusive:
			copy(createVerf[:], d.OpaqueFixed(8))
		default:
			argStatus = nfs4ErrInval
		}
	}
	claim := d.Uint32()
	switch claim {
	case claimNull:
		name, argStatus = decodeName(d)
	case claimPrevious:
		d.Uint32() // delegation type requested for reclaim
	case claimDelegCur:
		decodeStateid(d)
		name, argStatus = decodeName(d)
	case claimDelegPrev:
		name, argStatus = decodeName(d)
	default:
		argStatus = nfs4ErrInval
	}
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	o, st := c.s.state.ownerOf(clientID, string(ownerID))
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(o, opOpen, seqid, e, func() { c.fh, c.hasFH = o.lastFH, true }, func(result *xdr.Encoder) nfsStat {
		if argStatus != nfs4OK {
			return status(result, argStatus)
		}
		return c.openWith(result, o, access, deny, openType, createMode, createAttr, createVals, createVerf, claim, name)
	})
}

func (c *compound) openWith(e *xdr.Encoder, owner *owner, access, deny, openType, createMode uint32, attrMask bitmap, attrVals []byte, createVerf [8]byte, claim uint32, name string) nfsStat {
	switch {
	case access == 0 || access&^uint32(shareBoth) != 0, deny&^uint32(denyBoth) != 0:
		return status(e, nfs4ErrInval)
	case openType != openNoCreate && openType != openCreate:
		return status(e, nfs4ErrInval)
	case claim == claimPrevious:
		return status(e, nfs4ErrNoGrace)
	case claim != claimNull:
		return status(e, nfs4ErrNotSupp)
	}
	if st := c.dirFH(); st != nfs4OK {
		return status(e, st)
	}

	attrs, st := decodeSetAttrs(c.s.supported, attrMask, attrVals)
	if st != nfs4OK {
		return status(e, st)
	}
	if openType == openNoCreate && (len(attrMask) != 0 || len(attrVals) != 0) {
		return status(e, nfs4ErrBadXDR)
	}
	target := path.Join(c.fh, name)
	before := c.changeOfDir(c.fh)
	fi, statErr := c.lstatOrStat(target)
	exists := statErr == nil
	if statErr != nil && nameErr(statErr) != nfs4ErrNoEnt {
		return status(e, nameErr(statErr))
	}
	if openType == openNoCreate && !exists {
		return status(e, nfs4ErrNoEnt)
	}
	if openType == openCreate && createMode == createGuarded && exists {
		return status(e, nfs4ErrExist)
	}
	// An exclusive create that names an existing file is only allowed when it
	// is a retransmission of the create that made it, which the verifier
	// identifies (RFC 7530 §16.18.4).
	if openType == openCreate && createMode == createExclusive && exists &&
		!c.s.exclusive.matches(target, createVerf) {
		return status(e, nfs4ErrExist)
	}
	if exists {
		switch {
		case fi.IsDir():
			return status(e, nfs4ErrIsDir)
		case fi.Mode()&os.ModeSymlink != 0:
			return status(e, nfs4ErrSymlink)
		}
	}

	state := c.s.state
	state.mu.Lock()
	held := findOpenLocked(state, target, owner)
	unionAccess, unionDeny := access, deny
	if held != nil {
		unionAccess |= held.access
		unionDeny |= held.deny
	}
	if state.shareConflictLocked(target, owner, unionAccess, unionDeny) {
		state.mu.Unlock()
		return status(e, nfs4ErrShareDenied)
	}
	state.mu.Unlock()

	// A truncating open arrives as a size of zero in the create attributes.
	// Serving it through the open flag rather than through SetStatFS is what
	// lets a filesystem that implements only the core interface be truncated,
	// and it is how Linux opens a file with O_TRUNC.
	truncating := openType == openCreate && attrs.size != nil && *attrs.size == 0
	if truncating {
		attrs.size = nil
		attrs.applied.set(attrSize)
	}
	flags := openFlags(unionAccess)
	needOpen := held == nil || held.flag != flags || truncating
	var replacement *openFile
	if needOpen {
		openFlags := flags
		if openType == openCreate {
			openFlags |= os.O_CREATE
			// An exclusive create that reached here either found nothing or
			// is a retransmission, so O_EXCL applies only to the first.
			if createMode == createGuarded || createMode == createExclusive && !exists {
				openFlags |= os.O_EXCL
			}
		}
		if truncating {
			openFlags |= os.O_TRUNC
		}
		perm := os.FileMode(0o666)
		if attrs.mode != nil {
			perm = *attrs.mode
		}
		f, err := c.s.FileSystem.OpenFile(c.ctx, target, openFlags, perm)
		if err != nil {
			return status(e, nameErr(err))
		}
		replacement = newOpenFile(f)
	}
	if openType == openCreate {
		createdMode := attrs.mode
		if !exists && createdMode != nil {
			attrs.mode = nil
			attrs.applied.set(attrMode)
		}
		if st := c.applySetAttrs(target, attrs, true); st != nfs4OK {
			attrs.mode = createdMode
			if replacement != nil {
				replacement.Close()
			}
			if !exists && (createMode == createGuarded || createMode == createExclusive) {
				_ = c.s.FileSystem.RemoveAll(c.ctx, target)
				c.s.exclusive.forget(target)
			}
			return status(e, st)
		}
		attrs.mode = createdMode
		if createMode == createExclusive {
			c.s.exclusive.record(target, createVerf)
		}
	}

	state.mu.Lock()
	held = findOpenLocked(state, target, owner)
	if state.shareConflictLocked(target, owner, unionAccess, unionDeny) {
		state.mu.Unlock()
		if replacement != nil {
			replacement.Close()
		}
		return status(e, nfs4ErrShareDenied)
	}
	var old *openFile
	if held == nil {
		if owner.client.opens >= maxOpensPerClient {
			state.mu.Unlock()
			if replacement != nil {
				replacement.Close()
			}
			return status(e, nfs4ErrResource)
		}
		held = &openState{
			other: state.newOther(), seq: 1, client: owner.client, owner: owner,
			path: target, access: unionAccess, deny: unionDeny, file: replacement, flag: flags,
		}
		state.opens[held.other] = held
		state.stateOwners[held.other] = owner
		state.byPath[target] = append(state.byPath[target], held)
		owner.client.opens++
	} else {
		held.seq++
		held.access, held.deny = unionAccess, unionDeny
		if replacement != nil {
			old, held.file, held.flag = held.file, replacement, flags
		}
	}
	other, stateSeq := held.other, held.seq
	confirm := !owner.confirmed
	owner.client.lastRenew = state.now()
	state.mu.Unlock()
	if old != nil {
		old.Close()
	}

	c.fh = target
	owner.lastFH = target
	e.Uint32(uint32(nfs4OK))
	encodeStateid(e, stateSeq, other)
	encodeChangeInfo(e, before, c.changeOfDir(path.Dir(target)))
	if confirm {
		e.Uint32(openResultConfirm)
	} else {
		e.Uint32(0)
	}
	encodeBitmap(e, attrs.applied)
	e.Uint32(openDelegateNone)
	return nfs4OK
}

func findOpenLocked(st *stateStore, p string, owner *owner) *openState {
	for _, held := range st.byPath[p] {
		if held.owner == owner {
			return held
		}
	}
	return nil
}

func (c *compound) openConfirm(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	stateSeq, other := decodeStateid(d)
	seqid := d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	o, st := c.s.state.ownerForStateid(other)
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(o, opOpenConfirm, seqid, e, nil, func(result *xdr.Encoder) nfsStat {
		if !c.hasFH {
			return status(result, nfs4ErrNoFilehandle)
		}
		state := c.s.state
		state.mu.Lock()
		defer state.mu.Unlock()
		held, ok := state.opens[other]
		switch {
		case !ok || held.owner != o:
			return status(result, nfs4ErrBadStateID)
		case stateSeq < held.seq:
			return status(result, nfs4ErrOldStateID)
		case stateSeq > held.seq, held.path != c.fh:
			return status(result, nfs4ErrBadStateID)
		}
		o.confirmed = true
		held.client.lastRenew = state.now()
		result.Uint32(uint32(nfs4OK))
		encodeStateid(result, held.seq, held.other)
		return nfs4OK
	})
}

func (c *compound) openDowngrade(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	stateSeq, other := decodeStateid(d)
	seqid := d.Uint32()
	access, deny := d.Uint32(), d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	o, st := c.s.state.ownerForStateid(other)
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(o, opOpenDowngrade, seqid, e, nil, func(result *xdr.Encoder) nfsStat {
		if !c.hasFH {
			return status(result, nfs4ErrNoFilehandle)
		}
		if access == 0 || access&^uint32(shareBoth) != 0 || deny&^uint32(denyBoth) != 0 {
			return status(result, nfs4ErrInval)
		}
		held, st := c.s.state.resolveStateid(stateSeq, other, c.fh)
		if st != nfs4OK {
			return status(result, st)
		}
		if access&held.access != access || deny&held.deny != deny {
			return status(result, nfs4ErrInval)
		}
		state := c.s.state
		state.mu.Lock()
		blocked := state.locksBlockDowngradeLocked(held, access)
		state.mu.Unlock()
		if blocked {
			return status(result, nfs4ErrLocksHeld)
		}
		flags := openFlags(access)
		var replacement *openFile
		if flags != held.flag {
			f, err := c.s.FileSystem.OpenFile(c.ctx, held.path, flags, 0)
			if err != nil {
				return status(result, fhErr(err))
			}
			replacement = newOpenFile(f)
		}
		state.mu.Lock()
		if state.opens[other] != held || held.seq != stateSeq {
			state.mu.Unlock()
			if replacement != nil {
				replacement.Close()
			}
			return status(result, nfs4ErrBadStateID)
		}
		if state.locksBlockDowngradeLocked(held, access) {
			state.mu.Unlock()
			if replacement != nil {
				replacement.Close()
			}
			return status(result, nfs4ErrLocksHeld)
		}
		old := held.file
		held.seq++
		held.access, held.deny = access, deny
		if replacement != nil {
			held.file, held.flag = replacement, flags
		}
		held.client.lastRenew = state.now()
		newSeq := held.seq
		state.mu.Unlock()
		if replacement != nil {
			old.Close()
		}
		result.Uint32(uint32(nfs4OK))
		encodeStateid(result, newSeq, other)
		return nfs4OK
	})
}

func (c *compound) close(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	seqid := d.Uint32()
	stateSeq, other := decodeStateid(d)
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	o, st := c.s.state.ownerForStateid(other)
	if st != nfs4OK {
		return status(e, st)
	}
	return withSeqid(o, opClose, seqid, e, nil, func(result *xdr.Encoder) nfsStat {
		if !c.hasFH {
			return status(result, nfs4ErrNoFilehandle)
		}
		held, st := c.s.state.resolveStateid(stateSeq, other, c.fh)
		if st != nfs4OK {
			return status(result, st)
		}
		state := c.s.state
		state.mu.Lock()
		if state.opens[other] != held || held.seq != stateSeq {
			state.mu.Unlock()
			return status(result, nfs4ErrBadStateID)
		}
		if state.locksBlockCloseLocked(held) {
			state.mu.Unlock()
			return status(result, nfs4ErrLocksHeld)
		}
		state.removeEmptyLocksForOpenLocked(held)
		delete(state.opens, other)
		held.client.opens--
		state.removePathLocked(held)
		// Only the newest closed stateid is needed to route an exact replay
		// to this owner's one-slot cache.
		for prior, priorOwner := range state.stateOwners {
			if prior != other && priorOwner == o {
				if _, live := state.opens[prior]; !live {
					delete(state.stateOwners, prior)
				}
			}
		}
		held.seq++
		closedSeq, file := held.seq, held.file
		held.client.lastRenew = state.now()
		state.mu.Unlock()
		if err := file.Close(); err != nil {
			return status(result, nfs4ErrIO)
		}
		result.Uint32(uint32(nfs4OK))
		encodeStateid(result, closedSeq, other)
		return nfs4OK
	})
}

func (c *compound) setClientID(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	var verifier [8]byte
	copy(verifier[:], d.OpaqueFixed(8))
	ownerID := d.Opaque(maxClientOwnerID)
	cb := callbackPath{program: d.Uint32()}
	netid := d.String(16)
	uaddr := d.String(64)
	cb.ident = d.Uint32()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	// An unusable callback address is not an error (RFC 7530 §16.33.5): the
	// client is registered and simply never receives a delegation.
	cb.addr, _ = parseUniversalAddr(netid, uaddr)
	id, confirmVerf, st := c.s.state.setClientID(string(ownerID), verifier, principalOf(c.cred), cb)
	if st != nfs4OK {
		e.Uint32(uint32(st))
		// NFS4ERR_CLID_INUSE carries the holder's address; none is tracked.
		e.String("tcp")
		e.String("")
		return st
	}
	e.Uint32(uint32(nfs4OK))
	e.Uint64(id)
	e.OpaqueFixed(confirmVerf[:])
	return nfs4OK
}

func (c *compound) setClientIDConfirm(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	id := d.Uint64()
	var confirmVerf [8]byte
	copy(confirmVerf[:], d.OpaqueFixed(8))
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	confirmed, st := c.s.state.confirmClientID(id, confirmVerf)
	if confirmed != nil && confirmed.cb.addr != "" {
		go c.s.probeCallback(confirmed)
	}
	return status(e, st)
}

func (c *compound) renew(d *xdr.Decoder, e *xdr.Encoder) nfsStat {
	id := d.Uint64()
	if d.Err() != nil {
		return status(e, nfs4ErrBadXDR)
	}
	return status(e, c.s.state.renew(id))
}
