package nfs4

import (
	"crypto/rand"
	"strconv"
	"sync"
	"time"
)

// stateStore holds all NFSv4 state in memory. Nothing survives a restart:
// clients discover this through stale clientids and volatile filehandles.
type stateStore struct {
	mu    sync.Mutex
	now   func() time.Time
	lease time.Duration

	nextClient  uint64
	confirmed   map[uint64]*client
	unconfirmed map[uint64]*client
	byOwner     map[string]*client // confirmed records by nfs_client_id4.id
}

type client struct {
	id          uint64
	ownerID     string
	verifier    [8]byte // client's boot verifier from SETCLIENTID
	confirmVerf [8]byte // server-issued setclientid_confirm
	principal   string
	lastRenew   time.Time
}

func newStateStore(lease time.Duration) *stateStore {
	return &stateStore{
		now:         time.Now,
		lease:       lease,
		confirmed:   map[uint64]*client{},
		unconfirmed: map[uint64]*client{},
		byOwner:     map[string]*client{},
	}
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
func (st *stateStore) setClientID(ownerID string, verifier [8]byte, principal string) (uint64, [8]byte, nfsStat) {
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
		id:        st.nextClient,
		ownerID:   ownerID,
		verifier:  verifier,
		principal: principal,
		lastRenew: st.now(),
	}
	rand.Read(c.confirmVerf[:])
	st.unconfirmed[c.id] = c
	return c.id, c.confirmVerf, nfs4OK
}

// confirmClientID implements SETCLIENTID_CONFIRM. Confirming replaces any
// previously confirmed record for the same owner — the client rebooted — and
// releases that record's state. Re-confirming an already confirmed pair is
// idempotent because clients retry over connection loss.
func (st *stateStore) confirmClientID(id uint64, confirmVerf [8]byte) nfsStat {
	st.mu.Lock()
	defer st.mu.Unlock()
	if c, ok := st.unconfirmed[id]; ok && c.confirmVerf == confirmVerf {
		delete(st.unconfirmed, id)
		if old, ok := st.byOwner[c.ownerID]; ok {
			st.releaseLocked(old)
		}
		st.confirmed[c.id] = c
		st.byOwner[c.ownerID] = c
		c.lastRenew = st.now()
		return nfs4OK
	}
	if c, ok := st.confirmed[id]; ok && c.confirmVerf == confirmVerf {
		c.lastRenew = st.now()
		return nfs4OK
	}
	return nfs4ErrStaleClientID
}

func (st *stateStore) renew(id uint64) nfsStat {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.confirmed[id]
	if !ok {
		return nfs4ErrStaleClientID
	}
	c.lastRenew = st.now()
	return nfs4OK
}

// releaseLocked drops a client and all its state. Callers hold st.mu.
func (st *stateStore) releaseLocked(c *client) {
	delete(st.confirmed, c.id)
	if st.byOwner[c.ownerID] == c {
		delete(st.byOwner, c.ownerID)
	}
}
