package nfs4

import (
	"sync"
	"time"
)

// exclusiveCreates remembers the verifier of each EXCLUSIVE4 create so that a
// retransmitted OPEN is recognised as the same request rather than answered
// with NFS4ERR_EXIST (RFC 7530 §16.18.4). Linux uses this create mode for an
// ordinary file creation, so a server that refuses it cannot be written to at
// all.
//
// The record is only needed until the client stops retrying, so it is held in
// memory and expires. After a restart a retransmission is answered EXIST,
// which is the same staleness the volatile filehandles already carry.
type exclusiveCreates struct {
	now func() time.Time
	ttl time.Duration
	max int

	mu    sync.Mutex
	verfs map[string]exclusiveRecord
}

type exclusiveRecord struct {
	verf [8]byte
	at   time.Time
}

func newExclusiveCreates(now func() time.Time, ttl time.Duration, max int) *exclusiveCreates {
	return &exclusiveCreates{now: now, ttl: ttl, max: max, verfs: map[string]exclusiveRecord{}}
}

// matches reports whether path was created by an exclusive create carrying
// the same verifier, which makes this request a retransmission of that one.
func (x *exclusiveCreates) matches(path string, verf [8]byte) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	held, ok := x.verfs[path]
	if !ok {
		return false
	}
	if x.now().Sub(held.at) > x.ttl {
		delete(x.verfs, path)
		return false
	}
	return held.verf == verf
}

func (x *exclusiveCreates) record(path string, verf [8]byte) {
	now := x.now()
	x.mu.Lock()
	defer x.mu.Unlock()
	for held, record := range x.verfs {
		if now.Sub(record.at) > x.ttl {
			delete(x.verfs, held)
		}
	}
	if len(x.verfs) >= x.max {
		// The table only speeds up a retry, so dropping the oldest entry
		// costs a duplicate create an EXIST it would not otherwise get.
		oldest, at := "", now
		for held, record := range x.verfs {
			if !record.at.After(at) {
				oldest, at = held, record.at
			}
		}
		delete(x.verfs, oldest)
	}
	x.verfs[path] = exclusiveRecord{verf: verf, at: now}
}

func (x *exclusiveCreates) forget(path string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.verfs, path)
}
