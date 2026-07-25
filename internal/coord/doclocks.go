package coord

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ErrLimit reports that a state table refused an entry because a configured
// resource ceiling was reached.
var ErrLimit = errors.New("state limit")

// sweepInterval bounds how often a ceiling-triggered sweep may scan the table,
// so a table held at its limit by live locks cannot turn every acquisition into
// a full scan.
const sweepInterval = time.Second

// DocLock is a whole-object advisory lock, such as a WebDAV Class 2 write lock.
// Authority is carried by the opaque Token rather than by a connection session,
// so a lock survives the request that created it until release or expiry.
type DocLock struct {
	Token string
	Key   string
	Owner string
	// Exclusive locks conflict with any other lock on the key; shared locks
	// conflict only with an exclusive one.
	Exclusive bool
	// Deep records that the lock was requested over the members of a collection.
	// It is stored for discovery only: Guard resolves a single key, so a deep
	// lock protects its own object alone. Callers must not present a deep lock as
	// covering descendants until the table can express containment.
	Deep    bool
	Expires time.Time
}

type docLockShard struct {
	mu    sync.Mutex
	locks map[string][]DocLock
}

// DocLockTable stores object-scoped advisory locks with expiry, sharded by key
// so unrelated objects never contend on a shared mutex.
type DocLockTable struct {
	now       func() time.Time
	max       int64
	count     atomic.Int64
	sweepMu   sync.Mutex
	lastSweep int64
	shards    [shardCount]docLockShard
}

// NewDocLockTable returns a table that expires locks against now and refuses new
// locks once max are held. A non-positive max disables the ceiling. The ceiling
// is tested before the key is locked, so concurrent acquisitions may overshoot
// max by at most the number of them in flight; it bounds memory rather than
// admitting an exact count.
func NewDocLockTable(now func() time.Time, max int64) *DocLockTable {
	if now == nil {
		now = time.Now
	}
	return &DocLockTable{now: now, max: max}
}

// Acquire records lock unless an incompatible lock is already held on its key.
// Exclusive locks conflict with any existing lock; shared locks conflict only
// with an exclusive lock.
func (t *DocLockTable) Acquire(lock DocLock) (DocLock, error) {
	if lock.Token == "" || lock.Key == "" {
		return DocLock{}, ErrLimit
	}
	now := t.now()
	if t.max > 0 && t.count.Load() >= t.max {
		// The count includes locks that expired on keys no caller has revisited,
		// since live() only reclaims the key it is passed. Sweep before refusing so
		// the ceiling cannot wedge on locks that are no longer held.
		t.sweep(now)
		if t.count.Load() >= t.max {
			return DocLock{}, ErrLimit
		}
	}
	shard := &t.shards[shardIndex(lock.Key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	existing := t.live(shard, lock.Key, now)
	for _, held := range existing {
		if lock.Exclusive || held.Exclusive {
			return DocLock{}, ErrConflict
		}
	}
	if shard.locks == nil {
		shard.locks = make(map[string][]DocLock)
	}
	shard.locks[lock.Key] = append(existing, lock)
	t.count.Add(1)
	return lock, nil
}

// Release drops the lock identified by token on key and reports whether it was
// found.
func (t *DocLockTable) Release(key, token string) bool {
	now := t.now()
	shard := &t.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	existing := t.live(shard, key, now)
	for i, held := range existing {
		if held.Token != token {
			continue
		}
		existing = slices.Delete(existing, i, i+1)
		t.count.Add(-1)
		if len(existing) == 0 {
			delete(shard.locks, key)
		} else {
			shard.locks[key] = existing
		}
		return true
	}
	return false
}

// ReleaseKey drops every lock held on key and reports how many were removed. It
// is for keys whose object has ceased to exist: a lock must not outlive its
// object, both because a later object could reuse the key and because the
// abandoned entry would hold a slot against the table ceiling until it expired.
func (t *DocLockTable) ReleaseKey(key string) int {
	shard := &t.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	// Every stored entry counts against the ceiling, including any that has
	// expired without yet being reclaimed, so the whole slice is discounted.
	dropped := len(shard.locks[key])
	if dropped == 0 {
		return 0
	}
	delete(shard.locks, key)
	t.count.Add(-int64(dropped))
	return dropped
}

// Refresh extends the expiry of the lock identified by token on key.
func (t *DocLockTable) Refresh(key, token string, expires time.Time) (DocLock, bool) {
	now := t.now()
	shard := &t.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	existing := t.live(shard, key, now)
	for i := range existing {
		if existing[i].Token != token {
			continue
		}
		existing[i].Expires = expires
		shard.locks[key] = existing
		return existing[i], true
	}
	return DocLock{}, false
}

// Guard reports a lock on key that none of tokens satisfies. A mutation whose
// caller presents no matching token must be rejected when a lock is returned.
func (t *DocLockTable) Guard(key string, tokens []string) (DocLock, bool) {
	now := t.now()
	shard := &t.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	existing := t.live(shard, key, now)
	if len(existing) == 0 {
		return DocLock{}, false
	}
	for _, held := range existing {
		if slices.Contains(tokens, held.Token) {
			return DocLock{}, false
		}
	}
	return existing[0], true
}

// Holder returns a live lock on key for discovery, if any is held.
func (t *DocLockTable) Holder(key string) (DocLock, bool) {
	now := t.now()
	shard := &t.shards[shardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	existing := t.live(shard, key, now)
	if len(existing) == 0 {
		return DocLock{}, false
	}
	return existing[0], true
}

// sweep drops expired locks across every shard, correcting the live count. It is
// the only reclamation path for keys that no caller revisits, so without it a
// table whose locks have all expired would refuse acquisitions forever. Callers
// that lose the race to a concurrent sweep block until it finishes and then
// observe the corrected count, so the ceiling is never reported stale.
func (t *DocLockTable) sweep(now time.Time) {
	t.sweepMu.Lock()
	defer t.sweepMu.Unlock()
	stamp := now.UnixNano()
	if stamp-t.lastSweep < int64(sweepInterval) {
		return
	}
	t.lastSweep = stamp
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		for key := range shard.locks {
			// live prunes expired entries and deletes emptied keys; deleting during
			// a range is safe and the deleted key is simply not revisited.
			t.live(shard, key, now)
		}
		shard.mu.Unlock()
	}
}

// live returns the unexpired locks on key, dropping expired entries and pruning
// empty keys. The caller must hold shard.mu.
func (t *DocLockTable) live(shard *docLockShard, key string, now time.Time) []DocLock {
	locks := shard.locks[key]
	if len(locks) == 0 {
		return nil
	}
	kept := make([]DocLock, 0, len(locks))
	for _, lock := range locks {
		if lock.Expires.After(now) {
			kept = append(kept, lock)
		} else {
			t.count.Add(-1)
		}
	}
	if len(kept) == 0 {
		delete(shard.locks, key)
		return nil
	}
	shard.locks[key] = kept
	return kept
}
