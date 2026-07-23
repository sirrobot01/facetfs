package coord

import (
	"math"
	"slices"
	"sync"
	"sync/atomic"
)

type RangeLock struct {
	ID        uint64
	Key       string
	Owner     string
	Offset    uint64
	Length    uint64
	Exclusive bool
}

type lockShard struct {
	mu    sync.Mutex
	locks map[string][]RangeLock
}

type LockTable struct {
	next   atomic.Uint64
	shards [shardCount]lockShard
}

func (t *LockTable) Lock(key, owner string, offset, length uint64, exclusive bool) (RangeLock, error) {
	shard := t.lockShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for _, existing := range shard.locks[key] {
		if existing.Owner != owner && overlaps(offset, length, existing.Offset, existing.Length) && (exclusive || existing.Exclusive) {
			return RangeLock{}, ErrConflict
		}
	}
	if shard.locks == nil {
		shard.locks = make(map[string][]RangeLock)
	}
	lock := RangeLock{ID: t.next.Add(1), Key: key, Owner: owner, Offset: offset, Length: length, Exclusive: exclusive}
	shard.locks[key] = append(shard.locks[key], lock)
	return lock, nil
}

func (t *LockTable) Unlock(lock RangeLock) {
	shard := t.lockShard(lock.Key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	locks := shard.locks[lock.Key]
	for i := range locks {
		if locks[i].ID != lock.ID {
			continue
		}
		locks[i] = locks[len(locks)-1]
		locks = locks[:len(locks)-1]
		if len(locks) == 0 {
			delete(shard.locks, lock.Key)
		} else {
			shard.locks[lock.Key] = locks
		}
		return
	}
}

func (t *LockTable) Conflicts(key, owner string, offset, length uint64, write bool) bool {
	shard := t.lockShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for _, lock := range shard.locks[key] {
		if lock.Owner != owner && overlaps(offset, length, lock.Offset, lock.Length) && (write || lock.Exclusive) {
			return true
		}
	}
	return false
}

func (t *LockTable) ReleaseOwner(owner string) {
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		for key, locks := range shard.locks {
			kept := slices.DeleteFunc(locks, func(lock RangeLock) bool { return lock.Owner == owner })
			if len(kept) == 0 {
				delete(shard.locks, key)
			} else {
				shard.locks[key] = kept
			}
		}
		shard.mu.Unlock()
	}
}

func (t *LockTable) lockShard(key string) *lockShard {
	return &t.shards[shardIndex(key)]
}

func overlaps(aOffset, aLength, bOffset, bLength uint64) bool {
	aEnd := rangeEnd(aOffset, aLength)
	bEnd := rangeEnd(bOffset, bLength)
	return aOffset < bEnd && bOffset < aEnd
}

func rangeEnd(offset, length uint64) uint64 {
	if length == 0 || length > math.MaxUint64-offset {
		return math.MaxUint64
	}
	return offset + length
}
