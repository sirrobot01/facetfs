package coord

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
)

const shardCount = 64

var ErrConflict = errors.New("state conflict")

type Reservation struct {
	ID  uint64
	Key string
}

type openRecord struct {
	id     uint64
	owner  string
	access uint8
	share  uint8
}

type openShard struct {
	mu      sync.Mutex
	records map[string][]openRecord
}

type OpenTable struct {
	next   atomic.Uint64
	shards [shardCount]openShard
}

func (t *OpenTable) Reserve(key, owner string, access, share uint8) (Reservation, error) {
	shard := t.openShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for _, existing := range shard.records[key] {
		if access&^existing.share != 0 || existing.access&^share != 0 {
			return Reservation{}, ErrConflict
		}
	}
	if shard.records == nil {
		shard.records = make(map[string][]openRecord)
	}
	id := t.next.Add(1)
	shard.records[key] = append(shard.records[key], openRecord{id: id, owner: owner, access: access, share: share})
	return Reservation{ID: id, Key: key}, nil
}

func (t *OpenTable) Release(reservation Reservation) {
	shard := t.openShard(reservation.Key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	records := shard.records[reservation.Key]
	for i := range records {
		if records[i].id != reservation.ID {
			continue
		}
		records[i] = records[len(records)-1]
		records = records[:len(records)-1]
		if len(records) == 0 {
			delete(shard.records, reservation.Key)
		} else {
			shard.records[reservation.Key] = records
		}
		return
	}
}

func (t *OpenTable) Conflicts(key string, access uint8) bool {
	shard := t.openShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for _, existing := range shard.records[key] {
		if access&^existing.share != 0 {
			return true
		}
	}
	return false
}

func (t *OpenTable) ReleaseOwner(owner string) {
	for i := range t.shards {
		shard := &t.shards[i]
		shard.mu.Lock()
		for key, records := range shard.records {
			kept := slices.DeleteFunc(records, func(record openRecord) bool { return record.owner == owner })
			if len(kept) == 0 {
				delete(shard.records, key)
			} else {
				shard.records[key] = kept
			}
		}
		shard.mu.Unlock()
	}
}

func (t *OpenTable) openShard(key string) *openShard {
	return &t.shards[shardIndex(key)]
}
