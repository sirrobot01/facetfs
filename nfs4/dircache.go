package nfs4

import (
	"io/fs"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// dirCache holds the directory listings that clients are paging through.
//
// READDIR cookies are entry indexes, so resuming a listing means finding the
// entry a cookie names. Without a snapshot the server has to read the whole
// directory again for every page, which costs a full read per page and makes
// listing a large directory quadratic. A snapshot also gives one listing a
// stable view, which index cookies cannot otherwise promise.
//
// The cache is bounded by total entries and by age. Dropping a snapshot only
// costs the re-read it was avoiding.
type dirCache struct {
	now func() time.Time
	ttl time.Duration
	max int
	seq atomic.Uint64

	mu    sync.Mutex
	total int
	held  map[dirKey]*dirSnapshot
	order []dirKey // insertion order, oldest first
}

type dirKey struct {
	path string
	verf uint64
}

type dirSnapshot struct {
	entries []fs.FileInfo
	at      time.Time
}

func newDirCache(now func() time.Time, ttl time.Duration, max int) *dirCache {
	return &dirCache{now: now, ttl: ttl, max: max, held: map[dirKey]*dirSnapshot{}}
}

// mint returns the verifier for a listing that is starting.
func (c *dirCache) mint() uint64 {
	return c.seq.Add(1)
}

// lookup returns the snapshot a resumed listing named, if it is still held.
func (c *dirCache) lookup(path string, verf uint64) ([]fs.FileInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	held, ok := c.held[dirKey{path, verf}]
	if !ok || c.now().Sub(held.at) > c.ttl {
		return nil, false
	}
	return held.entries, true
}

// put stores a listing, dropping stale and then oldest snapshots to stay
// within the entry bound. A listing too large to bound is not stored.
func (c *dirCache) put(path string, verf uint64, entries []fs.FileInfo) {
	if len(entries) > c.max {
		return
	}
	key := dirKey{path, verf}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	c.dropLocked(key)
	for _, older := range slices.Clone(c.order) {
		if held, ok := c.held[older]; ok && now.Sub(held.at) > c.ttl {
			c.dropLocked(older)
		}
	}
	// Evict before recording the new key so it cannot evict itself.
	for c.total+len(entries) > c.max && len(c.order) > 0 {
		c.dropLocked(c.order[0])
	}
	c.held[key] = &dirSnapshot{entries: entries, at: now}
	c.order = append(c.order, key)
	c.total += len(entries)
}

// dropLocked removes a snapshot and its place in the eviction order.
func (c *dirCache) dropLocked(key dirKey) {
	held, ok := c.held[key]
	if !ok {
		return
	}
	c.total -= len(held.entries)
	delete(c.held, key)
	for i, held := range c.order {
		if held == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}
