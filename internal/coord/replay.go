package coord

import (
	"bytes"
	"sync"
	"time"
)

type replayEntry struct {
	value   []byte
	expires time.Time
}

type ReplayCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]replayEntry
}

func NewReplayCache(now func() time.Time) *ReplayCache {
	return &ReplayCache{now: now, entries: make(map[string]replayEntry)}
}

func (c *ReplayCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expires.IsZero() && !entry.expires.After(c.now()) {
		delete(c.entries, key)
		return nil, false
	}
	return bytes.Clone(entry.value), true
}

func (c *ReplayCache) Put(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := replayEntry{value: bytes.Clone(value)}
	if ttl > 0 {
		entry.expires = c.now().Add(ttl)
	}
	c.entries[key] = entry
}
