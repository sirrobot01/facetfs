package facetcache

import (
	"io/fs"
	"sync"
	"time"
)

// hashString is FNV-1a inlined over the string so the hot paths hash
// without converting the path to []byte, which would allocate per call.
func hashString(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

// attrCache answers Stat and Lstat from memory. NFS is stat-dominated — one
// READ costs several backend stats before any data moves — so this cache is
// worth more than the content cache against a high-latency backend.
//
// Entries are keyed by (path, lstat) because the two calls differ on
// symlinks. Negative entries remember fs.ErrNotExist, which absorbs the
// LOOKUP storms clients send for absent files. Invalidation at every
// mutation is the coherence mechanism; the TTL is only the backstop.
type attrCache struct {
	ttl time.Duration
	now func() time.Time

	shards [attrShardCount]attrShard
}

type attrShard struct {
	mu sync.RWMutex
	m  map[attrKey]attrEntry
}

type attrKey struct {
	path  string
	lstat bool
}

type attrEntry struct {
	info     fs.FileInfo
	expire   int64 // unix nanoseconds
	negative bool
}

func newAttrCache(ttl time.Duration, now func() time.Time) *attrCache {
	a := &attrCache{ttl: ttl, now: now}
	for i := range a.shards {
		a.shards[i].m = make(map[attrKey]attrEntry)
	}
	return a
}

func (a *attrCache) shard(path string) *attrShard {
	return &a.shards[hashString(path)%attrShardCount]
}

// get returns the cached info for the key. found reports a live entry;
// negative reports that the live entry records fs.ErrNotExist.
func (a *attrCache) get(path string, lstat bool) (info fs.FileInfo, found, negative bool) {
	s := a.shard(path)
	s.mu.RLock()
	e, ok := s.m[attrKey{path, lstat}]
	s.mu.RUnlock()
	if !ok || a.now().UnixNano() >= e.expire {
		return nil, false, false
	}
	return e.info, true, e.negative
}

func (a *attrCache) store(path string, lstat bool, info fs.FileInfo) {
	a.put(path, lstat, attrEntry{info: info, expire: a.now().Add(a.ttl).UnixNano()})
}

func (a *attrCache) storeNegative(path string, lstat bool) {
	a.put(path, lstat, attrEntry{negative: true, expire: a.now().Add(a.ttl).UnixNano()})
}

func (a *attrCache) put(path string, lstat bool, e attrEntry) {
	s := a.shard(path)
	s.mu.Lock()
	if len(s.m) >= maxAttrEntries/attrShardCount {
		s.evictLocked(a.now().UnixNano())
	}
	s.m[attrKey{path, lstat}] = e
	s.mu.Unlock()
}

// evictLocked frees room in a full shard: expired entries go first, then an
// arbitrary entry so an insert always succeeds. Map iteration order is
// random enough that this behaves like random replacement, which is fine for
// a TTL cache that mutation invalidates anyway.
func (s *attrShard) evictLocked(now int64) {
	scanned := 0
	for k, e := range s.m {
		if e.expire <= now {
			delete(s.m, k)
			return
		}
		scanned++
		if scanned >= attrEvictScan {
			break
		}
	}
	for k := range s.m {
		delete(s.m, k)
		return
	}
}

// invalidate drops both the stat and lstat entries for path.
func (a *attrCache) invalidate(path string) {
	s := a.shard(path)
	s.mu.Lock()
	delete(s.m, attrKey{path, false})
	delete(s.m, attrKey{path, true})
	s.mu.Unlock()
}
