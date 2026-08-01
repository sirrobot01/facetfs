package facetcache

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// janitor owns the disk budget. It is the only reclaimer: goBlack runs a
// file-granular janitor and a byte-granular pool that share a budget but
// never talk, and they fight; facetcache has one owner.
//
// Accounting is live: cfs.cachedBytes moves on every range insert, removal,
// and unlink, seeded by one startup walk. The janitor never rescans the tree
// per tick; a slow reconciliation walk corrects drift once an hour.
//
// The index maps closed on-disk items (path -> atime, bytes). Live items are
// tracked by the registry and are pinned while open. Lock order everywhere:
// registry shard -> item.mu -> janitor.mu.
type janitor struct {
	f    *cfs
	kick chan struct{}

	mu    sync.Mutex
	index map[string]dEntry
}

type dEntry struct {
	atime int64
	bytes int64
}

func newJanitor(f *cfs) *janitor {
	return &janitor{f: f, kick: make(chan struct{}, 1), index: make(map[string]dEntry)}
}

// forget removes name from the closed-file index and returns the bytes that
// entry accounted, so a loading item can take the accounting over without
// double counting.
func (j *janitor) forget(name string) int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.index[name]
	if !ok {
		return 0
	}
	delete(j.index, name)
	return e.bytes
}

// remember records a closed on-disk item. The caller keeps cachedBytes
// unchanged: the bytes merely moved from a live item to the index.
func (j *janitor) remember(name string, atime, bytes int64) {
	j.mu.Lock()
	j.index[name] = dEntry{atime: atime, bytes: bytes}
	j.mu.Unlock()
}

// kickNow asks for an immediate pass; the fill path calls it on ENOSPC.
func (j *janitor) kickNow() {
	select {
	case j.kick <- struct{}{}:
	default:
	}
}

func (j *janitor) run() {
	defer j.f.wg.Done()
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	lastReconcile := j.f.cache.timeNow()
	for {
		select {
		case <-j.f.ctx.Done():
			return
		case <-t.C:
		case <-j.kick:
		}
		j.pass()
		if j.f.cache.timeNow().Sub(lastReconcile) >= reconcileEvery {
			lastReconcile = j.f.cache.timeNow()
			j.reconcile()
		}
	}
}

func (j *janitor) pass() {
	now := j.f.cache.timeNow()
	j.closeIdle(now)
	j.evictExpired(now)
	j.evictOverBudget()
	j.punchBehind()
}

// closeIdle flushes and closes items nobody has opened for a while. The
// whole transition runs under the shard lock so a concurrent open can never
// race the handoff from registry to index.
func (j *janitor) closeIdle(now time.Time) {
	for i := range j.f.shards {
		s := &j.f.shards[i]
		s.mu.Lock()
		for name, it := range s.m {
			if it.opens != 0 || it.idleSince.IsZero() || now.Sub(it.idleSince) < itemIdleClose {
				continue
			}
			delete(s.m, name)
			if err := it.shutdown(); err != nil {
				j.f.cache.logf(err)
			}
		}
		s.mu.Unlock()
	}
}

// evictExpired deletes closed items whose atime exceeds MaxAge.
func (j *janitor) evictExpired(now time.Time) {
	cutoff := now.Add(-j.f.cache.maxAge()).UnixNano()
	for _, c := range j.candidates() {
		if c.atime < cutoff {
			j.deleteEntry(c.name)
		}
	}
}

// evictOverBudget deletes closed items oldest-first until the accounted
// bytes fit MaxBytes. Open items are pinned, so the budget is soft against
// them; punchBehind is the remaining lever.
func (j *janitor) evictOverBudget() {
	limit := j.f.cache.maxBytes()
	if j.f.cachedBytes.Load() <= limit {
		return
	}
	cands := j.candidates()
	sort.Slice(cands, func(a, b int) bool { return cands[a].atime < cands[b].atime })
	for _, c := range cands {
		if j.f.cachedBytes.Load() <= limit {
			return
		}
		j.deleteEntry(c.name)
	}
}

type candidate struct {
	name  string
	atime int64
}

func (j *janitor) candidates() []candidate {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]candidate, 0, len(j.index))
	for name, e := range j.index {
		out = append(out, candidate{name, e.atime})
	}
	return out
}

// deleteEntry unlinks a closed item's files. It holds the shard lock across
// the unlink so a concurrent open of the same name cannot interleave and
// lose its fresh files.
func (j *janitor) deleteEntry(name string) {
	s := j.f.shard(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, live := s.m[name]; live {
		// The item came back to life since the snapshot; its accounting
		// moved with it via forget.
		return
	}
	j.mu.Lock()
	e, ok := j.index[name]
	delete(j.index, name)
	j.mu.Unlock()
	if !ok {
		return
	}
	dataPath, metaPath, err := j.f.cachePaths(name)
	if err != nil {
		return
	}
	os.Remove(dataPath)
	os.Remove(metaPath)
	removeEmptyParents(j.f.cache.Dir, dataPath)
	removeEmptyParents(j.f.cache.Dir, metaPath)
	j.f.cachedBytes.Add(-e.bytes)
	j.f.evictedBytes.Add(uint64(e.bytes))
}

// punchBehind reclaims space inside open streams when whole-file eviction
// cannot reach the budget: ranges far behind each open item's read head are
// punched out. Reads re-validate presence after every pread, so a racing
// reader retries through the fill path instead of seeing zeros. No-op where
// the platform cannot punch holes.
func (j *janitor) punchBehind() {
	if !punchSupported || j.f.cachedBytes.Load() <= j.f.cache.maxBytes() {
		return
	}
	for i := range j.f.shards {
		s := &j.f.shards[i]
		s.mu.Lock()
		items := make([]*item, 0, len(s.m))
		for _, it := range s.m {
			items = append(items, it)
		}
		s.mu.Unlock()
		for _, it := range items {
			if j.f.cachedBytes.Load() <= j.f.cache.maxBytes() {
				return
			}
			j.punchItem(it)
		}
	}
}

func (j *janitor) punchItem(it *item) {
	cut := it.readHead.Load() - punchBackWindow
	if cut <= 0 {
		return
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	if !it.loaded || it.doomed {
		return
	}
	var punch []rng
	for _, r := range it.rs {
		if r.end() <= cut {
			punch = append(punch, r)
		} else if r.pos < cut {
			punch = append(punch, rng{r.pos, cut - r.pos})
		}
	}
	punched := false
	for _, r := range punch {
		// Align inward where the platform requires block-aligned punches.
		// Shrinking is the safe direction: sub-block edges stay cached
		// rather than being deallocated while still claimed.
		r = alignPunch(r)
		if r.size <= 0 {
			continue
		}
		if err := punchHole(it.fd, r.pos, r.size); err != nil {
			j.f.cache.logf(fmt.Errorf("facetcache: %s: punch: %w", it.name, err))
			return
		}
		// Remove before anything can read through: metadata claiming less
		// than the disk holds is safe, the reverse is not.
		it.rs.remove(r)
		it.f.cachedBytes.Add(-r.size)
		it.f.punchedBytes.Add(uint64(r.size))
		punched = true
	}
	if punched {
		it.dirty.Store(true)
	}
}

// alignPunch shrinks r to punchAlign boundaries. On platforms with
// punchAlign == 1 the compiler removes the arithmetic.
func alignPunch(r rng) rng {
	if punchAlign == 1 {
		return r
	}
	pos := (r.pos + punchAlign - 1) / punchAlign * punchAlign
	end := r.end() / punchAlign * punchAlign
	return rng{pos, end - pos}
}

// load seeds the index and the byte accounting from the metadata tree, and
// removes orphans on either side. It runs once, before the wrapper serves.
func (j *janitor) load() error {
	metaRoot := filepath.Join(j.f.cache.Dir, "meta")
	dataRoot := filepath.Join(j.f.cache.Dir, "data")
	var total int64
	err := filepath.WalkDir(metaRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, ".json.tmp") {
			return os.Remove(p) // interrupted flush; the rename never happened
		}
		if !strings.HasSuffix(p, ".json") {
			return nil
		}
		rel, err := filepath.Rel(metaRoot, strings.TrimSuffix(p, ".json"))
		if err != nil {
			return err
		}
		name := "/" + filepath.ToSlash(rel)
		dataPath := filepath.Join(dataRoot, rel)
		meta, merr := loadMeta(p)
		if _, serr := os.Stat(dataPath); serr != nil || merr != nil {
			// Orphan metadata or corrupt metadata: drop the pair.
			os.Remove(p)
			os.Remove(dataPath)
			return nil
		}
		var bytes int64
		for _, r := range meta.Ranges {
			bytes += r[1]
		}
		j.index[name] = dEntry{atime: meta.ATime, bytes: bytes}
		total += bytes
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Orphan data files have no metadata claiming them; delete so they do
	// not occupy space outside the accounting.
	err = filepath.WalkDir(dataRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dataRoot, p)
		if err != nil {
			return err
		}
		if _, ok := j.index["/"+filepath.ToSlash(rel)]; !ok {
			os.Remove(p)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	j.f.cachedBytes.Store(total)
	return nil
}

// reconcile re-walks the tree and adopts the real totals, logging drift.
// Live accounting should already be exact; this is the audit.
func (j *janitor) reconcile() {
	metaRoot := filepath.Join(j.f.cache.Dir, "meta")
	var indexTotal int64
	j.mu.Lock()
	for name := range j.index {
		e := j.index[name]
		if m, err := loadMeta(filepath.Join(metaRoot, filepath.FromSlash(strings.TrimPrefix(name, "/"))+".json")); err == nil {
			var bytes int64
			for _, r := range m.Ranges {
				bytes += r[1]
			}
			if bytes != e.bytes {
				j.index[name] = dEntry{atime: e.atime, bytes: bytes}
			}
			indexTotal += bytes
		}
	}
	j.mu.Unlock()
	var liveTotal int64
	for i := range j.f.shards {
		s := &j.f.shards[i]
		s.mu.Lock()
		for _, it := range s.m {
			it.mu.RLock()
			if it.loaded && !it.doomed {
				liveTotal += it.rs.size()
			}
			it.mu.RUnlock()
		}
		s.mu.Unlock()
	}
	total := indexTotal + liveTotal
	if old := j.f.cachedBytes.Swap(total); old != total {
		j.f.cache.logf(fmt.Errorf("facetcache: accounting drift: tracked %d bytes, found %d", old, total))
	}
}

// removeEmptyParents prunes empty directories up to, but excluding, root.
func removeEmptyParents(root, p string) {
	for dir := filepath.Dir(p); strings.HasPrefix(dir, root) && dir != root; dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			return // not empty or gone; either way stop
		}
	}
}
