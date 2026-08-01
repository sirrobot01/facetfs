package facetcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// item is one cached file. Identity is the backend path, which matches the
// servers exactly: NFS filehandles are sealed paths, so a rename both
// invalidates client handles and drops the cache entry.
type item struct {
	f    *cfs
	name string // cleaned backend path, "/"-rooted

	// opens and idleSince are guarded by the registry shard mutex. An item
	// with opens > 0 is pinned: the janitor never evicts or closes it.
	opens     int
	idleSince time.Time

	mu     sync.RWMutex
	loaded bool
	fd     *os.File
	rs     rangeSet
	size   int64
	fpr    string
	// doomed marks an item whose on-disk files were invalidated (rename,
	// remove). Open handles keep reading through the open fd; nothing is
	// persisted any more.
	doomed bool

	// dirty means the metadata file lags memory. needSync means the data
	// file holds ranges no fdatasync has covered yet; metadata must never
	// claim bytes the disk does not hold, so a flush syncs data first.
	// Both are atomic so the warm read path can mark atime movement
	// without taking the item lock.
	dirty    atomic.Bool
	needSync atomic.Bool

	atime    atomic.Int64 // unix nanoseconds, LRU order
	readHead atomic.Int64 // furthest byte returned to a reader
	lastKick atomic.Int64 // rate limit for warm read-ahead kicks

	dls atomic.Pointer[dlGroup]
}

// metaJSON is the persisted per-item state. Ranges are [pos, size] pairs.
type metaJSON struct {
	Size        int64      `json:"size"`
	ATime       int64      `json:"atime"`
	Fingerprint string     `json:"fingerprint"`
	Ranges      [][2]int64 `json:"ranges"`
}

// fingerprint derives content identity from backend attributes. A backend
// object replaced behind the same name changes size or mtime, and a cold
// open then discards every cached range instead of serving stale bytes.
func fingerprint(info fs.FileInfo) string {
	return strconv.FormatInt(info.Size(), 10) + "," + strconv.FormatInt(info.ModTime().UnixNano(), 10)
}

// cachePaths maps a backend name to the data and metadata files. The two
// parallel trees keep metadata from ever colliding with a data file name,
// and component validation keeps every created file inside them, where the
// janitor can always find it.
func (f *cfs) cachePaths(name string) (data, meta string, err error) {
	rel := strings.TrimPrefix(name, "/")
	if rel == "" {
		return "", "", fmt.Errorf("facetcache: cannot cache %q: %w", name, fs.ErrInvalid)
	}
	for part := range strings.SplitSeq(rel, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, '\\') {
			return "", "", fmt.Errorf("facetcache: unsafe path %q: %w", name, fs.ErrInvalid)
		}
	}
	osRel := filepath.FromSlash(rel)
	return filepath.Join(f.cache.Dir, "data", osRel),
		filepath.Join(f.cache.Dir, "meta", osRel+".json"),
		nil
}

func (f *cfs) shard(name string) *regShard {
	return &f.shards[hashString(name)%registryShards]
}

// openItem returns the pinned item for name, creating it on first use. st is
// the backend stat the caller already holds; a cold item validates its
// fingerprint against it. The warm path is a map hit and a counter: no
// backend call, no disk I/O.
func (f *cfs) openItem(name string, st fs.FileInfo) (*item, error) {
	s := f.shard(name)
	s.mu.Lock()
	it := s.m[name]
	if it == nil {
		it = &item{f: f, name: name}
		s.m[name] = it
	}
	it.opens++
	s.mu.Unlock()
	if err := it.ensureLoaded(st); err != nil {
		f.releaseItem(it)
		return nil, err
	}
	return it, nil
}

// lookupItem returns the pinned item for name only if it is already live.
// The write path uses it to mirror into an existing cached copy without
// populating the cache for write-only traffic.
func (f *cfs) lookupItem(name string) *item {
	s := f.shard(name)
	s.mu.Lock()
	it := s.m[name]
	if it != nil {
		it.opens++
	}
	s.mu.Unlock()
	if it != nil && !it.isLive() {
		f.releaseItem(it)
		return nil
	}
	return it
}

func (f *cfs) releaseItem(it *item) {
	s := f.shard(it.name)
	s.mu.Lock()
	it.opens--
	last := it.opens == 0
	if last {
		it.idleSince = f.cache.timeNow()
	}
	doomed := it.isDoomed()
	s.mu.Unlock()
	if last && doomed {
		// A doomed item never re-enters the registry; the last handle out
		// closes the fd.
		if err := it.shutdown(); err != nil {
			f.cache.logf(err)
		}
	}
}

func (it *item) isLive() bool {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.loaded && !it.doomed
}

func (it *item) isDoomed() bool {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.doomed
}

// ensureLoaded opens the sparse data file, loads persisted metadata, and
// validates the fingerprint. It runs outside the registry shard lock so a
// slow disk never blocks unrelated opens.
func (it *item) ensureLoaded(st fs.FileInfo) error {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.doomed {
		return fmt.Errorf("facetcache: %s: item invalidated: %w", it.name, fs.ErrInvalid)
	}
	if it.loaded {
		return nil
	}
	dataPath, metaPath, err := it.f.cachePaths(it.name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o700); err != nil {
		return err
	}
	fd, err := os.OpenFile(dataPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	it.fd = fd
	it.size = st.Size()
	it.fpr = fingerprint(st)
	it.atime.Store(it.f.cache.timeNow().UnixNano())

	if meta, err := loadMeta(metaPath); err == nil {
		if meta.Fingerprint == it.fpr {
			for _, p := range meta.Ranges {
				it.rs.insert(rng{p[0], p[1]})
			}
			it.rs.remove(rng{it.size, 1<<62 - it.size})
			if meta.ATime > 0 {
				it.atime.Store(meta.ATime)
			}
		} else {
			// Content changed behind the same name; the persisted ranges
			// describe bytes that no longer exist. Flush promptly so a
			// crash cannot resurrect them.
			it.dirty.Store(true)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		os.Remove(metaPath)
		it.dirty.Store(true)
		it.f.cache.logf(fmt.Errorf("facetcache: %s: discarding metadata: %w", it.name, err))
	} else {
		it.dirty.Store(true)
	}
	// Pre-truncate so every pwrite inside [0, size) is valid, and so a
	// shrunk backend object cannot leave stale bytes past EOF.
	if err := fd.Truncate(it.size); err != nil {
		fd.Close()
		it.fd = nil
		return err
	}
	// Take the accounting over from the closed-file index without double
	// counting; adopt any difference between the index and what loaded.
	previously := it.f.jan.forget(it.name)
	it.f.cachedBytes.Add(it.rs.size() - previously)
	it.loaded = true
	return nil
}

func loadMeta(path string) (*metaJSON, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m metaJSON
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for _, p := range m.Ranges {
		if p[0] < 0 || p[1] <= 0 {
			return nil, fmt.Errorf("facetcache: invalid range in %s", path)
		}
	}
	return &m, nil
}

// flushMeta persists item state when it is dirty. The order is load-bearing:
// snapshot under the lock, fdatasync the data file when the snapshot claims
// ranges no sync has covered, then write and rename the metadata. Metadata
// must never claim bytes the disk does not hold, or a crash turns holes into
// silently served zeros.
func (it *item) flushMeta() error {
	if !it.dirty.Load() {
		return nil
	}
	it.mu.Lock()
	if it.doomed || !it.loaded {
		it.mu.Unlock()
		return nil
	}
	snap := metaJSON{
		Size:        it.size,
		ATime:       it.atime.Load(),
		Fingerprint: it.fpr,
	}
	for _, r := range it.rs {
		snap.Ranges = append(snap.Ranges, [2]int64{r.pos, r.size})
	}
	fd := it.fd
	needSync := it.needSync.Swap(false)
	it.dirty.Store(false)
	it.mu.Unlock()

	fail := func(err error) error {
		it.dirty.Store(true)
		if needSync {
			it.needSync.Store(true)
		}
		return fmt.Errorf("facetcache: %s: metadata flush: %w", it.name, err)
	}
	if needSync {
		if err := fd.Sync(); err != nil {
			return fail(err)
		}
	}
	_, metaPath, err := it.f.cachePaths(it.name)
	if err != nil {
		return fail(err)
	}
	b, err := json.Marshal(&snap)
	if err != nil {
		return fail(err)
	}
	tmp := metaPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, metaPath); err != nil {
		os.Remove(tmp)
		return fail(err)
	}
	return nil
}

// readAt serves p from the cache, filling missing ranges from the backend
// first. The warm path is: presence check under the read lock, pread with no
// lock held, post-read re-validation (the janitor may punch holes under open
// streams), and zero heap allocations.
func (it *item) readAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	it.mu.RLock()
	size := it.size
	it.mu.RUnlock()
	if off >= size {
		return 0, io.EOF
	}
	n := int64(len(p))
	if off+n > size {
		n = size - off
	}
	r := rng{off, n}
	warm := true
	for try := 0; ; try++ {
		if !it.hasRange(r) {
			warm = false
			if err := it.group().download(it.f.ctx, r); err != nil {
				return 0, err
			}
		}
		if _, err := it.fd.ReadAt(p[:n], off); err != nil {
			return 0, err
		}
		// A concurrent hole punch between the presence check and the pread
		// serves zeros; presence is validated after the read, not trusted
		// before it.
		if it.hasRange(r) {
			break
		}
		if try >= readRetries {
			return 0, fmt.Errorf("facetcache: %s: range evicted during read", it.name)
		}
	}
	it.touch(off + n)
	if warm {
		it.f.bytesFromCache.Add(uint64(n))
		it.warmKick(r, size)
	} else {
		it.f.bytesFilled.Add(uint64(n))
	}
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func (it *item) touch(head int64) {
	it.atime.Store(it.f.cache.timeNow().UnixNano())
	for {
		old := it.readHead.Load()
		if head <= old || it.readHead.CompareAndSwap(old, head) {
			break
		}
	}
	// Atime moved; persist lazily through the flusher. Losing this store to
	// a racing flush snapshot only delays the atime by one interval.
	it.dirty.Store(true)
}

// warmKick extends the fill frontier while reads are still hitting cache, so
// a sequential stream never stalls at the edge of the cached region. It is
// rate-limited and costs one atomic load when gated.
func (it *item) warmKick(r rng, size int64) {
	now := it.f.cache.timeNow().UnixNano()
	last := it.lastKick.Load()
	if now-last < int64(warmKickEvery) || !it.lastKick.CompareAndSwap(last, now) {
		return
	}
	ahead := rng{r.end(), min(it.f.cache.readAhead(), size-r.end())}
	if ahead.size <= 0 || it.hasRange(ahead) || it.isProbe(r, size) {
		return
	}
	it.group().ensureAsync(ahead)
}

// isProbe reports a latency-sensitive read near the end of the file, the
// shape ffprobe produces reading an MP4 moov atom. The zone is proportional
// so small files keep read-ahead; a flat zone would classify every read of
// every sub-64 MiB file as a probe.
func (it *item) isProbe(r rng, size int64) bool {
	zone := min(int64(probeTailMax), size/4)
	return r.end() >= size-zone
}

func (it *item) group() *dlGroup {
	if g := it.dls.Load(); g != nil {
		return g
	}
	g := newDLGroup(it)
	if it.dls.CompareAndSwap(nil, g) {
		return g
	}
	return it.dls.Load()
}

// writeNoOverwrite stores fetched bytes, skipping ranges that are already
// present, and returns how many bytes were skipped. Cache-file writes are
// serialized under the item lock: an unlocked pwrite could interleave with a
// mirror write of newer backend-acknowledged bytes and clobber them.
func (it *item) writeNoOverwrite(p []byte, off int64) (skipped int64, err error) {
	r := rng{off, int64(len(p))}
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.doomed || !it.loaded {
		return 0, fmt.Errorf("facetcache: %s: item invalidated: %w", it.name, fs.ErrInvalid)
	}
	if r.end() > it.size {
		r.size = it.size - r.pos
		if r.size <= 0 {
			return int64(len(p)), nil
		}
	}
	var scratch [8]rng
	for _, m := range it.rs.missingWithin(r, scratch[:0]) {
		if _, err := it.fd.WriteAt(p[m.pos-off:m.end()-off], m.pos); err != nil {
			if isNoSpace(err) {
				it.f.jan.kickNow()
			}
			return 0, err
		}
	}
	before := it.rs.size()
	it.rs.insert(r)
	written := it.rs.size() - before
	it.f.cachedBytes.Add(written)
	if written > 0 {
		it.dirty.Store(true)
		it.needSync.Store(true)
	}
	return r.size - written, nil
}

// mirrorWrite stores backend-acknowledged bytes from the write-through
// path. Unlike fills it overwrites, because the backend content is newer by
// definition.
func (it *item) mirrorWrite(p []byte, off int64) {
	if len(p) == 0 || off < 0 {
		return
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.doomed || !it.loaded {
		return
	}
	before := it.rs.size()
	if _, err := it.fd.WriteAt(p, off); err != nil {
		// Mirroring is best-effort; on failure the range becomes absent so
		// the next read refetches from the backend.
		it.rs.remove(rng{off, int64(len(p))})
		it.f.cachedBytes.Add(it.rs.size() - before)
		it.f.cache.logf(fmt.Errorf("facetcache: %s: mirror write: %w", it.name, err))
		return
	}
	if end := off + int64(len(p)); end > it.size {
		it.size = end
	}
	it.rs.insert(rng{off, int64(len(p))})
	it.f.cachedBytes.Add(it.rs.size() - before)
	it.dirty.Store(true)
	it.needSync.Store(true)
}

// truncate resizes the cached copy after the backend acknowledged the same
// truncate.
func (it *item) truncate(size int64) {
	if size < 0 {
		return
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.doomed || !it.loaded {
		return
	}
	if err := it.fd.Truncate(size); err != nil {
		it.f.cache.logf(fmt.Errorf("facetcache: %s: truncate: %w", it.name, err))
		it.doomLocked()
		return
	}
	before := it.rs.size()
	it.rs.remove(rng{size, 1<<62 - size})
	if size > it.size {
		// The extended region is all zeros on the backend and in the sparse
		// file alike, so it is present by construction.
		it.rs.insert(rng{it.size, size - it.size})
	}
	it.f.cachedBytes.Add(it.rs.size() - before)
	it.size = size
	// The fingerprint changes with the backend mtime; a cold open would
	// discard everything. Adopting the resize here keeps the warm state
	// valid, and the next Stat refreshes the fingerprint lazily.
	it.dirty.Store(true)
	it.needSync.Store(true)
}

// doomLocked detaches the item from disk: no more flushes, no more
// accounting, open readers keep their fd. Callers hold it.mu.
func (it *item) doomLocked() {
	if it.doomed {
		return
	}
	it.doomed = true
	if it.loaded {
		it.f.cachedBytes.Add(-it.rs.size())
	}
	if g := it.dls.Swap(nil); g != nil {
		// Stop takes the group lock only; it.mu is safe to hold here
		// because group code never calls into the item with its own lock
		// held while waiting on it.mu writers.
		go g.stop()
	}
}

// shutdown flushes and closes an item that has left the registry. For a
// healthy item the on-disk files stay and the janitor's index takes the
// accounting over; for a doomed item only the fd is left to release.
func (it *item) shutdown() error {
	err := it.flushMeta()
	it.mu.Lock()
	if g := it.dls.Swap(nil); g != nil {
		go g.stop()
	}
	if it.loaded && !it.doomed {
		it.f.jan.remember(it.name, it.atime.Load(), it.rs.size())
	}
	if it.fd != nil {
		if cerr := it.fd.Close(); cerr != nil && err == nil {
			err = cerr
		}
		it.fd = nil
	}
	it.loaded = false
	it.doomed = true
	it.mu.Unlock()
	return err
}

func isNoSpace(err error) bool {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return strings.Contains(pe.Err.Error(), "no space")
	}
	return false
}
