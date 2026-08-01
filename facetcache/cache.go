package facetcache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	facetfs "github.com/sirrobot01/facetfs"
)

//go:generate go run mkmatrix.go

const (
	defaultMaxBytes  = 10 << 30 // an unlimited default on a root disk is a foot-gun
	defaultMaxAge    = 24 * time.Hour
	defaultAttrTTL   = time.Second
	defaultChunkSize = 4 << 20
	defaultReadAhead = 16 << 20

	registryShards = 16
	attrShardCount = 16
	maxAttrEntries = 65536
	attrEvictScan  = 32

	// Downloader bounds. rclone leaves both unbounded and regrets it; a
	// pathological random-access pattern must not open arbitrarily many
	// backend sessions.
	maxDownloadersPerItem = 4
	maxDownloadersTotal   = 32

	downloaderIdle = 5 * time.Second
	// chunkGrowthCap bounds adaptive chunk doubling at 16x the base size.
	chunkGrowthCap = 16
	// maxSkipBytes stops a downloader that keeps re-covering cached bytes.
	maxSkipBytes = 1 << 20
	copyBufSize  = 1 << 20
	// probeTailMax caps the probe zone; the zone is also capped at a quarter
	// of the file so small files keep read-ahead.
	probeTailMax    = 64 << 20
	probeChunk      = 1 << 20
	breakerErrors   = 10
	breakerCooldown = 2 * time.Minute
	warmKickEvery   = time.Second

	metaFlushInterval = 2 * time.Second
	itemIdleClose     = time.Minute
	janitorInterval   = time.Minute
	reconcileEvery    = time.Hour
	// punchBackWindow is how far behind an open stream's read head the
	// janitor may punch holes when whole-file eviction cannot reach the
	// budget.
	punchBackWindow = 256 << 20

	readRetries = 3
)

// Cache configures a caching FileSystem wrapper. The zero value of every
// optional field is usable.
type Cache struct {
	// Backend is the FileSystem to cache. Required.
	Backend facetfs.FileSystem

	// Dir is the cache directory. The Cache owns its contents. Required.
	Dir string

	// MaxBytes bounds cached content on disk. Zero means 10 GiB. The bound
	// is soft against open files; Stats reports the overshoot.
	MaxBytes int64

	// MaxAge evicts content not read for this long. Zero means 24h.
	MaxAge time.Duration

	// AttrTTL bounds attribute staleness. Zero means 1s.
	AttrTTL time.Duration

	// ChunkSize is the base network fetch size. Zero means 4 MiB.
	ChunkSize int64

	// ReadAhead is fetched beyond each read. Zero means 16 MiB.
	ReadAhead int64

	// Logger receives background errors. Optional.
	Logger func(error)

	once    sync.Once
	initErr error
	fsys    facetfs.FileSystem
	core    *cfs

	// now is replaced by tests.
	now func() time.Time
}

// Stats reports cache counters. Byte counters are byte-granular: a read
// that is 99% cached counts 99% as hits.
type Stats struct {
	// AttrHits, AttrMisses, and AttrNegatives count attribute lookups.
	AttrHits, AttrMisses, AttrNegatives uint64
	// BytesFromCache counts read bytes served from disk that were already
	// present. BytesFilled counts read bytes that waited for a fetch.
	// BytesFromBackend counts bytes fetched from the backend, including
	// read-ahead.
	BytesFromCache, BytesFilled, BytesFromBackend uint64
	// CachedBytes is the accounted content on disk. Overshoot is how far
	// CachedBytes exceeds MaxBytes; nonzero means open files pin more than
	// the budget. EvictedBytes and PunchedBytes count reclaimed bytes.
	CachedBytes, MaxBytes, Overshoot int64
	EvictedBytes, PunchedBytes       uint64
	// OpenDownloaders is the current number of backend fetch sessions.
	OpenDownloaders int64
}

// FileSystem validates the configuration, loads persisted state, starts the
// background flusher and janitor, and returns the caching wrapper. The
// wrapper implements the same optional facetfs interfaces as Backend.
func (c *Cache) FileSystem() (facetfs.FileSystem, error) {
	c.once.Do(c.init)
	return c.fsys, c.initErr
}

func (c *Cache) init() {
	if c.Backend == nil {
		c.initErr = errors.New("facetcache: Backend is required")
		return
	}
	if c.Dir == "" {
		c.initErr = errors.New("facetcache: Dir is required")
		return
	}
	for _, sub := range []string{"data", "meta"} {
		if err := os.MkdirAll(filepath.Join(c.Dir, sub), 0o700); err != nil {
			c.initErr = err
			return
		}
	}
	f := newCFS(c)
	if err := f.jan.load(); err != nil {
		c.initErr = err
		return
	}
	c.core = f
	c.fsys = wrapFS(f)
	f.wg.Add(2)
	go f.flushLoop()
	go f.jan.run()
}

// Close stops background work, flushes metadata, and closes cached file
// handles. It does not delete cached data. Stop the protocol servers first;
// operations after Close fail.
func (c *Cache) Close() error {
	c.once.Do(c.init)
	if c.initErr != nil || c.core == nil {
		return c.initErr
	}
	return c.core.close()
}

// Stats returns a snapshot of the cache counters.
func (c *Cache) Stats() Stats {
	c.once.Do(c.init)
	f := c.core
	if f == nil {
		return Stats{}
	}
	s := Stats{
		AttrHits:         f.attrHits.Load(),
		AttrMisses:       f.attrMisses.Load(),
		AttrNegatives:    f.attrNegatives.Load(),
		BytesFromCache:   f.bytesFromCache.Load(),
		BytesFilled:      f.bytesFilled.Load(),
		BytesFromBackend: f.bytesFromBackend.Load(),
		CachedBytes:      f.cachedBytes.Load(),
		MaxBytes:         c.maxBytes(),
		EvictedBytes:     f.evictedBytes.Load(),
		PunchedBytes:     f.punchedBytes.Load(),
		OpenDownloaders:  f.dlCount.Load(),
	}
	if s.CachedBytes > s.MaxBytes {
		s.Overshoot = s.CachedBytes - s.MaxBytes
	}
	return s
}

func (c *Cache) maxBytes() int64 {
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return defaultMaxBytes
}

func (c *Cache) maxAge() time.Duration {
	if c.MaxAge > 0 {
		return c.MaxAge
	}
	return defaultMaxAge
}

func (c *Cache) attrTTL() time.Duration {
	if c.AttrTTL > 0 {
		return c.AttrTTL
	}
	return defaultAttrTTL
}

func (c *Cache) chunkSize() int64 {
	if c.ChunkSize > 0 {
		return c.ChunkSize
	}
	return defaultChunkSize
}

func (c *Cache) readAhead() int64 {
	if c.ReadAhead > 0 {
		return c.ReadAhead
	}
	return defaultReadAhead
}

func (c *Cache) timeNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Cache) logf(err error) {
	if c.Logger != nil && err != nil {
		c.Logger(err)
	}
}

// cfs is the wrapper core. It implements the base facetfs.FileSystem;
// generated combination types in matrix_gen.go add the optional interfaces
// the backend supports.
type cfs struct {
	cache   *Cache
	backend facetfs.FileSystem

	// Typed views of the backend's optional interfaces, nil when absent.
	// They are asserted once here so the extension methods never repeat the
	// assertion on hot paths.
	symlink facetfs.SymlinkFS
	link    facetfs.LinkFS
	remove  facetfs.RemoveFS
	setstat facetfs.SetStatFS
	statvfs facetfs.StatVFSFS

	attr   *attrCache
	shards [registryShards]regShard
	jan    *janitor

	// ctx bounds every background operation: downloads, flushes, eviction.
	// File methods have no context of their own, so waits on fills use it.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	attrHits, attrMisses, attrNegatives           atomic.Uint64
	bytesFromCache, bytesFilled, bytesFromBackend atomic.Uint64
	evictedBytes, punchedBytes                    atomic.Uint64
	cachedBytes                                   atomic.Int64
	dlCount                                       atomic.Int64
}

type regShard struct {
	mu sync.Mutex
	m  map[string]*item
}

func newCFS(c *Cache) *cfs {
	f := &cfs{
		cache:   c,
		backend: c.Backend,
		attr:    newAttrCache(c.attrTTL(), c.timeNow),
	}
	f.symlink, _ = c.Backend.(facetfs.SymlinkFS)
	f.link, _ = c.Backend.(facetfs.LinkFS)
	f.remove, _ = c.Backend.(facetfs.RemoveFS)
	f.setstat, _ = c.Backend.(facetfs.SetStatFS)
	f.statvfs, _ = c.Backend.(facetfs.StatVFSFS)
	for i := range f.shards {
		f.shards[i].m = make(map[string]*item)
	}
	f.jan = newJanitor(f)
	f.ctx, f.cancel = context.WithCancel(context.Background())
	return f
}

func (f *cfs) close() error {
	f.cancel()
	f.wg.Wait()
	var firstErr error
	for i := range f.shards {
		s := &f.shards[i]
		s.mu.Lock()
		items := make([]*item, 0, len(s.m))
		for _, it := range s.m {
			items = append(items, it)
		}
		clear(s.m)
		s.mu.Unlock()
		for _, it := range items {
			if err := it.shutdown(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// flushLoop persists dirty item metadata. One loop serves every item: the
// debounce lives in the cadence, so no item flushes more than once per
// interval and none needs its own goroutine.
func (f *cfs) flushLoop() {
	defer f.wg.Done()
	t := time.NewTicker(metaFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-t.C:
			f.flushAll()
		}
	}
}

func (f *cfs) flushAll() {
	for i := range f.shards {
		s := &f.shards[i]
		s.mu.Lock()
		items := make([]*item, 0, len(s.m))
		for _, it := range s.m {
			items = append(items, it)
		}
		s.mu.Unlock()
		for _, it := range items {
			if err := it.flushMeta(); err != nil {
				f.cache.logf(err)
			}
		}
	}
}
