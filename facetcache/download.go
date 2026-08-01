package facetcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	facetfs "github.com/sirrobot01/facetfs"
)

var errCacheClosed = errors.New("facetcache: cache closed")

// dlGroup coordinates fetches for one item. Readers that miss park as
// waiters; downloaders stream ranges from the backend and wake them as the
// bytes land. N concurrent readers of one region cost one fetch.
//
// Lock order: dlGroup.mu -> downloader.mu, and dlGroup.mu -> item.mu. The
// group may take the item range lock; item code never calls into the group
// with item.mu held.
type dlGroup struct {
	it *item

	mu           sync.Mutex
	dls          []*downloader
	waiters      []*waiter
	errCount     int
	lastErr      error
	breakerUntil time.Time
	stopped      bool
	kickerOn     bool
}

type waiter struct {
	r  rng
	ch chan error
}

func newDLGroup(it *item) *dlGroup { return &dlGroup{it: it} }

// download blocks until [r] is present, filling it (plus read-ahead) from
// the backend. The caller already observed the range missing; the breaker is
// checked here, after that presence check, so a fully cached range stays
// readable through a backend outage.
func (g *dlGroup) download(ctx context.Context, r rng) error {
	it := g.it
	it.mu.RLock()
	size := it.size
	it.mu.RUnlock()
	probe := it.isProbe(r, size)
	target := r.end()
	if !probe {
		target = min(target+it.f.cache.readAhead(), size)
	}

	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return errCacheClosed
	}
	if until := g.breakerUntil; g.it.f.cache.timeNow().Before(until) {
		err := g.lastErr
		g.mu.Unlock()
		return fmt.Errorf("facetcache: %s: backend suspended after repeated errors: %w", it.name, err)
	}
	g.ensureLocked(r.pos, target, probe)
	w := &waiter{r: r, ch: make(chan error, 1)}
	g.waiters = append(g.waiters, w)
	if !g.kickerOn {
		g.kickerOn = true
		go g.kicker()
	}
	g.mu.Unlock()

	select {
	case err := <-w.ch:
		return err
	case <-ctx.Done():
		g.dropWaiter(w)
		return ctx.Err()
	}
}

// ensureAsync extends the fill frontier without waiting; the warm-read
// kick uses it so sequential streams never stall at the cache edge.
func (g *dlGroup) ensureAsync(r rng) {
	g.mu.Lock()
	if !g.stopped && !g.it.f.cache.timeNow().Before(g.breakerUntil) {
		g.ensureLocked(r.pos, r.end(), false)
	}
	g.mu.Unlock()
}

// ensureLocked reuses a downloader whose frontier is near pos, or spawns a
// new one within the per-item and global bounds. When both bounds are hit
// the waiter simply parks; a downloader exit or the kicker retries.
func (g *dlGroup) ensureLocked(pos, target int64, probe bool) {
	live := g.dls[:0]
	for _, dl := range g.dls {
		if !dl.done() {
			live = append(live, dl)
		}
	}
	g.dls = live
	window := max(int64(4<<20), g.it.f.cache.chunkSize()/2)
	for _, dl := range g.dls {
		if start, off := dl.span(); pos >= start && pos < off+window {
			dl.extend(target)
			return
		}
	}
	if len(g.dls) >= maxDownloadersPerItem || g.it.f.dlCount.Load() >= maxDownloadersTotal {
		return
	}
	chunk := g.it.f.cache.chunkSize()
	if probe {
		chunk = probeChunk
	}
	dl := &downloader{
		g:      g,
		probe:  probe,
		start:  pos,
		offset: pos,
		target: target,
		chunk:  chunk,
		kick:   make(chan struct{}, 1),
	}
	g.dls = append(g.dls, dl)
	g.it.f.dlCount.Add(1)
	go dl.run()
}

// kickWaiters wakes every waiter whose range is now present. Waiter counts
// are small (parked readers of one file), so a scan under the lock per
// megabyte of fill is cheap.
func (g *dlGroup) kickWaiters() {
	g.mu.Lock()
	g.kickWaitersLocked()
	g.mu.Unlock()
}

func (g *dlGroup) kickWaitersLocked() {
	rest := g.waiters[:0]
	for _, w := range g.waiters {
		if g.it.hasRange(w.r) {
			w.ch <- nil
		} else {
			rest = append(rest, w)
		}
	}
	g.waiters = rest
}

func (g *dlGroup) failWaitersLocked(err error) {
	for _, w := range g.waiters {
		w.ch <- err
	}
	g.waiters = nil
}

func (g *dlGroup) dropWaiter(w *waiter) {
	g.mu.Lock()
	for i, o := range g.waiters {
		if o == w {
			g.waiters = append(g.waiters[:i], g.waiters[i+1:]...)
			break
		}
	}
	g.mu.Unlock()
}

// kicker is the fallback dispatcher: it re-checks parked waiters once per
// second and re-ensures a downloader for each, covering downloader death and
// the benign race where another fill satisfied a waiter between checks. It
// runs only while waiters exist.
func (g *dlGroup) kicker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-g.it.f.ctx.Done():
			g.mu.Lock()
			g.failWaitersLocked(errCacheClosed)
			g.kickerOn = false
			g.mu.Unlock()
			return
		case <-t.C:
			g.mu.Lock()
			g.kickWaitersLocked()
			if len(g.waiters) == 0 {
				g.kickerOn = false
				g.mu.Unlock()
				return
			}
			if !g.stopped && !g.it.f.cache.timeNow().Before(g.breakerUntil) {
				for _, w := range g.waiters {
					g.ensureLocked(w.r.pos, w.r.end(), g.it.isProbeNow(w.r))
				}
			}
			g.mu.Unlock()
		}
	}
}

// recordError counts consecutive failures. Ten in a row open the breaker
// for two minutes and fail the parked waiters; cached ranges stay readable
// because the breaker is only consulted after a presence miss.
func (g *dlGroup) recordError(err error) (fatal bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.errCount++
	g.lastErr = err
	if g.errCount >= breakerErrors {
		g.breakerUntil = g.it.f.cache.timeNow().Add(breakerCooldown)
		g.errCount = 0
		g.failWaitersLocked(fmt.Errorf("facetcache: %s: backend suspended after repeated errors: %w", g.it.name, err))
		return true
	}
	return false
}

func (g *dlGroup) recordSuccess() {
	g.mu.Lock()
	g.errCount = 0
	g.mu.Unlock()
}

// onExit reaps a finished downloader and hands its remaining work to a
// replacement when waiters are still parked.
func (g *dlGroup) onExit(dl *downloader) {
	g.mu.Lock()
	for i, o := range g.dls {
		if o == dl {
			g.dls = append(g.dls[:i], g.dls[i+1:]...)
			break
		}
	}
	g.kickWaitersLocked()
	if !g.stopped && len(g.waiters) > 0 && !g.it.f.cache.timeNow().Before(g.breakerUntil) {
		for _, w := range g.waiters {
			g.ensureLocked(w.r.pos, w.r.end(), g.it.isProbeNow(w.r))
		}
	}
	g.mu.Unlock()
}

// stop fails waiters and stops downloaders; a doomed or closing item calls
// it. A fresh open of the same path builds a fresh group, so no state from
// this one can leak into it.
func (g *dlGroup) stop() {
	g.mu.Lock()
	g.stopped = true
	g.failWaitersLocked(errCacheClosed)
	for _, dl := range g.dls {
		dl.stop()
	}
	g.mu.Unlock()
}

// downloader streams one contiguous region [start, target) from the backend
// through one session. Sequential readers keep extending target, so the
// steady state for a stream is a single downloader running a read-ahead
// window in front of the read head.
type downloader struct {
	g     *dlGroup
	probe bool
	kick  chan struct{}

	mu      sync.Mutex
	start   int64
	offset  int64
	target  int64
	stopped bool

	chunk   int64
	skipped int64
	bf      facetfs.File
	bra     io.ReaderAt
	seekPos int64
	buf     []byte
}

func (dl *downloader) span() (start, offset int64) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return dl.start, dl.offset
}

func (dl *downloader) done() bool {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return dl.stopped
}

func (dl *downloader) extend(target int64) {
	dl.mu.Lock()
	if target > dl.target {
		dl.target = target
	}
	dl.mu.Unlock()
	select {
	case dl.kick <- struct{}{}:
	default:
	}
}

func (dl *downloader) stop() {
	dl.mu.Lock()
	dl.stopped = true
	dl.mu.Unlock()
	select {
	case dl.kick <- struct{}{}:
	default:
	}
}

func (dl *downloader) run() {
	f := dl.g.it.f
	defer func() {
		dl.closeSession()
		dl.mu.Lock()
		dl.stopped = true
		dl.mu.Unlock()
		f.dlCount.Add(-1)
		dl.g.onExit(dl)
	}()
	idle := time.NewTimer(downloaderIdle)
	defer idle.Stop()
	for {
		if f.ctx.Err() != nil {
			return
		}
		dl.mu.Lock()
		off, target, stopped := dl.offset, dl.target, dl.stopped
		dl.mu.Unlock()
		if stopped {
			return
		}
		if off >= target {
			// Caught up. Park briefly so an extending reader reuses this
			// session instead of paying for a new one; exit when idle.
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(downloaderIdle)
			select {
			case <-dl.kick:
				continue
			case <-idle.C:
				return
			case <-f.ctx.Done():
				return
			}
		}
		missing := dl.g.it.findMissing(rng{off, target - off})
		if missing.size == 0 {
			dl.setOffset(target)
			continue
		}
		if gap := missing.pos - off; gap > 0 {
			// Bytes between off and the gap are already present: another
			// downloader or a mirror write got there. Overlap is a benign
			// race, but a downloader that keeps re-covering cached bytes is
			// redundant and stops.
			dl.skipped += gap
			if dl.skipped > maxSkipBytes && !dl.g.hasWaiters() {
				return
			}
		}
		n, err := dl.fetch(rng{missing.pos, min(missing.size, dl.chunk)})
		if n > 0 {
			dl.setOffset(missing.pos + n)
			dl.g.recordSuccess()
			dl.grow()
		}
		if err != nil {
			dl.closeSession()
			dl.chunk = dl.baseChunk()
			if dl.g.recordError(err) {
				return
			}
			// Back off briefly so a dead backend is not hammered in a hot
			// loop while the error budget drains.
			select {
			case <-time.After(200 * time.Millisecond):
			case <-f.ctx.Done():
				return
			}
		}
	}
}

func (dl *downloader) baseChunk() int64 {
	if dl.probe {
		return probeChunk
	}
	return dl.g.it.f.cache.chunkSize()
}

// grow doubles the chunk after each successful fetch, capped at 16x the
// base, so long sequential streams amortize per-request overhead. Probe
// downloaders stay at a fixed small chunk for latency.
func (dl *downloader) grow() {
	if dl.probe {
		return
	}
	dl.chunk = min(dl.chunk*2, dl.g.it.f.cache.chunkSize()*chunkGrowthCap)
}

func (dl *downloader) setOffset(off int64) {
	dl.mu.Lock()
	if off > dl.offset {
		dl.offset = off
	}
	dl.mu.Unlock()
}

func (g *dlGroup) hasWaiters() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.waiters) > 0
}

// fetch reads [m] from the backend session and publishes it in copy-buffer
// slices, waking waiters as each lands rather than after the whole chunk.
func (dl *downloader) fetch(m rng) (int64, error) {
	f := dl.g.it.f
	if dl.bf == nil {
		bf, err := f.backend.OpenFile(f.ctx, dl.g.it.name, os.O_RDONLY, 0)
		if err != nil {
			return 0, err
		}
		dl.bf = bf
		dl.bra, _ = bf.(io.ReaderAt)
		dl.seekPos = 0
		if dl.buf == nil {
			dl.buf = make([]byte, copyBufSize)
		}
	}
	var total int64
	for total < m.size {
		want := min(int64(len(dl.buf)), m.size-total)
		pos := m.pos + total
		n, err := dl.readBackend(dl.buf[:want], pos)
		if n > 0 {
			f.bytesFromBackend.Add(uint64(n))
			skipped, werr := dl.g.it.writeNoOverwrite(dl.buf[:n], pos)
			if werr != nil {
				return total, werr
			}
			dl.skipped += skipped
			total += int64(n)
			dl.g.kickWaiters()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func (dl *downloader) readBackend(p []byte, pos int64) (int, error) {
	if dl.bra != nil {
		return dl.bra.ReadAt(p, pos)
	}
	// No positioned reads on the backend File: this session is the only
	// user of the handle, so plain Seek+Read is safe.
	if dl.seekPos != pos {
		if _, err := dl.bf.Seek(pos, io.SeekStart); err != nil {
			return 0, err
		}
		dl.seekPos = pos
	}
	n, err := dl.bf.Read(p)
	dl.seekPos += int64(n)
	return n, err
}

func (dl *downloader) closeSession() {
	if dl.bf != nil {
		dl.bf.Close()
		dl.bf = nil
		dl.bra = nil
	}
}

// isProbeNow re-derives probe classification for kicker retries.
func (it *item) isProbeNow(r rng) bool {
	it.mu.RLock()
	size := it.size
	it.mu.RUnlock()
	return it.isProbe(r, size)
}

func (it *item) findMissing(r rng) rng {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.rs.findMissing(r)
}

func (it *item) hasRange(r rng) bool {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.rs.present(r)
}
