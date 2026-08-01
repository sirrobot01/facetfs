package facetcache

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	facetfs "github.com/sirrobot01/facetfs"
)

// Static capability assertions: losing ReaderAt would serialize server I/O
// behind a mutex, and losing Sync would degrade NFS COMMIT.
var (
	_ io.ReaderAt               = (*cachedFile)(nil)
	_ interface{ Sync() error } = (*cachedFile)(nil)
	_ facetfs.File              = (*cachedFile)(nil)
	_ facetfs.File              = (*dirFile)(nil)
	_ facetfs.File              = (*writeFile)(nil)
)

// countingFS wraps a backend and counts the traffic the cache lets through.
type countingFS struct {
	facetfs.FileSystem
	stats     atomic.Int64
	opens     atomic.Int64
	readBytes atomic.Int64
	readDelay time.Duration
}

func (c *countingFS) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	c.stats.Add(1)
	return c.FileSystem.Stat(ctx, name)
}

func (c *countingFS) OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (facetfs.File, error) {
	c.opens.Add(1)
	f, err := c.FileSystem.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	cf := &countingFile{File: f, fs: c}
	cf.ra, _ = f.(io.ReaderAt)
	cf.wa, _ = f.(io.WriterAt)
	return cf, nil
}

type countingFile struct {
	facetfs.File
	fs *countingFS
	ra io.ReaderAt
	wa io.WriterAt
}

func (c *countingFile) WriteAt(p []byte, off int64) (int, error) {
	return c.wa.WriteAt(p, off)
}

func (c *countingFile) ReadAt(p []byte, off int64) (int, error) {
	if c.fs.readDelay > 0 {
		time.Sleep(c.fs.readDelay)
	}
	n, err := c.ra.ReadAt(p, off)
	c.fs.readBytes.Add(int64(n))
	return n, err
}

func (c *countingFile) Read(p []byte) (int, error) {
	if c.fs.readDelay > 0 {
		time.Sleep(c.fs.readDelay)
	}
	n, err := c.File.Read(p)
	c.fs.readBytes.Add(int64(n))
	return n, err
}

// clock is a fake time source tests advance by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func writeBackendFile(t *testing.T, backend facetfs.FileSystem, name string, data []byte) {
	t.Helper()
	f, err := backend.OpenFile(context.Background(), name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func newTestCache(t *testing.T, backend facetfs.FileSystem, mutate func(*Cache)) (*Cache, facetfs.FileSystem) {
	t.Helper()
	c := &Cache{Backend: backend, Dir: t.TempDir()}
	if mutate != nil {
		mutate(c)
	}
	fsys, err := c.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, fsys
}

func readAll(t *testing.T, fsys facetfs.FileSystem, name string) []byte {
	t.Helper()
	f, err := fsys.OpenFile(context.Background(), name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAttrCaching(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	writeBackendFile(t, backend, "/f", pattern(100))
	ck := newClock()
	_, fsys := newTestCache(t, backend, func(c *Cache) { c.now = ck.Now })
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := fsys.Stat(ctx, "/f"); err != nil {
			t.Fatal(err)
		}
	}
	if got := backend.stats.Load(); got != 1 {
		t.Fatalf("backend stats = %d, want 1", got)
	}
	ck.Advance(2 * time.Second) // past the 1s TTL
	if _, err := fsys.Stat(ctx, "/f"); err != nil {
		t.Fatal(err)
	}
	if got := backend.stats.Load(); got != 2 {
		t.Fatalf("backend stats after TTL = %d, want 2", got)
	}
}

func TestNegativeAttrCaching(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	_, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := fsys.Stat(ctx, "/missing"); !os.IsNotExist(err) && !errorsIsNotExist(err) {
			t.Fatalf("want ErrNotExist, got %v", err)
		}
	}
	if got := backend.stats.Load(); got != 1 {
		t.Fatalf("backend stats = %d, want 1", got)
	}
	// Creating the file must invalidate the negative entry immediately.
	f, err := fsys.OpenFile(ctx, "/missing", os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := fsys.Stat(ctx, "/missing"); err != nil {
		t.Fatalf("stat after create: %v", err)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && (os.IsNotExist(err) || errorsIs(err, fs.ErrNotExist))
}

func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func TestReaddirPopulatesAttrs(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	ctx := context.Background()
	if err := backend.FileSystem.Mkdir(ctx, "/d", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"/d/a", "/d/b", "/d/c"} {
		writeBackendFile(t, backend, n, pattern(10))
	}
	_, fsys := newTestCache(t, backend, nil)

	df, err := fsys.OpenFile(ctx, "/d", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := df.Readdir(-1); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	df.Close()
	before := backend.stats.Load()
	for _, n := range []string{"/d/a", "/d/b", "/d/c"} {
		if _, err := fsys.Stat(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if got := backend.stats.Load(); got != before {
		t.Fatalf("child stats hit the backend: %d calls", got-before)
	}
}

func TestReadThroughAndWarmReads(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	data := pattern(300 << 10)
	writeBackendFile(t, backend, "/f", data)
	c, fsys := newTestCache(t, backend, nil)

	if got := readAll(t, fsys, "/f"); !bytes.Equal(got, data) {
		t.Fatalf("cold read mismatch: %d bytes", len(got))
	}
	cold := backend.readBytes.Load()
	if cold < int64(len(data)) {
		t.Fatalf("backend served %d bytes, want at least %d", cold, len(data))
	}
	if got := readAll(t, fsys, "/f"); !bytes.Equal(got, data) {
		t.Fatal("warm read mismatch")
	}
	if got := backend.readBytes.Load(); got != cold {
		t.Fatalf("warm read hit the backend: %d extra bytes", got-cold)
	}
	st := c.Stats()
	if st.BytesFromCache == 0 || st.BytesFromBackend == 0 {
		t.Fatalf("stats missing traffic: %+v", st)
	}
}

func TestConcurrentReadersShareOneFetch(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS(), readDelay: 2 * time.Millisecond}
	data := pattern(1 << 20)
	writeBackendFile(t, backend, "/f", data)
	backend.opens.Store(0)
	_, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := fsys.OpenFile(ctx, "/f", os.O_RDONLY, 0)
			if err != nil {
				errs <- err
				return
			}
			defer f.Close()
			buf := make([]byte, 64<<10)
			if _, err := f.(io.ReaderAt).ReadAt(buf, 0); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(buf, data[:len(buf)]) {
				errs <- io.ErrUnexpectedEOF
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// All eight readers wanted the same region; waiter parking must not
	// open a backend session per reader.
	if got := backend.opens.Load(); got > maxDownloadersPerItem {
		t.Fatalf("backend opened %d times, want <= %d", got, maxDownloadersPerItem)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	data := pattern(128 << 10)
	writeBackendFile(t, backend, "/f", data)
	dir := t.TempDir()

	c1 := &Cache{Backend: backend, Dir: dir}
	fs1, err := c1.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs1, "/f"); !bytes.Equal(got, data) {
		t.Fatal("cold read mismatch")
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}

	before := backend.readBytes.Load()
	c2 := &Cache{Backend: backend, Dir: dir}
	fs2, err := c2.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if got := readAll(t, fs2, "/f"); !bytes.Equal(got, data) {
		t.Fatal("restart read mismatch")
	}
	if got := backend.readBytes.Load(); got != before {
		t.Fatalf("restart read refetched %d bytes", got-before)
	}
}

func TestFingerprintInvalidation(t *testing.T) {
	backend := facetfs.NewMemFS()
	writeBackendFile(t, &countingFS{FileSystem: backend}, "/f", pattern(1000))
	dir := t.TempDir()

	c1 := &Cache{Backend: backend, Dir: dir}
	fs1, err := c1.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, fs1, "/f")
	c1.Close()

	// Replace the object behind the same name with different content.
	replacement := bytes.Repeat([]byte{0xAB}, 2000)
	writeBackendFile(t, &countingFS{FileSystem: backend}, "/f", replacement)

	c2 := &Cache{Backend: backend, Dir: dir}
	fs2, err := c2.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if got := readAll(t, fs2, "/f"); !bytes.Equal(got, replacement) {
		t.Fatalf("served stale content after backend change")
	}
}

func TestWriteThroughMirror(t *testing.T) {
	backend := &countingFS{FileSystem: facetfs.NewMemFS()}
	data := pattern(64 << 10)
	writeBackendFile(t, backend, "/f", data)
	_, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	// Cache the file, then rewrite a slice through the cache.
	readAll(t, fsys, "/f")
	wf, err := fsys.OpenFile(ctx, "/f", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	patch := bytes.Repeat([]byte{0xEE}, 1000)
	if _, err := wf.(io.WriterAt).WriteAt(patch, 500); err != nil {
		t.Fatal(err)
	}
	if err := wf.Close(); err != nil {
		t.Fatal(err)
	}

	want := append([]byte(nil), data...)
	copy(want[500:], patch)
	backendBytes := backend.readBytes.Load()
	if got := readAll(t, fsys, "/f"); !bytes.Equal(got, want) {
		t.Fatal("mirror produced wrong content")
	}
	if got := backend.readBytes.Load(); got != backendBytes {
		t.Fatalf("read after mirrored write refetched %d bytes", got-backendBytes)
	}
	// The backend must hold the same content: write-through, not write-back.
	if got := readAll(t, backend, "/f"); !bytes.Equal(got, want) {
		t.Fatal("backend missing written bytes")
	}
}

func TestTruncateThroughSetStat(t *testing.T) {
	backend := facetfs.NewMemFS()
	writeBackendFile(t, &countingFS{FileSystem: backend}, "/f", pattern(4096))
	_, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	readAll(t, fsys, "/f")
	ss, ok := fsys.(facetfs.SetStatFS)
	if !ok {
		t.Fatal("wrapper lost SetStatFS")
	}
	if err := ss.Truncate(ctx, "/f", 100); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fsys, "/f"); len(got) != 100 {
		t.Fatalf("read %d bytes after truncate, want 100", len(got))
	}
}

func TestRenameInvalidates(t *testing.T) {
	backend := facetfs.NewMemFS()
	data := pattern(2048)
	writeBackendFile(t, &countingFS{FileSystem: backend}, "/a", data)
	c, fsys := newTestCache(t, backend, nil)
	ctx := context.Background()

	readAll(t, fsys, "/a")
	if err := fsys.Rename(ctx, "/a", "/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat(ctx, "/a"); !errorsIsNotExist(err) {
		t.Fatalf("stat of renamed-away name: %v", err)
	}
	if got := readAll(t, fsys, "/b"); !bytes.Equal(got, data) {
		t.Fatal("read after rename mismatch")
	}
	// The old name's cache files must be gone from disk.
	if _, err := os.Stat(filepath.Join(c.Dir, "data", "a")); !os.IsNotExist(err) {
		t.Fatalf("stale data file survived rename: %v", err)
	}
}

func TestOptionalInterfacePreservation(t *testing.T) {
	memfs := facetfs.NewMemFS()
	_, wrapped := newTestCache(t, memfs, nil)
	checks := []struct {
		name    string
		backend bool
		wrapper bool
	}{
		{"SymlinkFS", is[facetfs.SymlinkFS](memfs), is[facetfs.SymlinkFS](wrapped)},
		{"LinkFS", is[facetfs.LinkFS](memfs), is[facetfs.LinkFS](wrapped)},
		{"RemoveFS", is[facetfs.RemoveFS](memfs), is[facetfs.RemoveFS](wrapped)},
		{"SetStatFS", is[facetfs.SetStatFS](memfs), is[facetfs.SetStatFS](wrapped)},
		{"StatVFSFS", is[facetfs.StatVFSFS](memfs), is[facetfs.StatVFSFS](wrapped)},
	}
	for _, c := range checks {
		if c.backend != c.wrapper {
			t.Errorf("%s: backend %v, wrapper %v", c.name, c.backend, c.wrapper)
		}
	}

	// A core-only backend must produce a core-only wrapper.
	bare := struct{ facetfs.FileSystem }{memfs}
	_, bareWrapped := newTestCache(t, bare, nil)
	if is[facetfs.SymlinkFS](bareWrapped) || is[facetfs.SetStatFS](bareWrapped) || is[facetfs.StatVFSFS](bareWrapped) {
		t.Fatal("wrapper claims interfaces a bare backend lacks")
	}
}

func is[T any](v any) bool { _, ok := v.(T); return ok }

func TestEvictionBySizeAndAge(t *testing.T) {
	backend := facetfs.NewMemFS()
	cfs := &countingFS{FileSystem: backend}
	writeBackendFile(t, cfs, "/old", pattern(4096))
	writeBackendFile(t, cfs, "/new", pattern(4096))
	ck := newClock()
	c, fsys := newTestCache(t, backend, func(c *Cache) {
		c.now = ck.Now
		c.MaxBytes = 5000 // holds one file, not two
	})

	readAll(t, fsys, "/old")
	ck.Advance(10 * time.Second)
	readAll(t, fsys, "/new")

	// Let both items go idle, close them, then enforce the budget.
	ck.Advance(2 * itemIdleClose)
	c.core.jan.pass()
	if got := c.Stats().CachedBytes; got > 5000 {
		t.Fatalf("cachedBytes = %d after eviction, want <= 5000", got)
	}
	// The older item must be the one that went.
	if _, err := os.Stat(filepath.Join(c.Dir, "data", "old")); !os.IsNotExist(err) {
		t.Fatal("size eviction kept the older item")
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "data", "new")); err != nil {
		t.Fatalf("size eviction removed the newer item: %v", err)
	}

	// Age eviction: push past MaxAge and the survivor goes too.
	ck.Advance(25 * time.Hour)
	c.core.jan.pass()
	if _, err := os.Stat(filepath.Join(c.Dir, "data", "new")); !os.IsNotExist(err) {
		t.Fatal("age eviction kept an expired item")
	}
	if got := c.Stats().CachedBytes; got != 0 {
		t.Fatalf("cachedBytes = %d after full eviction, want 0", got)
	}
}

func TestCorruptMetadataRecovery(t *testing.T) {
	backend := facetfs.NewMemFS()
	data := pattern(1024)
	writeBackendFile(t, &countingFS{FileSystem: backend}, "/f", data)
	dir := t.TempDir()

	c1 := &Cache{Backend: backend, Dir: dir}
	fs1, err := c1.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, fs1, "/f")
	c1.Close()

	metaPath := filepath.Join(dir, "meta", "f.json")
	if err := os.WriteFile(metaPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath+".tmp", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	c2 := &Cache{Backend: backend, Dir: dir}
	fs2, err := c2.FileSystem()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := os.Stat(metaPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("interrupted flush temp file survived startup")
	}
	if got := readAll(t, fs2, "/f"); !bytes.Equal(got, data) {
		t.Fatal("read after corrupt metadata mismatch")
	}
}

func TestIsProbeProportionalZone(t *testing.T) {
	it := &item{}
	// 10 MiB file: zone is 2.5 MiB, so an opening read keeps read-ahead.
	if it.isProbe(rng{0, 4096}, 10<<20) {
		t.Fatal("opening read of a small file classified as probe")
	}
	if !it.isProbe(rng{9 << 20, 4096}, 10<<20) {
		t.Fatal("tail read not classified as probe")
	}
	// 10 GiB file: zone caps at 64 MiB.
	if it.isProbe(rng{5 << 30, 4096}, 10<<30) {
		t.Fatal("mid-file read of a large file classified as probe")
	}
	if !it.isProbe(rng{10<<30 - 1<<20, 4096}, 10<<30) {
		t.Fatal("moov-shaped tail read not classified as probe")
	}
}
