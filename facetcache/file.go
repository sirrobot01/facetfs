package facetcache

import (
	"io"
	"io/fs"
	"path"
	"sync"
	"sync/atomic"

	facetfs "github.com/sirrobot01/facetfs"
)

// cachedFile is a read-only handle onto a cached item. It always implements
// io.ReaderAt: the servers assert it and serialize behind a mutex without
// it. The handle is safe for concurrent ReadAt, Stat, Sync, and Close; both
// servers share one File across goroutines.
type cachedFile struct {
	f    *cfs
	it   *item
	base fs.FileInfo

	mu     sync.Mutex // serializes the Read/Seek cursor only
	off    int64
	closed atomic.Bool
}

// ReadAt implements io.ReaderAt.
func (cf *cachedFile) ReadAt(p []byte, off int64) (int, error) {
	if cf.closed.Load() {
		return 0, fs.ErrClosed
	}
	return cf.it.readAt(p, off)
}

func (cf *cachedFile) Read(p []byte) (int, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.closed.Load() {
		return 0, fs.ErrClosed
	}
	n, err := cf.it.readAt(p, cf.off)
	cf.off += int64(n)
	return n, err
}

func (cf *cachedFile) Seek(offset int64, whence int) (int64, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.closed.Load() {
		return 0, fs.ErrClosed
	}
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = cf.off
	case io.SeekEnd:
		base = cf.it.currentSize()
	default:
		return 0, fs.ErrInvalid
	}
	if base+offset < 0 {
		return 0, fs.ErrInvalid
	}
	cf.off = base + offset
	return cf.off, nil
}

func (cf *cachedFile) Write(p []byte) (int, error) {
	return 0, &fs.PathError{Op: "write", Path: cf.it.name, Err: fs.ErrInvalid}
}

func (cf *cachedFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "readdir", Path: cf.it.name, Err: fs.ErrInvalid}
}

// Stat reports the open-time attributes with the live cached size, so the
// per-READ EOF check the NFS server performs never touches the backend.
func (cf *cachedFile) Stat() (fs.FileInfo, error) {
	if cf.closed.Load() {
		return nil, fs.ErrClosed
	}
	return sizeInfo{cf.base, cf.it.currentSize()}, nil
}

// Sync reports success: the cache is write-through, so a read handle never
// holds bytes the backend has not already acknowledged.
func (cf *cachedFile) Sync() error { return nil }

func (cf *cachedFile) Close() error {
	if cf.closed.Swap(true) {
		return fs.ErrClosed
	}
	cf.f.releaseItem(cf.it)
	return nil
}

func (it *item) currentSize() int64 {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.size
}

// sizeInfo overrides Size on a backend FileInfo.
type sizeInfo struct {
	fs.FileInfo
	size int64
}

func (s sizeInfo) Size() int64 { return s.size }

// dirFile forwards a directory handle and feeds every Readdir batch into
// the attribute cache. The NFS server encodes READDIR attributes from these
// same values, so this population is free and absorbs the LOOKUP+GETATTR
// storm that follows a listing.
type dirFile struct {
	f    *cfs
	name string
	bf   facetfs.File
}

func (df *dirFile) Readdir(count int) ([]fs.FileInfo, error) {
	infos, err := df.bf.Readdir(count)
	for _, fi := range infos {
		child := path.Join(df.name, fi.Name())
		df.f.attr.store(child, true, fi)
		if fi.Mode()&fs.ModeSymlink == 0 {
			// For non-symlinks Stat and Lstat agree, so one entry serves
			// both. A symlink's followed stat must come from the backend.
			df.f.attr.store(child, false, fi)
		}
	}
	return infos, err
}

func (df *dirFile) Read(p []byte) (int, error)         { return df.bf.Read(p) }
func (df *dirFile) Write(p []byte) (int, error)        { return df.bf.Write(p) }
func (df *dirFile) Seek(o int64, w int) (int64, error) { return df.bf.Seek(o, w) }
func (df *dirFile) Stat() (fs.FileInfo, error)         { return df.bf.Stat() }
func (df *dirFile) Close() error                       { return df.bf.Close() }

// writeFile is the write-through handle: every operation goes to the
// backend first, and acknowledged bytes are mirrored into the cached item
// when one already exists. The generated matrix in matrix_gen.go adds
// WriteAt and Sync only when the backend handle has them; claiming Sync
// without backend durability would let NFS answer FILE_SYNC4 falsely.
type writeFile struct {
	f    *cfs
	name string
	bf   facetfs.File
	it   *item // pinned mirror target, nil when the file is not cached

	bwa interface {
		WriteAt(p []byte, off int64) (int, error)
	}
	bsync interface{ Sync() error }

	mu     sync.Mutex
	off    int64 // sequential cursor, mirrors the backend handle's
	closed atomic.Bool
}

func (wf *writeFile) Read(p []byte) (int, error) {
	wf.mu.Lock()
	defer wf.mu.Unlock()
	n, err := wf.bf.Read(p)
	wf.off += int64(n)
	return n, err
}

func (wf *writeFile) Seek(offset int64, whence int) (int64, error) {
	wf.mu.Lock()
	defer wf.mu.Unlock()
	n, err := wf.bf.Seek(offset, whence)
	if err == nil {
		wf.off = n
	}
	return n, err
}

func (wf *writeFile) Write(p []byte) (int, error) {
	wf.mu.Lock()
	defer wf.mu.Unlock()
	n, err := wf.bf.Write(p)
	if n > 0 {
		if wf.it != nil {
			wf.it.mirrorWrite(p[:n], wf.off)
		}
		wf.off += int64(n)
		wf.f.invalidateAttr(wf.name)
	}
	return n, err
}

func (wf *writeFile) Readdir(count int) ([]fs.FileInfo, error) { return wf.bf.Readdir(count) }
func (wf *writeFile) Stat() (fs.FileInfo, error)               { return wf.bf.Stat() }

func (wf *writeFile) Close() error {
	if wf.closed.Swap(true) {
		return fs.ErrClosed
	}
	err := wf.bf.Close()
	if wf.it != nil {
		wf.f.releaseItem(wf.it)
		wf.it = nil
	}
	wf.f.invalidateAttr(wf.name)
	return err
}

// writerAtExt adds io.WriterAt to a writeFile whose backend handle has it.
type writerAtExt struct{ w *writeFile }

// WriteAt implements io.WriterAt.
func (e writerAtExt) WriteAt(p []byte, off int64) (int, error) {
	n, err := e.w.bwa.WriteAt(p, off)
	if n > 0 {
		if e.w.it != nil {
			e.w.it.mirrorWrite(p[:n], off)
		}
		e.w.f.invalidateAttr(e.w.name)
	}
	return n, err
}

// syncExt adds Sync to a writeFile whose backend handle has it.
type syncExt struct{ w *writeFile }

// Sync forwards the durability barrier to the backend.
func (e syncExt) Sync() error {
	return e.w.bsync.Sync()
}
