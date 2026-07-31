package nfs4

import (
	"io"
	"io/fs"
	"sync"

	"github.com/sirrobot01/facetfs"
)

// openFile adapts a facetfs.File to the positioned I/O NFS performs. A File
// implementing io.ReaderAt or io.WriterAt serves requests in parallel;
// otherwise access is serialized behind a mutex with Seek.
type openFile struct {
	file facetfs.File
	ra   io.ReaderAt
	wa   io.WriterAt
	mu   sync.Mutex
	life sync.RWMutex
	once sync.Once
}

func newOpenFile(f facetfs.File) *openFile {
	o := &openFile{file: f}
	o.ra, _ = f.(io.ReaderAt)
	o.wa, _ = f.(io.WriterAt)
	return o
}

func (o *openFile) ReadAt(p []byte, off int64) (int, error) {
	o.life.RLock()
	defer o.life.RUnlock()
	if o.ra != nil {
		return o.ra.ReadAt(p, off)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.file.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(o.file, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

func (o *openFile) WriteAt(p []byte, off int64) (int, error) {
	o.life.RLock()
	defer o.life.RUnlock()
	if o.wa != nil {
		return o.wa.WriteAt(p, off)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.file.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return o.file.Write(p)
}

// sync flushes the file when the FileSystem's File supports it, and reports
// whether it did: COMMIT and stable WRITE answer honestly either way.
func (o *openFile) sync() (bool, error) {
	o.life.RLock()
	defer o.life.RUnlock()
	s, ok := o.file.(interface{ Sync() error })
	if !ok {
		return false, nil
	}
	return true, s.Sync()
}

func (o *openFile) canSync() bool {
	_, ok := o.file.(interface{ Sync() error })
	return ok
}

func (o *openFile) Stat() (fs.FileInfo, error) {
	o.life.RLock()
	defer o.life.RUnlock()
	return o.file.Stat()
}

func (o *openFile) Close() error {
	var err error
	o.once.Do(func() {
		o.life.Lock()
		defer o.life.Unlock()
		err = o.file.Close()
	})
	return err
}
