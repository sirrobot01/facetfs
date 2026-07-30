package sftp

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/sirrobot01/facetfs"
)

// openFile bridges a facetfs.File to the positioned I/O pkg/sftp performs.
// When the File implements io.ReaderAt or io.WriterAt those are used directly
// and requests run in parallel; otherwise positioned access is serialized
// behind a mutex with Seek.
type openFile struct {
	file     facetfs.File
	ra       io.ReaderAt
	wa       io.WriterAt
	appendTo bool
	mu       sync.Mutex
	closed   atomic.Bool
}

func newOpenFile(file facetfs.File, appendTo bool) *openFile {
	f := &openFile{file: file, appendTo: appendTo}
	f.ra, _ = file.(io.ReaderAt)
	f.wa, _ = file.(io.WriterAt)
	return f
}

func (f *openFile) ReadAt(p []byte, off int64) (int, error) {
	if f.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if f.ra != nil {
		n, err := f.ra.ReadAt(p, off)
		if err == io.EOF {
			return n, err
		}
		return n, wireError(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.file.Seek(off, io.SeekStart); err != nil {
		return 0, wireError(err)
	}
	n, err := io.ReadFull(f.file, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	if err == io.EOF {
		return n, err
	}
	return n, wireError(err)
}

func (f *openFile) WriteAt(p []byte, off int64) (int, error) {
	if f.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if f.appendTo {
		// The file was opened O_APPEND: the FileSystem places every write at
		// the end regardless of the requested offset.
		f.mu.Lock()
		defer f.mu.Unlock()
		n, err := f.file.Write(p)
		return n, wireError(err)
	}
	if f.wa != nil {
		n, err := f.wa.WriteAt(p, off)
		return n, wireError(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.file.Seek(off, io.SeekStart); err != nil {
		return 0, wireError(err)
	}
	n, err := f.file.Write(p)
	return n, wireError(err)
}

func (f *openFile) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	return wireError(f.file.Close())
}
