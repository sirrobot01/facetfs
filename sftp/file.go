package sftp

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/sirrobot01/facetfs"
)

type openFile struct {
	ctx     context.Context
	server  *facetfs.Server
	request facetfs.Request
	handle  facetfs.Handle
	mutable facetfs.MutableHandle
	append  bool
	mu      sync.Mutex
	closed  atomic.Bool
}

func (f *openFile) ReadAt(buffer []byte, offset int64) (int, error) {
	n, err := f.handle.ReadAt(f.ctx, buffer, offset)
	if errors.Is(err, io.EOF) {
		return n, err
	}
	return n, wireError(err)
}

func (f *openFile) WriteAt(buffer []byte, offset int64) (int, error) {
	if !f.append {
		n, err := f.mutable.WriteAt(f.ctx, buffer, offset)
		return n, wireError(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attr, err := f.server.GetAttr(f.ctx, f.request, f.handle.Object(), facetfs.AttrSize)
	if err != nil {
		return 0, wireError(err)
	}
	n, err := f.mutable.WriteAt(f.ctx, buffer, attr.Size)
	return n, wireError(err)
}

func (f *openFile) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	ctx := context.WithoutCancel(f.ctx)
	var flushErr error
	if f.mutable != nil {
		flushErr = wireError(f.mutable.Flush(ctx, true))
	}
	return errors.Join(flushErr, wireError(f.handle.Close(ctx)))
}
