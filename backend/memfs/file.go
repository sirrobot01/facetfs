package memfs

import (
	"context"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sirrobot01/facetfs"
)

type file struct {
	fs     *FS
	id     string
	object facetfs.ObjectRef
	access facetfs.OpenAccess
	closed atomic.Bool
}

var _ facetfs.MutableHandle = (*file)(nil)

func (f *FS) Open(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, options facetfs.OpenOptions) (facetfs.Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.node(object)
	if err != nil {
		return nil, err
	}
	if n.kind == facetfs.NodeTypeSymlink {
		return nil, facetfs.ErrNotSupported
	}
	if n.kind == facetfs.NodeTypeDirectory && options.Access&facetfs.OpenWrite != 0 {
		return nil, facetfs.ErrIsDirectory
	}
	return f.open(object, n, options), nil
}

func (f *FS) open(object facetfs.ObjectRef, n *node, options facetfs.OpenOptions) *file {
	f.handles++
	n.open++
	return &file{
		fs:     f,
		id:     strconv.FormatUint(f.handles, 10),
		object: object,
		access: options.Access,
	}
}

func (f *file) ID() string                { return f.id }
func (f *file) Object() facetfs.ObjectRef { return f.object }

func (f *file) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, facetfs.ErrInvalid
	}
	if err := f.check(facetfs.OpenRead); err != nil {
		return 0, err
	}
	f.fs.mu.RLock()
	defer f.fs.mu.RUnlock()
	n, err := f.fs.node(f.object)
	if err != nil {
		return 0, err
	}
	if n.kind == facetfs.NodeTypeDirectory {
		return 0, facetfs.ErrIsDirectory
	}
	if off >= int64(len(n.data)) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	nn := copy(p, n.data[off:])
	if nn != len(p) {
		return nn, io.EOF
	}
	return nn, nil
}

func (f *file) WriteAt(ctx context.Context, p []byte, off int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 || off > int64(int(^uint(0)>>1)-len(p)) {
		return 0, facetfs.ErrInvalid
	}
	if err := f.check(facetfs.OpenWrite); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	n, err := f.fs.node(f.object)
	if err != nil {
		return 0, err
	}
	if n.kind == facetfs.NodeTypeDirectory {
		return 0, facetfs.ErrIsDirectory
	}
	end := int(off) + len(p)
	if end > maxFileSize {
		return 0, facetfs.ErrNoSpace
	}
	if end > len(n.data) {
		data := make([]byte, end)
		copy(data, n.data)
		n.data = data
	}
	copy(n.data[off:], p)
	n.modified = time.Now().UTC()
	f.fs.touch(n)
	return len(p), nil
}

func (f *file) Flush(ctx context.Context, _ bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.check(0)
}

func (f *file) SetAttr(ctx context.Context, set facetfs.SetAttr) (facetfs.Attr, error) {
	if err := f.check(facetfs.OpenWrite); err != nil {
		return facetfs.Attr{}, err
	}
	return f.fs.SetAttr(ctx, facetfs.Request{}, f.object, set)
}

func (f *file) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.closed.Swap(true) {
		return nil
	}
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	n := f.fs.nodes[f.object.NodeID]
	if n != nil && n.generation == f.object.Generation {
		n.open--
		f.fs.release(n)
	}
	return nil
}

func (f *file) check(access facetfs.OpenAccess) error {
	if f.closed.Load() {
		return facetfs.ErrInvalid
	}
	if access != 0 && f.access&access == 0 {
		return facetfs.ErrAccessDenied
	}
	return nil
}
