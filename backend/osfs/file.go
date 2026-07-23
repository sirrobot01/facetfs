package osfs

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
)

type file struct {
	fs     *FS
	file   *os.File
	id     string
	record *record
	object facetfs.ObjectRef
	access facetfs.OpenAccess
	closed atomic.Bool
}

var _ facetfs.MutableHandle = (*file)(nil)

func (f *FS) Open(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, options facetfs.OpenOptions) (facetfs.Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, info, record, err := f.resolve(object)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, facetfs.ErrNotSupported
	}
	if info.IsDir() && options.Access&facetfs.OpenWrite != 0 {
		return nil, facetfs.ErrIsDirectory
	}
	opened, err := os.OpenFile(path, openFlags(options.Access), 0)
	if err != nil {
		return nil, mapError(err)
	}
	return f.openFile(opened, record, object, options.Access), nil
}

func (f *FS) Create(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, options facetfs.CreateOptions) (facetfs.ObjectRef, facetfs.Handle, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	parentPath, info, _, err := f.resolve(parent)
	if err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	if !info.IsDir() {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrNotDirectory
	}
	path := filepath.Join(parentPath, name)
	existed := false
	if existing, statErr := os.Lstat(path); statErr == nil {
		existed = true
		if existing.IsDir() {
			return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrIsDirectory
		}
		if existing.Mode()&fs.ModeSymlink != 0 {
			return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrNotSupported
		}
	} else if !os.IsNotExist(statErr) {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, mapError(statErr)
	}
	flags := openFlags(options.Open.Access) | os.O_CREATE
	if options.Exclusive {
		flags |= os.O_EXCL
	}
	mode := fs.FileMode(0o666)
	if options.Attr.Mode != nil {
		mode = *options.Attr.Mode
	}
	opened, err := os.OpenFile(path, flags, mode.Perm())
	if err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, mapError(err)
	}
	createdInfo, err := opened.Stat()
	if err != nil {
		_ = opened.Close()
		if !existed {
			_ = os.Remove(path)
		}
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, mapError(err)
	}
	record := f.track(path, createdInfo)
	object := objectRef(parent.ExportID, record)
	handle := f.openFile(opened, record, object, options.Open.Access)
	if err := f.apply(path, createdInfo, options.Attr); err != nil {
		_ = handle.Close(context.WithoutCancel(ctx))
		if !existed {
			_ = os.Remove(path)
			f.removed(path)
		}
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	if !existed {
		f.changed(parentPath)
	}
	createdInfo, err = os.Lstat(path)
	if err != nil {
		_ = handle.Close(context.WithoutCancel(ctx))
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, mapError(err)
	}
	f.changed(path)
	return object, handle, f.fileAttr(record, createdInfo), nil
}

func (f *FS) openFile(opened *os.File, record *record, object facetfs.ObjectRef, access facetfs.OpenAccess) *file {
	f.mu.Lock()
	record.open++
	f.handles++
	id := strconv.FormatUint(f.handles, 10)
	f.mu.Unlock()
	return &file{fs: f, file: opened, id: id, record: record, object: object, access: access}
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
	n, err := f.file.ReadAt(p, off)
	if err != nil && err != io.EOF {
		return n, mapError(err)
	}
	return n, err
}

func (f *file) WriteAt(ctx context.Context, p []byte, off int64) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, facetfs.ErrInvalid
	}
	if err := f.check(facetfs.OpenWrite); err != nil {
		return 0, err
	}
	n, err := f.file.WriteAt(p, off)
	if err != nil {
		return n, mapError(err)
	}
	if info, statErr := f.file.Stat(); statErr == nil {
		f.fs.changedRecord(f.record, info)
	}
	return n, nil
}

func (f *file) Flush(ctx context.Context, _ bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.check(0); err != nil {
		return err
	}
	return mapError(f.file.Sync())
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
	err := mapError(f.file.Close())
	f.fs.mu.Lock()
	f.record.open--
	if len(f.record.paths) == 0 && f.record.open == 0 {
		delete(f.fs.records, f.record.id)
	}
	f.fs.mu.Unlock()
	return err
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

func (f *FS) apply(path string, info fs.FileInfo, set facetfs.SetAttr) error {
	if set.Owner != nil || set.Group != nil {
		return facetfs.ErrNotSupported
	}
	if info.Mode()&fs.ModeSymlink != 0 && (set.Size != nil || set.Mode != nil || set.AccessedAt != nil || set.ModifiedAt != nil) {
		return facetfs.ErrNotSupported
	}
	if set.Size != nil {
		if *set.Size < 0 {
			return facetfs.ErrInvalid
		}
		if info.IsDir() {
			return facetfs.ErrIsDirectory
		}
		if err := os.Truncate(path, *set.Size); err != nil {
			return mapError(err)
		}
	}
	if set.Mode != nil {
		if err := os.Chmod(path, set.Mode.Perm()); err != nil {
			return mapError(err)
		}
	}
	if set.AccessedAt != nil || set.ModifiedAt != nil {
		accessed, modified := info.ModTime(), info.ModTime()
		if set.AccessedAt != nil {
			accessed = *set.AccessedAt
		}
		if set.ModifiedAt != nil {
			modified = *set.ModifiedAt
		}
		if err := os.Chtimes(path, accessed, modified); err != nil {
			return mapError(err)
		}
	}
	f.changed(path)
	return nil
}

func openFlags(access facetfs.OpenAccess) int {
	switch access & (facetfs.OpenRead | facetfs.OpenWrite) {
	case facetfs.OpenWrite:
		return os.O_WRONLY
	case facetfs.OpenRead | facetfs.OpenWrite:
		return os.O_RDWR
	default:
		return os.O_RDONLY
	}
}
