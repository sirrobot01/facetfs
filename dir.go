package facetfs

import (
	"context"
	"io/fs"
	"os"
	"path"
	"time"
)

// Dir serves a directory tree on the native filesystem. It implements
// FileSystem, LinkFS, RemoveFS, SymlinkFS, and SetStatFS. All access goes
// through os.Root, so symbolic links cannot escape the tree.
//
// Dir opens the tree again for every operation, which costs two extra system
// calls each time. A server serving many small operations should use OpenDir,
// which holds the tree open.
type Dir string

func (d Dir) with(fn func(*Root) error) error {
	root, err := OpenDir(string(d))
	if err != nil {
		return err
	}
	defer root.Close()
	return fn(root)
}

func (d Dir) Mkdir(ctx context.Context, name string, perm fs.FileMode) error {
	return d.with(func(r *Root) error { return r.Mkdir(ctx, name, perm) })
}

func (d Dir) OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (File, error) {
	var file File
	err := d.with(func(r *Root) (err error) {
		file, err = r.OpenFile(ctx, name, flag, perm)
		return err
	})
	return file, err
}

func (d Dir) Remove(ctx context.Context, name string) error {
	return d.with(func(r *Root) error { return r.Remove(ctx, name) })
}

func (d Dir) RemoveAll(ctx context.Context, name string) error {
	return d.with(func(r *Root) error { return r.RemoveAll(ctx, name) })
}

func (d Dir) Rename(ctx context.Context, oldName, newName string) error {
	return d.with(func(r *Root) error { return r.Rename(ctx, oldName, newName) })
}

func (d Dir) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	var info fs.FileInfo
	err := d.with(func(r *Root) (err error) {
		info, err = r.Stat(ctx, name)
		return err
	})
	return info, err
}

func (d Dir) Lstat(ctx context.Context, name string) (fs.FileInfo, error) {
	var info fs.FileInfo
	err := d.with(func(r *Root) (err error) {
		info, err = r.Lstat(ctx, name)
		return err
	})
	return info, err
}

func (d Dir) Link(ctx context.Context, oldName, newName string) error {
	return d.with(func(r *Root) error { return r.Link(ctx, oldName, newName) })
}

func (d Dir) Symlink(ctx context.Context, oldName, newName string) error {
	return d.with(func(r *Root) error { return r.Symlink(ctx, oldName, newName) })
}

func (d Dir) Readlink(ctx context.Context, name string) (string, error) {
	var target string
	err := d.with(func(r *Root) (err error) {
		target, err = r.Readlink(ctx, name)
		return err
	})
	return target, err
}

func (d Dir) Chmod(ctx context.Context, name string, mode fs.FileMode) error {
	return d.with(func(r *Root) error { return r.Chmod(ctx, name, mode) })
}

func (d Dir) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	return d.with(func(r *Root) error { return r.Chtimes(ctx, name, atime, mtime) })
}

func (d Dir) Truncate(ctx context.Context, name string, size int64) error {
	return d.with(func(r *Root) error { return r.Truncate(ctx, name, size) })
}

// Root serves a directory tree that it holds open, so an operation costs no
// more system calls than the operation itself needs. It implements the same
// interfaces as Dir, and symbolic links cannot escape the tree either.
//
// A Root is safe for concurrent use. Close it when the server is finished
// with it.
type Root struct {
	root *os.Root
}

// OpenDir opens a directory tree for serving.
func OpenDir(name string) (*Root, error) {
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &Root{root: root}, nil
}

// Close releases the directory tree. Operations after it fail.
func (r *Root) Close() error { return r.root.Close() }

// resolve turns a served path into one relative to the tree.
func resolve(name string) string {
	name = path.Clean("/" + name)
	if name == "/" {
		return "."
	}
	return name[1:]
}

func (r *Root) Mkdir(_ context.Context, name string, perm fs.FileMode) error {
	return r.root.Mkdir(resolve(name), perm)
}

func (r *Root) OpenFile(_ context.Context, name string, flag int, perm fs.FileMode) (File, error) {
	return r.root.OpenFile(resolve(name), flag, perm)
}

func (r *Root) Remove(_ context.Context, name string) error {
	return r.root.Remove(resolve(name))
}

func (r *Root) RemoveAll(_ context.Context, name string) error {
	return r.root.RemoveAll(resolve(name))
}

func (r *Root) Rename(_ context.Context, oldName, newName string) error {
	return r.root.Rename(resolve(oldName), resolve(newName))
}

func (r *Root) Stat(_ context.Context, name string) (fs.FileInfo, error) {
	return r.root.Stat(resolve(name))
}

func (r *Root) Lstat(_ context.Context, name string) (fs.FileInfo, error) {
	return r.root.Lstat(resolve(name))
}

func (r *Root) Link(_ context.Context, oldName, newName string) error {
	return r.root.Link(resolve(oldName), resolve(newName))
}

func (r *Root) Symlink(_ context.Context, oldName, newName string) error {
	return r.root.Symlink(oldName, resolve(newName))
}

func (r *Root) Readlink(_ context.Context, name string) (string, error) {
	return r.root.Readlink(resolve(name))
}

func (r *Root) Chmod(_ context.Context, name string, mode fs.FileMode) error {
	return r.root.Chmod(resolve(name), mode)
}

func (r *Root) Chtimes(_ context.Context, name string, atime, mtime time.Time) error {
	return r.root.Chtimes(resolve(name), atime, mtime)
}

func (r *Root) Truncate(_ context.Context, name string, size int64) error {
	f, err := r.root.OpenFile(resolve(name), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}
