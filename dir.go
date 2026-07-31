package facetfs

import (
	"context"
	"io/fs"
	"os"
	"path"
	"time"
)

// Dir serves a directory tree on the native filesystem. It implements
// FileSystem, SymlinkFS, and SetStatFS. All access goes through os.Root, so
// symbolic links cannot escape the tree.
type Dir string

func (d Dir) resolve(name string) string {
	name = path.Clean("/" + name)
	if name == "/" {
		return "."
	}
	return name[1:]
}

func (d Dir) root() (*os.Root, error) {
	return os.OpenRoot(string(d))
}

func (d Dir) Mkdir(_ context.Context, name string, perm fs.FileMode) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Mkdir(d.resolve(name), perm)
}

func (d Dir) OpenFile(_ context.Context, name string, flag int, perm fs.FileMode) (File, error) {
	root, err := d.root()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.OpenFile(d.resolve(name), flag, perm)
}

func (d Dir) RemoveAll(_ context.Context, name string) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(d.resolve(name))
}

func (d Dir) Rename(_ context.Context, oldName, newName string) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Rename(d.resolve(oldName), d.resolve(newName))
}

func (d Dir) Stat(_ context.Context, name string) (fs.FileInfo, error) {
	root, err := d.root()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Stat(d.resolve(name))
}

func (d Dir) Link(_ context.Context, oldName, newName string) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Link(d.resolve(oldName), d.resolve(newName))
}

func (d Dir) Symlink(ctx context.Context, oldName, newName string) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Symlink(oldName, d.resolve(newName))
}

func (d Dir) Readlink(ctx context.Context, name string) (string, error) {
	root, err := d.root()
	if err != nil {
		return "", err
	}
	defer root.Close()
	return root.Readlink(d.resolve(name))
}

func (d Dir) Lstat(ctx context.Context, name string) (fs.FileInfo, error) {
	root, err := d.root()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Lstat(d.resolve(name))
}

func (d Dir) Chmod(ctx context.Context, name string, mode fs.FileMode) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Chmod(d.resolve(name), mode)
}

func (d Dir) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Chtimes(d.resolve(name), atime, mtime)
}

func (d Dir) Truncate(ctx context.Context, name string, size int64) error {
	root, err := d.root()
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(d.resolve(name), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}
