package facetfs

import (
	"context"
	"io"
	"io/fs"
	"time"
)

// FileSystem is the path-based filesystem contract served by the protocol
// packages. Paths are slash-separated and rooted at "/". Implementations must
// reject names that escape the root after path.Clean and must be safe for
// concurrent use.
//
// Errors should satisfy errors.Is against the io/fs sentinels fs.ErrNotExist,
// fs.ErrExist, fs.ErrPermission, and fs.ErrInvalid; protocol packages map
// anything else to a generic internal error.
type FileSystem interface {
	Mkdir(ctx context.Context, name string, perm fs.FileMode) error
	OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (File, error)
	RemoveAll(ctx context.Context, name string) error
	// Rename has POSIX semantics: it replaces an existing target.
	Rename(ctx context.Context, oldName, newName string) error
	Stat(ctx context.Context, name string) (fs.FileInfo, error)
}

// File is an open file returned by FileSystem.OpenFile.
//
// Protocol packages that perform positioned I/O (such as SFTP) assert
// io.ReaderAt and io.WriterAt on the returned File as a fast path; a File
// that does not implement them is serialized behind a mutex with Seek.
type File interface {
	io.Closer
	io.Reader
	io.Seeker
	io.Writer
	Readdir(count int) ([]fs.FileInfo, error)
	Stat() (fs.FileInfo, error)
}

// SymlinkFS is implemented by filesystems that support symbolic links.
type SymlinkFS interface {
	FileSystem
	Symlink(ctx context.Context, oldname, newname string) error
	Readlink(ctx context.Context, name string) (string, error)
	Lstat(ctx context.Context, name string) (fs.FileInfo, error)
}

// SetStatFS is implemented by filesystems that can change metadata by path.
// SFTP uses it to serve setstat requests.
type SetStatFS interface {
	FileSystem
	Chmod(ctx context.Context, name string, mode fs.FileMode) error
	Chtimes(ctx context.Context, name string, atime, mtime time.Time) error
	Truncate(ctx context.Context, name string, size int64) error
}

// StatVFSFS is implemented by filesystems that can report capacity.
type StatVFSFS interface {
	FileSystem
	StatVFS(ctx context.Context, name string) (FSStat, error)
}

// FSStat describes filesystem capacity.
type FSStat struct {
	TotalBytes uint64
	FreeBytes  uint64
	AvailBytes uint64
	TotalFiles uint64
	FreeFiles  uint64
	NameMax    uint32
}
