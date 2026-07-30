package sftp

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	pkgsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
)

const directoryPage = 256

type handler struct {
	ctx                 context.Context
	fs                  facetfs.FileSystem
	maxDirectoryEntries int
}

func (h *handler) Fileread(request *pkgsftp.Request) (io.ReaderAt, error) {
	return h.open(request)
}

func (h *handler) Filewrite(request *pkgsftp.Request) (io.WriterAt, error) {
	return h.open(request)
}

func (h *handler) OpenFile(request *pkgsftp.Request) (pkgsftp.WriterAtReaderAt, error) {
	return h.open(request)
}

func (h *handler) open(request *pkgsftp.Request) (*openFile, error) {
	p, err := cleanPath(request.Filepath)
	if err != nil {
		return nil, wireError(err)
	}
	flags := request.Pflags()
	read := flags.Read
	write := flags.Write || flags.Append
	var flag int
	switch {
	case read && write:
		flag = os.O_RDWR
	case read:
		flag = os.O_RDONLY
	case write:
		flag = os.O_WRONLY
	default:
		return nil, pkgsftp.ErrSSHFxBadMessage
	}
	if flags.Append {
		flag |= os.O_APPEND
	}
	if flags.Creat {
		flag |= os.O_CREATE
	}
	if flags.Trunc {
		flag |= os.O_TRUNC
	}
	if flags.Excl {
		flag |= os.O_EXCL
	}
	perm := fs.FileMode(0o644)
	if request.AttrFlags().Permissions {
		perm = request.Attributes().FileMode().Perm()
	}
	file, err := h.fs.OpenFile(request.Context(), p, flag, perm)
	if err != nil {
		return nil, wireError(err)
	}
	return newOpenFile(file, flags.Append), nil
}

func (h *handler) Filelist(request *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	p, err := cleanPath(request.Filepath)
	if err != nil {
		return nil, wireError(err)
	}
	switch request.Method {
	case "List":
		return h.list(request.Context(), p)
	case "Stat":
		fi, err := h.fs.Stat(request.Context(), p)
		if err != nil {
			return nil, wireError(err)
		}
		return fileList{fi}, nil
	default:
		return nil, pkgsftp.ErrSSHFxOpUnsupported
	}
}

func (h *handler) list(ctx context.Context, p string) (pkgsftp.ListerAt, error) {
	fi, err := h.fs.Stat(ctx, p)
	if err != nil {
		return nil, wireError(err)
	}
	if !fi.IsDir() {
		return nil, wireError(fs.ErrInvalid)
	}
	dir, err := h.fs.OpenFile(ctx, p, os.O_RDONLY, 0)
	if err != nil {
		return nil, wireError(err)
	}
	defer dir.Close()
	var entries []fs.FileInfo
	for {
		page, err := dir.Readdir(directoryPage)
		entries = append(entries, page...)
		if len(entries) > h.maxDirectoryEntries {
			return nil, pkgsftp.ErrSSHFxFailure
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fileList(entries), nil
			}
			return nil, wireError(err)
		}
		if len(page) == 0 {
			return fileList(entries), nil
		}
	}
}

func (h *handler) Lstat(request *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	p, err := cleanPath(request.Filepath)
	if err != nil {
		return nil, wireError(err)
	}
	fi, err := h.lstat(request.Context(), p)
	if err != nil {
		return nil, wireError(err)
	}
	return fileList{fi}, nil
}

// lstat uses SymlinkFS.Lstat when the filesystem supports it and otherwise
// falls back to Stat.
func (h *handler) lstat(ctx context.Context, p string) (fs.FileInfo, error) {
	if symlinks, ok := h.fs.(facetfs.SymlinkFS); ok {
		return symlinks.Lstat(ctx, p)
	}
	return h.fs.Stat(ctx, p)
}

func (h *handler) Readlink(name string) (string, error) {
	symlinks, ok := h.fs.(facetfs.SymlinkFS)
	if !ok {
		return "", pkgsftp.ErrSSHFxOpUnsupported
	}
	p, err := cleanPath(name)
	if err != nil {
		return "", wireError(err)
	}
	target, err := symlinks.Readlink(h.ctx, p)
	return target, wireError(err)
}

func (h *handler) RealPath(name string) (string, error) {
	p, err := cleanPath(name)
	if err != nil {
		return "", wireError(err)
	}
	return p, nil
}

func (h *handler) Filecmd(request *pkgsftp.Request) error {
	ctx := request.Context()
	p, err := cleanPath(request.Filepath)
	if err != nil {
		return wireError(err)
	}
	switch request.Method {
	case "Setstat":
		return h.setstat(ctx, request, p)
	case "Mkdir":
		perm := fs.FileMode(0o755)
		if request.AttrFlags().Permissions {
			perm = request.Attributes().FileMode().Perm()
		}
		return wireError(h.fs.Mkdir(ctx, p, perm))
	case "Remove":
		fi, err := h.lstat(ctx, p)
		if err != nil {
			return wireError(err)
		}
		if fi.IsDir() {
			return pkgsftp.ErrSSHFxFailure
		}
		return wireError(h.fs.RemoveAll(ctx, p))
	case "Rmdir":
		return h.rmdir(ctx, p)
	case "Rename":
		target, err := cleanPath(request.Target)
		if err != nil {
			return wireError(err)
		}
		// SSH_FXP_RENAME must not replace an existing target. The check is
		// best-effort: the FileSystem's Rename is POSIX and replaces.
		if _, err := h.lstat(ctx, target); err == nil {
			return pkgsftp.ErrSSHFxFailure
		}
		return wireError(h.fs.Rename(ctx, p, target))
	case "Symlink":
		symlinks, ok := h.fs.(facetfs.SymlinkFS)
		if !ok {
			return pkgsftp.ErrSSHFxOpUnsupported
		}
		target, err := cleanPath(request.Target)
		if err != nil {
			return wireError(err)
		}
		return wireError(symlinks.Symlink(ctx, request.Filepath, target))
	default:
		return pkgsftp.ErrSSHFxOpUnsupported
	}
}

func (h *handler) setstat(ctx context.Context, request *pkgsftp.Request, p string) error {
	setstat, ok := h.fs.(facetfs.SetStatFS)
	if !ok {
		return pkgsftp.ErrSSHFxOpUnsupported
	}
	flags := request.AttrFlags()
	if flags.UidGid {
		return pkgsftp.ErrSSHFxOpUnsupported
	}
	attributes := request.Attributes()
	if flags.Size {
		if attributes.Size > 1<<62 {
			return pkgsftp.ErrSSHFxBadMessage
		}
		if err := setstat.Truncate(ctx, p, int64(attributes.Size)); err != nil {
			return wireError(err)
		}
	}
	if flags.Permissions {
		if err := setstat.Chmod(ctx, p, attributes.FileMode().Perm()); err != nil {
			return wireError(err)
		}
	}
	if flags.Acmodtime {
		if err := setstat.Chtimes(ctx, p, attributes.AccessTime(), attributes.ModTime()); err != nil {
			return wireError(err)
		}
	}
	return nil
}

// rmdir removes an empty directory. The emptiness check and the removal are
// separate FileSystem calls, so the operation is best-effort rather than
// atomic.
func (h *handler) rmdir(ctx context.Context, p string) error {
	fi, err := h.fs.Stat(ctx, p)
	if err != nil {
		return wireError(err)
	}
	if !fi.IsDir() {
		return pkgsftp.ErrSSHFxFailure
	}
	dir, err := h.fs.OpenFile(ctx, p, os.O_RDONLY, 0)
	if err != nil {
		return wireError(err)
	}
	entries, err := dir.Readdir(1)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return wireError(err)
	}
	if len(entries) > 0 {
		return pkgsftp.ErrSSHFxFailure
	}
	return wireError(h.fs.RemoveAll(ctx, p))
}

func (h *handler) PosixRename(request *pkgsftp.Request) error {
	source, err := cleanPath(request.Filepath)
	if err != nil {
		return wireError(err)
	}
	target, err := cleanPath(request.Target)
	if err != nil {
		return wireError(err)
	}
	return wireError(h.fs.Rename(request.Context(), source, target))
}

func (h *handler) StatVFS(request *pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	statvfs, ok := h.fs.(facetfs.StatVFSFS)
	if !ok {
		return nil, pkgsftp.ErrSSHFxOpUnsupported
	}
	p, err := cleanPath(request.Filepath)
	if err != nil {
		return nil, wireError(err)
	}
	stat, err := statvfs.StatVFS(request.Context(), p)
	if err != nil {
		return nil, wireError(err)
	}
	const blockSize = 4096
	return &pkgsftp.StatVFS{
		Bsize:   blockSize,
		Frsize:  blockSize,
		Blocks:  stat.TotalBytes/blockSize + min(stat.TotalBytes%blockSize, 1),
		Bfree:   stat.FreeBytes / blockSize,
		Bavail:  stat.AvailBytes / blockSize,
		Files:   stat.TotalFiles,
		Ffree:   stat.FreeFiles,
		Favail:  stat.FreeFiles,
		Namemax: uint64(stat.NameMax),
	}, nil
}

// cleanPath normalizes an SFTP path to a slash-rooted cleaned path and
// validates each segment.
func cleanPath(name string) (string, error) {
	cleaned := path.Clean("/" + name)
	if cleaned == "/" {
		return cleaned, nil
	}
	for segment := range strings.SplitSeq(cleaned[1:], "/") {
		if err := names.Validate(segment); err != nil {
			return "", err
		}
		if strings.Contains(segment, "\\") {
			return "", fs.ErrInvalid
		}
	}
	return cleaned, nil
}

func wireError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		return err
	case errors.Is(err, fs.ErrNotExist):
		return pkgsftp.ErrSSHFxNoSuchFile
	case errors.Is(err, fs.ErrPermission):
		return pkgsftp.ErrSSHFxPermissionDenied
	case errors.Is(err, fs.ErrInvalid):
		return pkgsftp.ErrSSHFxBadMessage
	default:
		return pkgsftp.ErrSSHFxFailure
	}
}

// fileList serves directory entries and stat results to pkg/sftp.
type fileList []fs.FileInfo

func (l fileList) ListAt(destination []fs.FileInfo, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(destination, l[offset:])
	if int(offset)+n == len(l) {
		return n, io.EOF
	}
	return n, nil
}
