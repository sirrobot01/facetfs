package sftp

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"path"
	"slices"
	"strings"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
	"golang.org/x/text/unicode/norm"
)

const (
	maxSymlinkDepth = 40
	directoryPage   = 256
	allShares       = facetfs.ShareRead | facetfs.ShareWrite | facetfs.ShareDelete
)

type handler struct {
	ctx                 context.Context
	server              *facetfs.Server
	exportID            string
	request             facetfs.Request
	atomicRename        bool
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
	flags := request.Pflags()
	access := facetfs.OpenAccess(0)
	if flags.Read {
		access |= facetfs.OpenRead
	}
	if flags.Write || flags.Append {
		access |= facetfs.OpenWrite
	}
	if access == 0 {
		return nil, pkgsftp.ErrSSHFxBadMessage
	}
	options := facetfs.OpenOptions{Access: access, Share: allShares}
	object, _, _, err := h.resolve(request.Context(), request.Filepath, true)
	var handle facetfs.Handle
	if err == nil {
		if flags.Creat && flags.Excl {
			return nil, pkgsftp.ErrSSHFxFailure
		}
		handle, err = h.server.Open(request.Context(), h.request, object, options)
	} else if errors.Is(err, facetfs.ErrNotFound) && flags.Creat {
		parent, name, parentErr := h.parent(request.Context(), request.Filepath)
		if parentErr != nil {
			return nil, wireError(parentErr)
		}
		create := facetfs.CreateOptions{Open: options, Exclusive: flags.Excl}
		attributeFlags := request.AttrFlags()
		if attributeFlags.Permissions {
			mode := request.Attributes().FileMode().Perm()
			create.Attr.Mode = &mode
		}
		_, handle, _, err = h.server.Create(request.Context(), h.request, parent, name, create)
	}
	if err != nil {
		return nil, wireError(err)
	}
	opened := &openFile{ctx: request.Context(), server: h.server, request: h.request, handle: handle, append: flags.Append}
	opened.mutable, _ = handle.(facetfs.MutableHandle)
	if access&facetfs.OpenWrite != 0 && opened.mutable == nil {
		_ = handle.Close(context.WithoutCancel(request.Context()))
		return nil, pkgsftp.ErrSSHFxOpUnsupported
	}
	if flags.Trunc {
		size := int64(0)
		if _, err := opened.mutable.SetAttr(request.Context(), facetfs.SetAttr{Size: &size}); err != nil {
			_ = opened.Close()
			return nil, wireError(err)
		}
	}
	return opened, nil
}

func (h *handler) Filelist(request *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	switch request.Method {
	case "List":
		object, attr, _, err := h.resolve(request.Context(), request.Filepath, true)
		if err != nil {
			return nil, wireError(err)
		}
		if attr.Type != facetfs.NodeTypeDirectory {
			return nil, wireError(facetfs.ErrNotDirectory)
		}
		handle, err := h.server.Open(request.Context(), h.request, object, facetfs.OpenOptions{Access: facetfs.OpenRead, Share: allShares})
		if err != nil {
			return nil, wireError(err)
		}
		entries := make([]fs.FileInfo, 0, directoryPage)
		var cursor facetfs.DirCursor
		for {
			page, err := h.server.ReadDir(request.Context(), h.request, object, cursor, directoryPage)
			if err != nil {
				_ = handle.Close(context.WithoutCancel(request.Context()))
				return nil, wireError(err)
			}
			for _, entry := range page.Entries {
				if len(entries) >= h.maxDirectoryEntries {
					_ = handle.Close(context.WithoutCancel(request.Context()))
					return nil, pkgsftp.ErrSSHFxFailure
				}
				entries = append(entries, fileInfo{name: entry.Name, attr: entry.Attr})
			}
			if page.Next == "" {
				return &fileList{entries: entries, handle: handle, ctx: request.Context()}, nil
			}
			cursor = page.Next
		}
	case "Stat":
		_, attr, segments, err := h.resolve(request.Context(), request.Filepath, true)
		if err != nil {
			return nil, wireError(err)
		}
		return fileList{entries: []fs.FileInfo{fileInfo{name: baseName(segments), attr: attr}}}, nil
	default:
		return nil, pkgsftp.ErrSSHFxOpUnsupported
	}
}

func (h *handler) Lstat(request *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	_, attr, segments, err := h.resolve(request.Context(), request.Filepath, false)
	if err != nil {
		return nil, wireError(err)
	}
	return fileList{entries: []fs.FileInfo{fileInfo{name: baseName(segments), attr: attr}}}, nil
}

func (h *handler) Readlink(name string) (string, error) {
	object, attr, _, err := h.resolve(h.ctx, name, false)
	if err != nil {
		return "", wireError(err)
	}
	if attr.Type != facetfs.NodeTypeSymlink {
		return "", wireError(facetfs.ErrInvalid)
	}
	target, err := h.server.Readlink(h.ctx, h.request, object)
	return target, wireError(err)
}

func (h *handler) RealPath(name string) (string, error) {
	_, _, segments, err := h.resolve(h.ctx, name, true)
	if err != nil {
		return "", wireError(err)
	}
	if len(segments) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(segments, "/"), nil
}

func (h *handler) Filecmd(request *pkgsftp.Request) error {
	ctx := request.Context()
	switch request.Method {
	case "Setstat":
		object, _, _, err := h.resolve(ctx, request.Filepath, true)
		if err != nil {
			return wireError(err)
		}
		set, err := setAttributes(request)
		if err != nil {
			return err
		}
		_, err = h.server.SetAttr(ctx, h.request, object, set)
		return wireError(err)
	case "Mkdir":
		parent, name, err := h.parent(ctx, request.Filepath)
		if err != nil {
			return wireError(err)
		}
		set, err := setAttributes(request)
		if err != nil {
			return err
		}
		_, _, err = h.server.Mkdir(ctx, h.request, parent, name, set)
		return wireError(err)
	case "Rmdir", "Remove":
		parent, name, err := h.parent(ctx, request.Filepath)
		if err != nil {
			return wireError(err)
		}
		kind := facetfs.RemoveFile
		if request.Method == "Rmdir" {
			kind = facetfs.RemoveDirectory
		}
		return wireError(h.server.Remove(ctx, h.request, parent, name, kind))
	case "Rename":
		return h.rename(ctx, request.Filepath, request.Target, false)
	case "Link":
		object, _, _, err := h.resolve(ctx, request.Filepath, false)
		if err != nil {
			return wireError(err)
		}
		parent, name, err := h.parent(ctx, request.Target)
		if err != nil {
			return wireError(err)
		}
		return wireError(h.server.Link(ctx, h.request, object, parent, name))
	case "Symlink":
		parent, name, err := h.parent(ctx, request.Target)
		if err != nil {
			return wireError(err)
		}
		_, _, err = h.server.Symlink(ctx, h.request, parent, name, request.Filepath, facetfs.SetAttr{})
		return wireError(err)
	default:
		return pkgsftp.ErrSSHFxOpUnsupported
	}
}

func (h *handler) PosixRename(request *pkgsftp.Request) error {
	if !h.atomicRename {
		return pkgsftp.ErrSSHFxOpUnsupported
	}
	return h.rename(request.Context(), request.Filepath, request.Target, true)
}

func (h *handler) rename(ctx context.Context, source, target string, replace bool) error {
	sourceParent, sourceName, err := h.parent(ctx, source)
	if err != nil {
		return wireError(err)
	}
	targetParent, targetName, err := h.parent(ctx, target)
	if err != nil {
		return wireError(err)
	}
	return wireError(h.server.Rename(ctx, h.request, sourceParent, sourceName, targetParent, targetName, facetfs.RenameOptions{Replace: replace}))
}

func (h *handler) StatVFS(request *pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	object, _, _, err := h.resolve(request.Context(), request.Filepath, true)
	if err != nil {
		return nil, wireError(err)
	}
	stat, err := h.server.StatFS(request.Context(), h.request, object)
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
		Namemax: stat.NameMax,
	}, nil
}

func (h *handler) resolve(ctx context.Context, name string, followFinal bool) (facetfs.ObjectRef, facetfs.Attr, []string, error) {
	pending, err := pathSegments(name)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
	}
	object, attr, err := h.server.Root(ctx, h.request, h.exportID)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
	}
	resolved := make([]string, 0, len(pending))
	for followed := 0; len(pending) > 0; {
		segment := pending[0]
		pending = pending[1:]
		child, childAttr, err := h.server.Lookup(ctx, h.request, object, segment)
		if err != nil {
			return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
		}
		if childAttr.Type != facetfs.NodeTypeSymlink || len(pending) == 0 && !followFinal {
			object, attr = child, childAttr
			resolved = append(resolved, segment)
			continue
		}
		followed++
		if followed > maxSymlinkDepth {
			return facetfs.ObjectRef{}, facetfs.Attr{}, nil, facetfs.ErrInvalid
		}
		target, err := h.server.Readlink(ctx, h.request, child)
		if err != nil {
			return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
		}
		base := resolved
		if strings.HasPrefix(target, "/") {
			base = nil
		}
		combined := slices.Concat(base, strings.Split(target, "/"), pending)
		pending, err = pathSegments("/" + strings.Join(combined, "/"))
		if err != nil {
			return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
		}
		object, attr, err = h.server.Root(ctx, h.request, h.exportID)
		if err != nil {
			return facetfs.ObjectRef{}, facetfs.Attr{}, nil, err
		}
		resolved = resolved[:0]
	}
	return object, attr, resolved, nil
}

func (h *handler) parent(ctx context.Context, name string) (facetfs.ObjectRef, string, error) {
	segments, err := pathSegments(name)
	if err != nil || len(segments) == 0 {
		if err == nil {
			err = facetfs.ErrInvalid
		}
		return facetfs.ObjectRef{}, "", err
	}
	parentPath := "/" + strings.Join(segments[:len(segments)-1], "/")
	parent, attr, _, err := h.resolve(ctx, parentPath, true)
	if err != nil {
		return facetfs.ObjectRef{}, "", err
	}
	if attr.Type != facetfs.NodeTypeDirectory {
		return facetfs.ObjectRef{}, "", facetfs.ErrNotDirectory
	}
	return parent, segments[len(segments)-1], nil
}

func pathSegments(name string) ([]string, error) {
	cleaned := path.Clean("/" + name)
	if cleaned == "/" {
		return nil, nil
	}
	segments := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	for _, segment := range segments {
		if err := names.Validate(segment); err != nil || strings.Contains(segment, "\\") || !norm.NFC.IsNormalString(segment) {
			return nil, facetfs.ErrInvalid
		}
	}
	return segments, nil
}

func setAttributes(request *pkgsftp.Request) (facetfs.SetAttr, error) {
	flags := request.AttrFlags()
	if flags.UidGid {
		return facetfs.SetAttr{}, pkgsftp.ErrSSHFxOpUnsupported
	}
	attributes := request.Attributes()
	var set facetfs.SetAttr
	if flags.Size {
		if attributes.Size > math.MaxInt64 {
			return facetfs.SetAttr{}, pkgsftp.ErrSSHFxBadMessage
		}
		size := int64(attributes.Size)
		set.Size = &size
	}
	if flags.Permissions {
		mode := attributes.FileMode().Perm()
		set.Mode = &mode
	}
	if flags.Acmodtime {
		accessed := attributes.AccessTime()
		modified := attributes.ModTime()
		set.AccessedAt = &accessed
		set.ModifiedAt = &modified
	}
	return set, nil
}

func wireError(err error) error {
	if err == nil {
		return nil
	}
	switch facetfs.CodeOf(err) {
	case facetfs.ErrNotFound, facetfs.ErrStaleObject:
		return pkgsftp.ErrSSHFxNoSuchFile
	case facetfs.ErrAccessDenied, facetfs.ErrAuthenticationRequired, facetfs.ErrReadOnly,
		facetfs.ErrLockConflict, facetfs.ErrWouldBlock:
		return pkgsftp.ErrSSHFxPermissionDenied
	case facetfs.ErrNotSupported:
		return pkgsftp.ErrSSHFxOpUnsupported
	case facetfs.ErrInvalid, facetfs.ErrNameTooLong:
		return pkgsftp.ErrSSHFxBadMessage
	default:
		return pkgsftp.ErrSSHFxFailure
	}
}

func baseName(segments []string) string {
	if len(segments) == 0 {
		return "/"
	}
	return segments[len(segments)-1]
}

type fileInfo struct {
	name string
	attr facetfs.Attr
}

func (f fileInfo) Name() string       { return f.name }
func (f fileInfo) Size() int64        { return f.attr.Size }
func (f fileInfo) ModTime() time.Time { return f.attr.ModifiedAt }
func (f fileInfo) IsDir() bool        { return f.attr.Type == facetfs.NodeTypeDirectory }
func (f fileInfo) Sys() any           { return nil }

func (f fileInfo) Mode() fs.FileMode {
	mode := f.attr.Mode
	switch f.attr.Type {
	case facetfs.NodeTypeDirectory:
		mode |= fs.ModeDir
	case facetfs.NodeTypeSymlink:
		mode |= fs.ModeSymlink
	}
	return mode
}

type fileList struct {
	entries []fs.FileInfo
	handle  facetfs.Handle
	ctx     context.Context
}

func (l fileList) ListAt(destination []fs.FileInfo, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(l.entries)) {
		return 0, io.EOF
	}
	n := copy(destination, l.entries[offset:])
	if int(offset)+n == len(l.entries) {
		return n, io.EOF
	}
	return n, nil
}

func (l *fileList) Close() error {
	if l.handle == nil {
		return nil
	}
	return wireError(l.handle.Close(context.WithoutCancel(l.ctx)))
}
