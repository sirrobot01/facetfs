package facetfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// NewMemFS returns a new in-memory FileSystem for testing and prototyping.
// It implements SymlinkFS, SetStatFS, and StatVFSFS (with synthetic capacity
// numbers), and its files implement io.ReaderAt and io.WriterAt. It is not
// durable.
func NewMemFS() FileSystem {
	return &memFS{
		root: &memNode{
			mode:     fs.ModeDir | 0o755,
			modTime:  time.Now(),
			children: map[string]*memNode{},
		},
	}
}

type memFS struct {
	mu   sync.RWMutex
	root *memNode
}

type memNode struct {
	mode     fs.FileMode
	modTime  time.Time
	data     []byte
	link     string
	children map[string]*memNode
}

func (n *memNode) info(name string) fs.FileInfo {
	size := int64(len(n.data))
	if n.mode&fs.ModeSymlink != 0 {
		size = int64(len(n.link))
	}
	return &memInfo{name: name, size: size, mode: n.mode, modTime: n.modTime}
}

type memInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

func (i *memInfo) Name() string       { return i.name }
func (i *memInfo) Size() int64        { return i.size }
func (i *memInfo) Mode() fs.FileMode  { return i.mode }
func (i *memInfo) ModTime() time.Time { return i.modTime }
func (i *memInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *memInfo) Sys() any           { return nil }

var errTooManyLinks = errors.New("too many levels of symbolic links")

// lookup resolves p to a node, following symlinks in intermediate components
// and, when follow is true, in the final component. Callers hold m.mu.
func (m *memFS) lookup(p string, follow bool, depth *int) (*memNode, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return m.root, nil
	}
	segments := strings.Split(p[1:], "/")
	node := m.root
	for i, segment := range segments {
		if !node.mode.IsDir() {
			return nil, fs.ErrNotExist
		}
		child, ok := node.children[segment]
		if !ok {
			return nil, fs.ErrNotExist
		}
		last := i == len(segments)-1
		if child.mode&fs.ModeSymlink != 0 && (!last || follow) {
			*depth++
			if *depth > 40 {
				return nil, errTooManyLinks
			}
			target := child.link
			if !path.IsAbs(target) {
				target = path.Join("/", strings.Join(segments[:i], "/"), target)
			}
			return m.lookup(path.Join(target, strings.Join(segments[i+1:], "/")), follow, depth)
		}
		node = child
	}
	return node, nil
}

func (m *memFS) resolve(p string, follow bool) (*memNode, error) {
	depth := 0
	return m.lookup(p, follow, &depth)
}

// parentOf resolves the directory containing p. Callers hold m.mu.
func (m *memFS) parentOf(p string) (*memNode, string, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return nil, "", fs.ErrInvalid
	}
	dir, base := path.Split(p)
	parent, err := m.resolve(dir, true)
	if err != nil {
		return nil, "", err
	}
	if !parent.mode.IsDir() {
		return nil, "", fs.ErrNotExist
	}
	return parent, base, nil
}

func pathError(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func (m *memFS) Mkdir(ctx context.Context, name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, base, err := m.parentOf(name)
	if err != nil {
		return pathError("mkdir", name, err)
	}
	if _, ok := parent.children[base]; ok {
		return pathError("mkdir", name, fs.ErrExist)
	}
	parent.children[base] = &memNode{
		mode:     fs.ModeDir | perm.Perm(),
		modTime:  time.Now(),
		children: map[string]*memNode{},
	}
	parent.modTime = time.Now()
	return nil
}

func (m *memFS) OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	writable := flag&(os.O_WRONLY|os.O_RDWR) != 0
	readable := flag&os.O_WRONLY == 0

	node, err := m.resolve(name, true)
	switch {
	case err == nil:
		if flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0 {
			return nil, pathError("open", name, fs.ErrExist)
		}
	case errors.Is(err, fs.ErrNotExist) && flag&os.O_CREATE != 0:
		parent, base, perr := m.parentOf(name)
		if perr != nil {
			return nil, pathError("open", name, perr)
		}
		node = &memNode{mode: perm.Perm(), modTime: time.Now()}
		parent.children[base] = node
		parent.modTime = time.Now()
	default:
		return nil, pathError("open", name, err)
	}

	if node.mode.IsDir() && writable {
		return nil, pathError("open", name, fs.ErrInvalid)
	}
	if flag&os.O_TRUNC != 0 && !node.mode.IsDir() {
		node.data = nil
		node.modTime = time.Now()
	}
	return &memFile{
		fsys:     m,
		node:     node,
		name:     path.Base(path.Clean("/" + name)),
		readable: readable,
		writable: writable,
		appendTo: flag&os.O_APPEND != 0,
	}, nil
}

func (m *memFS) RemoveAll(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if path.Clean("/"+name) == "/" {
		return pathError("removeall", name, fs.ErrInvalid)
	}
	parent, base, err := m.parentOf(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return pathError("removeall", name, err)
	}
	if _, ok := parent.children[base]; ok {
		delete(parent.children, base)
		parent.modTime = time.Now()
	}
	return nil
}

func (m *memFS) Rename(ctx context.Context, oldName, newName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	from := path.Clean("/" + oldName)
	to := path.Clean("/" + newName)
	if from == "/" || to == "/" || strings.HasPrefix(to+"/", from+"/") {
		return pathError("rename", oldName, fs.ErrInvalid)
	}
	oldParent, oldBase, err := m.parentOf(from)
	if err != nil {
		return pathError("rename", oldName, err)
	}
	node, ok := oldParent.children[oldBase]
	if !ok {
		return pathError("rename", oldName, fs.ErrNotExist)
	}
	newParent, newBase, err := m.parentOf(to)
	if err != nil {
		return pathError("rename", newName, err)
	}
	if existing, ok := newParent.children[newBase]; ok {
		if existing.mode.IsDir() && len(existing.children) > 0 {
			return pathError("rename", newName, fs.ErrExist)
		}
	}
	delete(oldParent.children, oldBase)
	newParent.children[newBase] = node
	now := time.Now()
	oldParent.modTime = now
	newParent.modTime = now
	return nil
}

func (m *memFS) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, err := m.resolve(name, true)
	if err != nil {
		return nil, pathError("stat", name, err)
	}
	return node.info(path.Base(path.Clean("/" + name))), nil
}

func (m *memFS) Lstat(ctx context.Context, name string) (fs.FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, err := m.resolve(name, false)
	if err != nil {
		return nil, pathError("lstat", name, err)
	}
	return node.info(path.Base(path.Clean("/" + name))), nil
}

func (m *memFS) Symlink(ctx context.Context, oldname, newname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, base, err := m.parentOf(newname)
	if err != nil {
		return pathError("symlink", newname, err)
	}
	if _, ok := parent.children[base]; ok {
		return pathError("symlink", newname, fs.ErrExist)
	}
	parent.children[base] = &memNode{
		mode:    fs.ModeSymlink | 0o777,
		modTime: time.Now(),
		link:    oldname,
	}
	parent.modTime = time.Now()
	return nil
}

func (m *memFS) Readlink(ctx context.Context, name string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	node, err := m.resolve(name, false)
	if err != nil {
		return "", pathError("readlink", name, err)
	}
	if node.mode&fs.ModeSymlink == 0 {
		return "", pathError("readlink", name, fs.ErrInvalid)
	}
	return node.link, nil
}

func (m *memFS) Chmod(ctx context.Context, name string, mode fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true)
	if err != nil {
		return pathError("chmod", name, err)
	}
	node.mode = node.mode&^fs.ModePerm | mode.Perm()
	return nil
}

func (m *memFS) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true)
	if err != nil {
		return pathError("chtimes", name, err)
	}
	node.modTime = mtime
	return nil
}

func (m *memFS) Truncate(ctx context.Context, name string, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true)
	if err != nil {
		return pathError("truncate", name, err)
	}
	if node.mode.IsDir() || size < 0 {
		return pathError("truncate", name, fs.ErrInvalid)
	}
	node.setSize(size)
	return nil
}

// StatVFS reports synthetic capacity: the filesystem is bounded only by
// process memory.
func (m *memFS) StatVFS(ctx context.Context, name string) (FSStat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, err := m.resolve(name, true); err != nil {
		return FSStat{}, pathError("statvfs", name, err)
	}
	const total = 1 << 33
	return FSStat{
		TotalBytes: total,
		FreeBytes:  total / 2,
		AvailBytes: total / 2,
		TotalFiles: 1 << 20,
		FreeFiles:  1 << 19,
		NameMax:    255,
	}, nil
}

func (n *memNode) setSize(size int64) {
	if size <= int64(len(n.data)) {
		n.data = n.data[:size]
	} else {
		n.data = append(n.data, make([]byte, size-int64(len(n.data)))...)
	}
	n.modTime = time.Now()
}

type memFile struct {
	fsys     *memFS
	node     *memNode
	name     string
	readable bool
	writable bool
	appendTo bool

	mu      sync.Mutex
	pos     int64
	dirEnts []fs.FileInfo
	dirPos  int
	closed  bool
}

func (f *memFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return fs.ErrClosed
	}
	f.closed = true
	return nil
}

func (f *memFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.readAt(p, f.pos)
	f.pos += int64(n)
	return n, err
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readAt(p, off)
}

func (f *memFile) readAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, fs.ErrClosed
	}
	if !f.readable {
		return 0, fs.ErrPermission
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	f.fsys.mu.RLock()
	defer f.fsys.mu.RUnlock()
	if f.node.mode.IsDir() {
		return 0, fs.ErrInvalid
	}
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if !f.writable {
		return 0, fs.ErrPermission
	}
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.appendTo {
		f.pos = int64(len(f.node.data))
	}
	n := f.node.writeAt(p, f.pos)
	f.pos += int64(n)
	return n, nil
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	if !f.writable {
		return 0, fs.ErrPermission
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return f.node.writeAt(p, off), nil
}

func (n *memNode) writeAt(p []byte, off int64) int {
	if grow := off + int64(len(p)) - int64(len(n.data)); grow > 0 {
		n.data = append(n.data, make([]byte, grow)...)
	}
	copy(n.data[off:], p)
	n.modTime = time.Now()
	return len(p)
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, fs.ErrClosed
	}
	f.fsys.mu.RLock()
	size := int64(len(f.node.data))
	f.fsys.mu.RUnlock()
	var pos int64
	switch whence {
	case io.SeekStart:
		pos = offset
	case io.SeekCurrent:
		pos = f.pos + offset
	case io.SeekEnd:
		pos = size + offset
	default:
		return 0, fs.ErrInvalid
	}
	if pos < 0 {
		return 0, fs.ErrInvalid
	}
	f.pos = pos
	return pos, nil
}

func (f *memFile) Readdir(count int) ([]fs.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, fs.ErrClosed
	}
	f.fsys.mu.RLock()
	if !f.node.mode.IsDir() {
		f.fsys.mu.RUnlock()
		return nil, fs.ErrInvalid
	}
	if f.dirEnts == nil {
		names := make([]string, 0, len(f.node.children))
		for name := range f.node.children {
			names = append(names, name)
		}
		slices.Sort(names)
		f.dirEnts = make([]fs.FileInfo, 0, len(names))
		for _, name := range names {
			f.dirEnts = append(f.dirEnts, f.node.children[name].info(name))
		}
	}
	f.fsys.mu.RUnlock()

	remaining := f.dirEnts[f.dirPos:]
	if count <= 0 {
		f.dirPos = len(f.dirEnts)
		return remaining, nil
	}
	if len(remaining) == 0 {
		return nil, io.EOF
	}
	if count > len(remaining) {
		count = len(remaining)
	}
	f.dirPos += count
	return remaining[:count], nil
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, fs.ErrClosed
	}
	f.fsys.mu.RLock()
	defer f.fsys.mu.RUnlock()
	return f.node.info(f.name), nil
}
