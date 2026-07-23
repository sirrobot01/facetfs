package memfs

import (
	"context"
	"io/fs"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
	"github.com/sirrobot01/facetfs/internal/token"
)

const maxFileSize = 64 << 20

var _ facetfs.MutableBackend = (*FS)(nil)

type node struct {
	id         facetfs.NodeID
	generation uint64
	kind       facetfs.NodeType
	mode       fs.FileMode
	owner      string
	group      string
	data       []byte
	target     string
	children   map[string]facetfs.NodeID
	links      uint32
	open       uint64
	created    time.Time
	accessed   time.Time
	modified   time.Time
	changed    time.Time
	revision   uint64
}

type FS struct {
	mu       sync.RWMutex
	nodes    map[facetfs.NodeID]*node
	root     facetfs.NodeID
	cursors  token.Codec
	sequence uint64
	revision uint64
	handles  uint64
}

func New() *FS {
	f := &FS{
		nodes:   make(map[facetfs.NodeID]*node),
		cursors: token.New(),
	}
	root := f.makeNode(facetfs.NodeTypeDirectory, 0o755)
	f.root = root.id
	return f
}

func (f *FS) Capabilities(ctx context.Context) (facetfs.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Capabilities{}, err
	}
	return facetfs.Capabilities{
		StableObjectIDs: true,
		AtomicRename:    true,
		HardLinks:       true,
		Symlinks:        true,
		CaseSensitive:   true,
		CasePreserving:  true,
	}, nil
}

func (f *FS) Root(ctx context.Context, _ facetfs.Request, exportID string) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if exportID == "" {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrInvalid
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := f.nodes[f.root]
	return ref(exportID, n), attr(n), nil
}

func (f *FS) Lookup(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	dir, err := f.directory(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	id, ok := dir.children[name]
	if !ok {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotFound
	}
	n := f.nodes[id]
	return ref(parent.ExportID, n), attr(n), nil
}

func (f *FS) GetAttr(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, _ facetfs.AttrMask) (facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Attr{}, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.node(object)
	if err != nil {
		return facetfs.Attr{}, err
	}
	return attr(n), nil
}

func (f *FS) ReadDir(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, cursor facetfs.DirCursor, limit int) (facetfs.DirPage, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.DirPage{}, err
	}
	if limit < 1 {
		return facetfs.DirPage{}, facetfs.ErrInvalid
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	dir, err := f.directory(object)
	if err != nil {
		return facetfs.DirPage{}, err
	}

	after := ""
	if cursor != "" {
		revision, name, ok := f.parseCursor(cursor)
		if !ok || revision != dir.revision {
			return facetfs.DirPage{}, facetfs.ErrStaleCursor
		}
		after = name
	}

	names := make([]string, 0, len(dir.children))
	for name := range dir.children {
		if name > after {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	more := len(names) > limit
	if more {
		names = names[:limit]
	}
	page := facetfs.DirPage{Entries: make([]facetfs.DirEntry, len(names))}
	for i, name := range names {
		n := f.nodes[dir.children[name]]
		page.Entries[i] = facetfs.DirEntry{Name: name, Object: ref(object.ExportID, n), Attr: attr(n)}
	}
	if more {
		page.Next = f.cursor(dir.revision, names[len(names)-1])
	}
	return page, nil
}

func (f *FS) StatFS(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef) (facetfs.FSStat, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.FSStat{}, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, err := f.node(object); err != nil {
		return facetfs.FSStat{}, err
	}
	const (
		capacity   = uint64(1 << 40)
		totalFiles = uint64(1 << 32)
	)
	var used uint64
	for _, n := range f.nodes {
		used += uint64(len(n.data))
	}
	return facetfs.FSStat{
		TotalBytes: capacity,
		FreeBytes:  capacity - used,
		AvailBytes: capacity - used,
		TotalFiles: totalFiles,
		FreeFiles:  totalFiles - uint64(len(f.nodes)),
		NameMax:    255,
	}, nil
}

func (f *FS) makeNode(kind facetfs.NodeType, mode fs.FileMode) *node {
	f.sequence++
	f.revision++
	now := time.Now().UTC()
	n := &node{
		id:         facetfs.NodeID(strconv.FormatUint(f.sequence, 10)),
		generation: 1,
		kind:       kind,
		mode:       mode.Perm(),
		links:      1,
		created:    now,
		accessed:   now,
		modified:   now,
		changed:    now,
		revision:   f.revision,
	}
	if kind == facetfs.NodeTypeDirectory {
		n.children = make(map[string]facetfs.NodeID)
	}
	f.nodes[n.id] = n
	return n
}

func (f *FS) node(object facetfs.ObjectRef) (*node, error) {
	n := f.nodes[object.NodeID]
	if object.ExportID == "" || n == nil || n.generation != object.Generation {
		return nil, facetfs.ErrStaleObject
	}
	return n, nil
}

func (f *FS) directory(object facetfs.ObjectRef) (*node, error) {
	n, err := f.node(object)
	if err != nil {
		return nil, err
	}
	if n.kind != facetfs.NodeTypeDirectory {
		return nil, facetfs.ErrNotDirectory
	}
	return n, nil
}

func (f *FS) touch(n *node) {
	f.revision++
	n.revision = f.revision
	n.changed = time.Now().UTC()
}

func (f *FS) release(n *node) {
	if n.links == 0 && n.open == 0 {
		delete(f.nodes, n.id)
	}
}

func ref(exportID string, n *node) facetfs.ObjectRef {
	return facetfs.ObjectRef{ExportID: exportID, NodeID: n.id, Generation: n.generation}
}

func attr(n *node) facetfs.Attr {
	size := len(n.data)
	if n.kind == facetfs.NodeTypeSymlink {
		size = len(n.target)
	}
	return facetfs.Attr{
		Type:           n.kind,
		Size:           int64(size),
		AllocationSize: int64(len(n.data)),
		Owner:          n.owner,
		Group:          n.group,
		Mode:           n.mode,
		LinkCount:      n.links,
		AccessedAt:     n.accessed,
		ModifiedAt:     n.modified,
		ChangedAt:      n.changed,
		CreatedAt:      n.created,
		ChangeToken:    strconv.FormatUint(n.revision, 10),
		FileID:         n.id,
		Generation:     n.generation,
	}
}
