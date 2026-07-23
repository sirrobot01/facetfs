package osfs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
	"github.com/sirrobot01/facetfs/internal/token"
)

type record struct {
	id         facetfs.NodeID
	generation uint64
	info       fs.FileInfo
	paths      map[string]struct{}
	open       uint64
	revision   uint64
	// mode overrides the permission bits reported by fileAttr when modeSet is
	// true. It is only consulted on platforms that cannot store Unix modes
	// natively (see modeOverlay), where the host filesystem loses the value.
	mode    fs.FileMode
	modeSet bool
}

type FS struct {
	root      string
	mu        sync.Mutex
	namespace sync.Mutex
	records   map[facetfs.NodeID]*record
	paths     map[string]*record
	sequence  uint64
	revision  uint64
	handles   uint64
	cursors   token.Codec
}

var _ facetfs.MutableBackend = (*FS)(nil)

func New(root string) (*FS, error) {
	path, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, mapError(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, mapError(err)
	}
	if !info.IsDir() {
		return nil, facetfs.ErrNotDirectory
	}
	f := &FS{
		root:    filepath.Clean(path),
		records: make(map[facetfs.NodeID]*record),
		paths:   make(map[string]*record),
		cursors: token.New(),
	}
	f.track(path, info)
	return f, nil
}

func (f *FS) Capabilities(ctx context.Context) (facetfs.Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Capabilities{}, err
	}
	return facetfs.Capabilities{
		StableObjectIDs: true,
		AtomicRename:    true,
		HardLinks:       hardLinks,
		Symlinks:        symlinks,
		CaseSensitive:   caseSensitive,
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
	info, err := os.Lstat(f.root)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	record := f.track(f.root, info)
	return objectRef(exportID, record), f.fileAttr(record, info), nil
}

func (f *FS) Lookup(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	path, info, _, err := f.resolve(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if !info.IsDir() {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotDirectory
	}
	path = filepath.Join(path, name)
	info, err = os.Lstat(path)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	record := f.track(path, info)
	return objectRef(parent.ExportID, record), f.fileAttr(record, info), nil
}

func (f *FS) GetAttr(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, _ facetfs.AttrMask) (facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Attr{}, err
	}
	_, info, record, err := f.resolve(object)
	if err != nil {
		return facetfs.Attr{}, err
	}
	return f.fileAttr(record, info), nil
}

func (f *FS) ReadDir(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, cursor facetfs.DirCursor, limit int) (facetfs.DirPage, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.DirPage{}, err
	}
	if limit < 1 {
		return facetfs.DirPage{}, facetfs.ErrInvalid
	}
	path, info, record, err := f.resolve(object)
	if err != nil {
		return facetfs.DirPage{}, err
	}
	if !info.IsDir() {
		return facetfs.DirPage{}, facetfs.ErrNotDirectory
	}
	after := ""
	if cursor != "" {
		revision, name, ok := f.parseCursor(cursor)
		if !ok || revision != f.recordRevision(record) {
			return facetfs.DirPage{}, facetfs.ErrStaleCursor
		}
		after = name
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return facetfs.DirPage{}, mapError(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	page := facetfs.DirPage{Entries: make([]facetfs.DirEntry, 0, min(limit, len(entries)))}
	more := false
	for _, entry := range entries {
		if entry.Name() <= after {
			continue
		}
		if len(page.Entries) == limit {
			more = true
			break
		}
		entryInfo, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil {
			return facetfs.DirPage{}, mapError(err)
		}
		entryRecord := f.track(filepath.Join(path, entry.Name()), entryInfo)
		page.Entries = append(page.Entries, facetfs.DirEntry{
			Name: entry.Name(), Object: objectRef(object.ExportID, entryRecord), Attr: f.fileAttr(entryRecord, entryInfo),
		})
	}
	if more {
		page.Next = f.cursor(f.recordRevision(record), page.Entries[len(page.Entries)-1].Name)
	}
	return page, nil
}

func (f *FS) Readlink(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, info, _, err := f.resolve(object)
	if err != nil {
		return "", err
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return "", facetfs.ErrInvalid
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", mapError(err)
	}
	return target, nil
}

func (f *FS) StatFS(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef) (facetfs.FSStat, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.FSStat{}, err
	}
	path, _, _, err := f.resolve(object)
	if err != nil {
		return facetfs.FSStat{}, err
	}
	return statFS(path)
}

func (f *FS) resolve(object facetfs.ObjectRef) (string, fs.FileInfo, *record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.records[object.NodeID]
	if object.ExportID == "" || record == nil || record.generation != object.Generation {
		return "", nil, nil, facetfs.ErrStaleObject
	}
	for path := range record.paths {
		info, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, record.info) {
			delete(record.paths, path)
			delete(f.paths, path)
			continue
		}
		if info.Size() != record.info.Size() || info.Mode() != record.info.Mode() || !info.ModTime().Equal(record.info.ModTime()) {
			f.revision++
			record.revision = f.revision
			record.info = info
		}
		return path, info, record, nil
	}
	if record.open == 0 {
		delete(f.records, record.id)
	}
	return "", nil, nil, facetfs.ErrStaleObject
}

func (f *FS) track(path string, info fs.FileInfo) *record {
	path = filepath.Clean(path)
	f.mu.Lock()
	defer f.mu.Unlock()
	if record := f.paths[path]; record != nil && os.SameFile(info, record.info) {
		record.info = info
		return record
	}
	if record := f.paths[path]; record != nil {
		delete(record.paths, path)
		delete(f.paths, path)
		if len(record.paths) == 0 && record.open == 0 {
			delete(f.records, record.id)
		}
	}
	for _, record := range f.records {
		if os.SameFile(info, record.info) {
			record.paths[path] = struct{}{}
			f.paths[path] = record
			f.revision++
			record.revision = f.revision
			record.info = info
			return record
		}
	}
	f.sequence++
	f.revision++
	record := &record{
		id:         facetfs.NodeID(strconv.FormatUint(f.sequence, 10)),
		generation: 1,
		info:       info,
		paths:      map[string]struct{}{path: {}},
		revision:   f.revision,
	}
	f.records[record.id] = record
	f.paths[path] = record
	return record
}

func (f *FS) changed(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.paths[filepath.Clean(path)]
	if record == nil {
		return
	}
	f.revision++
	record.revision = f.revision
	record.info = info
}

// overrideMode records the permission bits a caller requested so fileAttr can
// report them on platforms whose host filesystem cannot store Unix modes. It is
// a no-op elsewhere, where the mode is read back from the host directly.
func (f *FS) overrideMode(record *record, mode fs.FileMode) {
	if !modeOverlay {
		return
	}
	f.mu.Lock()
	record.mode = mode
	record.modeSet = true
	f.mu.Unlock()
}

func (f *FS) changedRecord(record *record, info fs.FileInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revision++
	record.revision = f.revision
	record.info = info
}

func (f *FS) removed(path string) {
	path = filepath.Clean(path)
	f.mu.Lock()
	defer f.mu.Unlock()
	record := f.paths[path]
	if record == nil {
		return
	}
	delete(record.paths, path)
	delete(f.paths, path)
	f.revision++
	record.revision = f.revision
	if len(record.paths) == 0 && record.open == 0 {
		delete(f.records, record.id)
	}
}

func objectRef(exportID string, record *record) facetfs.ObjectRef {
	return facetfs.ObjectRef{ExportID: exportID, NodeID: record.id, Generation: record.generation}
}

func (f *FS) fileAttr(record *record, info fs.FileInfo) facetfs.Attr {
	kind := facetfs.NodeTypeRegular
	if info.IsDir() {
		kind = facetfs.NodeTypeDirectory
	} else if info.Mode()&fs.ModeSymlink != 0 {
		kind = facetfs.NodeTypeSymlink
	}
	mode := info.Mode()
	f.mu.Lock()
	links := uint32(len(record.paths))
	revision := record.revision
	if modeOverlay && record.modeSet {
		mode = (mode &^ fs.ModePerm) | (record.mode & fs.ModePerm)
	}
	f.mu.Unlock()
	if links == 0 {
		links = 1
	}
	return facetfs.Attr{
		Type:           kind,
		Size:           info.Size(),
		AllocationSize: info.Size(),
		Mode:           mode,
		LinkCount:      links,
		ModifiedAt:     info.ModTime(),
		ChangedAt:      info.ModTime(),
		CreatedAt:      info.ModTime(),
		ChangeToken:    fmt.Sprintf("%d:%d", revision, info.ModTime().UnixNano()),
		FileID:         record.id,
		Generation:     record.generation,
	}
}

func (f *FS) recordRevision(record *record) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return record.revision
}
