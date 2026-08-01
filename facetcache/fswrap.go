package facetcache

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	facetfs "github.com/sirrobot01/facetfs"
)

const writeFlags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC

// statCached answers Stat and Lstat through the attribute cache. Negative
// entries absorb repeated lookups of absent names.
func (f *cfs) statCached(ctx context.Context, name string, lstat bool) (fs.FileInfo, error) {
	if info, found, negative := f.attr.get(name, lstat); found {
		if negative {
			f.attrNegatives.Add(1)
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		f.attrHits.Add(1)
		return info, nil
	}
	f.attrMisses.Add(1)
	var info fs.FileInfo
	var err error
	if lstat {
		info, err = f.symlink.Lstat(ctx, name)
	} else {
		info, err = f.backend.Stat(ctx, name)
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f.attr.storeNegative(name, lstat)
		}
		return nil, err
	}
	f.attr.store(name, lstat, info)
	return info, nil
}

func (f *cfs) invalidateAttr(name string) {
	f.attr.invalidate(name)
}

// invalidateEntry drops the attributes of a name and of its parent, whose
// mtime and link count a mutation changes.
func (f *cfs) invalidateEntry(name string) {
	f.attr.invalidate(name)
	f.attr.invalidate(path.Dir(name))
}

// invalidateTree dooms every cached item at or under name and deletes its
// files. Live handles keep their fd; nothing under name is persisted or
// served to new opens. Mutations are rare next to reads, so a full registry
// and index sweep is acceptable here and keeps the read path free of any
// tree bookkeeping.
func (f *cfs) invalidateTree(name string) {
	prefix := name + "/"
	covers := func(p string) bool { return p == name || strings.HasPrefix(p, prefix) }
	for i := range f.shards {
		s := &f.shards[i]
		s.mu.Lock()
		for p, it := range s.m {
			if !covers(p) {
				continue
			}
			delete(s.m, p)
			it.mu.Lock()
			it.doomLocked()
			it.mu.Unlock()
			if it.opens == 0 {
				if err := it.shutdown(); err != nil {
					f.cache.logf(err)
				}
			}
			f.removeFiles(p)
		}
		s.mu.Unlock()
	}
	var stale []string
	f.jan.mu.Lock()
	for p, e := range f.jan.index {
		if covers(p) {
			stale = append(stale, p)
			f.cachedBytes.Add(-e.bytes)
			delete(f.jan.index, p)
		}
	}
	f.jan.mu.Unlock()
	for _, p := range stale {
		f.removeFiles(p)
	}
}

func (f *cfs) removeFiles(name string) {
	dataPath, metaPath, err := f.cachePaths(name)
	if err != nil {
		return
	}
	os.Remove(dataPath)
	os.Remove(metaPath)
	removeEmptyParents(f.cache.Dir, dataPath)
	removeEmptyParents(f.cache.Dir, metaPath)
}

// Mkdir implements facetfs.FileSystem.
func (f *cfs) Mkdir(ctx context.Context, name string, perm fs.FileMode) error {
	err := f.backend.Mkdir(ctx, name, perm)
	if err == nil {
		f.invalidateEntry(name)
	}
	return err
}

// RemoveAll implements facetfs.FileSystem.
func (f *cfs) RemoveAll(ctx context.Context, name string) error {
	err := f.backend.RemoveAll(ctx, name)
	f.invalidateEntry(name)
	f.invalidateTree(name)
	return err
}

// Rename implements facetfs.FileSystem.
func (f *cfs) Rename(ctx context.Context, oldName, newName string) error {
	err := f.backend.Rename(ctx, oldName, newName)
	f.invalidateEntry(oldName)
	f.invalidateEntry(newName)
	f.invalidateTree(oldName)
	f.invalidateTree(newName)
	return err
}

// Stat implements facetfs.FileSystem.
func (f *cfs) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	return f.statCached(ctx, name, false)
}

// OpenFile implements facetfs.FileSystem. The warm read path performs no
// backend call: the stat comes from the attribute cache and the item from
// the registry.
func (f *cfs) OpenFile(ctx context.Context, name string, flag int, perm fs.FileMode) (facetfs.File, error) {
	if flag&writeFlags != 0 {
		return f.openWrite(ctx, name, flag, perm)
	}
	st, err := f.statCached(ctx, name, false)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		bf, err := f.backend.OpenFile(ctx, name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &dirFile{f: f, name: name, bf: bf}, nil
	}
	if !st.Mode().IsRegular() {
		return f.backend.OpenFile(ctx, name, flag, perm)
	}
	it, err := f.openItem(name, st)
	if err != nil {
		// Cache-disk trouble must not take reads down; serve through.
		f.cache.logf(err)
		return f.backend.OpenFile(ctx, name, flag, perm)
	}
	return &cachedFile{f: f, it: it, base: st}, nil
}

func (f *cfs) openWrite(ctx context.Context, name string, flag int, perm fs.FileMode) (facetfs.File, error) {
	bf, err := f.backend.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	f.invalidateEntry(name)
	var it *item
	if flag&os.O_APPEND != 0 {
		// Append offsets are the backend's secret; the mirror cannot know
		// where bytes land, so the cached copy goes instead of going stale.
		f.invalidateTree(name)
	} else {
		it = f.lookupItem(name)
		if it != nil && flag&os.O_TRUNC != 0 {
			it.truncate(0)
		}
	}
	wf := &writeFile{f: f, name: name, bf: bf, it: it}
	wf.bwa, _ = bf.(interface {
		WriteAt(p []byte, off int64) (int, error)
	})
	wf.bsync, _ = bf.(interface{ Sync() error })
	return wrapWriteFile(wf), nil
}

// Extension method holders. The generated matrix in matrix_gen.go embeds
// them so the wrapper exposes exactly the optional interfaces the backend
// implements; claiming an interface the backend lacks would silently change
// server behavior, and hiding one would degrade it.

type symlinkExt struct{ f *cfs }

// Symlink implements facetfs.SymlinkFS.
func (e symlinkExt) Symlink(ctx context.Context, oldName, newName string) error {
	err := e.f.symlink.Symlink(ctx, oldName, newName)
	if err == nil {
		e.f.invalidateEntry(newName)
	}
	return err
}

// Readlink implements facetfs.SymlinkFS.
func (e symlinkExt) Readlink(ctx context.Context, name string) (string, error) {
	return e.f.symlink.Readlink(ctx, name)
}

// Lstat implements facetfs.SymlinkFS.
func (e symlinkExt) Lstat(ctx context.Context, name string) (fs.FileInfo, error) {
	return e.f.statCached(ctx, name, true)
}

type linkExt struct{ f *cfs }

// Link implements facetfs.LinkFS.
func (e linkExt) Link(ctx context.Context, oldName, newName string) error {
	err := e.f.link.Link(ctx, oldName, newName)
	if err == nil {
		e.f.invalidateEntry(newName)
		e.f.invalidateAttr(oldName)
	}
	return err
}

type removeExt struct{ f *cfs }

// Remove implements facetfs.RemoveFS.
func (e removeExt) Remove(ctx context.Context, name string) error {
	err := e.f.remove.Remove(ctx, name)
	e.f.invalidateEntry(name)
	if err == nil {
		e.f.invalidateTree(name)
	}
	return err
}

type setStatExt struct{ f *cfs }

// Chmod implements facetfs.SetStatFS.
func (e setStatExt) Chmod(ctx context.Context, name string, mode fs.FileMode) error {
	err := e.f.setstat.Chmod(ctx, name, mode)
	e.f.invalidateAttr(name)
	return err
}

// Chtimes implements facetfs.SetStatFS.
func (e setStatExt) Chtimes(ctx context.Context, name string, atime, mtime time.Time) error {
	err := e.f.setstat.Chtimes(ctx, name, atime, mtime)
	e.f.invalidateAttr(name)
	return err
}

// Truncate implements facetfs.SetStatFS.
func (e setStatExt) Truncate(ctx context.Context, name string, size int64) error {
	err := e.f.setstat.Truncate(ctx, name, size)
	e.f.invalidateAttr(name)
	if err != nil {
		return err
	}
	if it := e.f.lookupItem(name); it != nil {
		it.truncate(size)
		e.f.releaseItem(it)
	}
	return nil
}

type statVFSExt struct{ f *cfs }

// StatVFS implements facetfs.StatVFSFS.
func (e statVFSExt) StatVFS(ctx context.Context, name string) (facetfs.FSStat, error) {
	return e.f.statvfs.StatVFS(ctx, name)
}
