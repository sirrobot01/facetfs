package osfs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
)

func (f *FS) Mkdir(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, set facetfs.SetAttr) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	parentPath, info, _, err := f.resolve(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if !info.IsDir() {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotDirectory
	}
	path := filepath.Join(parentPath, name)
	mode := fs.FileMode(0o777)
	if set.Mode != nil {
		mode = *set.Mode
	}
	if err := os.Mkdir(path, mode.Perm()); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	created, err := os.Lstat(path)
	if err != nil {
		_ = os.Remove(path)
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	if err := f.apply(path, created, set); err != nil {
		_ = os.Remove(path)
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	created, err = os.Lstat(path)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	record := f.track(path, created)
	if set.Mode != nil {
		f.overrideMode(record, *set.Mode)
	}
	f.changed(parentPath)
	return objectRef(parent.ExportID, record), f.fileAttr(record, created), nil
}

func (f *FS) Symlink(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name, target string, set facetfs.SetAttr) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if !symlinks {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotSupported
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if set.Size != nil || set.Owner != nil || set.Group != nil || set.Mode != nil || set.AccessedAt != nil || set.ModifiedAt != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotSupported
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	parentPath, info, _, err := f.resolve(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if !info.IsDir() {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrNotDirectory
	}
	path := filepath.Join(parentPath, name)
	if err := os.Symlink(target, path); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	created, err := os.Lstat(path)
	if err != nil {
		_ = os.Remove(path)
		return facetfs.ObjectRef{}, facetfs.Attr{}, mapError(err)
	}
	record := f.track(path, created)
	f.changed(parentPath)
	return objectRef(parent.ExportID, record), f.fileAttr(record, created), nil
}

func (f *FS) Link(ctx context.Context, _ facetfs.Request, object, parent facetfs.ObjectRef, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !hardLinks {
		return facetfs.ErrNotSupported
	}
	if object.ExportID != parent.ExportID {
		return facetfs.ErrCrossDevice
	}
	if err := names.Validate(name); err != nil {
		return err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	oldPath, info, _, err := f.resolve(object)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return facetfs.ErrIsDirectory
	}
	parentPath, parentInfo, _, err := f.resolve(parent)
	if err != nil {
		return err
	}
	if !parentInfo.IsDir() {
		return facetfs.ErrNotDirectory
	}
	newPath := filepath.Join(parentPath, name)
	if err := os.Link(oldPath, newPath); err != nil {
		return mapError(err)
	}
	linked, err := os.Lstat(newPath)
	if err != nil {
		return mapError(err)
	}
	f.track(newPath, linked)
	f.changed(oldPath)
	f.changed(parentPath)
	return nil
}

func (f *FS) Remove(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, kind facetfs.RemoveKind) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := names.Validate(name); err != nil {
		return err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	parentPath, parentInfo, _, err := f.resolve(parent)
	if err != nil {
		return err
	}
	if !parentInfo.IsDir() {
		return facetfs.ErrNotDirectory
	}
	path := filepath.Join(parentPath, name)
	info, err := os.Lstat(path)
	if err != nil {
		return mapError(err)
	}
	if kind == facetfs.RemoveDirectory && !info.IsDir() {
		return facetfs.ErrNotDirectory
	}
	if kind == facetfs.RemoveFile && info.IsDir() {
		return facetfs.ErrIsDirectory
	}
	if err := os.Remove(path); err != nil {
		return mapError(err)
	}
	f.removed(path)
	f.changed(parentPath)
	return nil
}

func (f *FS) Rename(ctx context.Context, _ facetfs.Request, oldParent facetfs.ObjectRef, oldName string, newParent facetfs.ObjectRef, newName string, options facetfs.RenameOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if oldParent.ExportID != newParent.ExportID {
		return facetfs.ErrCrossDevice
	}
	if err := names.Validate(oldName); err != nil {
		return err
	}
	if err := names.Validate(newName); err != nil {
		return err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	oldParentPath, oldParentInfo, _, err := f.resolve(oldParent)
	if err != nil {
		return err
	}
	newParentPath, newParentInfo, _, err := f.resolve(newParent)
	if err != nil {
		return err
	}
	if !oldParentInfo.IsDir() || !newParentInfo.IsDir() {
		return facetfs.ErrNotDirectory
	}
	oldPath := filepath.Join(oldParentPath, oldName)
	newPath := filepath.Join(newParentPath, newName)
	if oldPath == newPath {
		if _, err := os.Lstat(oldPath); err != nil {
			return mapError(err)
		}
		return nil
	}
	if _, err := os.Lstat(oldPath); err != nil {
		return mapError(err)
	}
	if _, err := os.Lstat(newPath); err == nil && !options.Replace {
		return facetfs.ErrExists
	} else if err != nil && !os.IsNotExist(err) {
		return mapError(err)
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return mapError(err)
	}
	f.moved(oldPath, newPath)
	f.changed(newPath)
	f.changed(oldParentPath)
	if oldParentPath != newParentPath {
		f.changed(newParentPath)
	}
	return nil
}

func (f *FS) SetAttr(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, set facetfs.SetAttr) (facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Attr{}, err
	}
	f.namespace.Lock()
	defer f.namespace.Unlock()
	path, info, record, err := f.resolve(object)
	if err != nil {
		return facetfs.Attr{}, err
	}
	if err := f.apply(path, info, set); err != nil {
		return facetfs.Attr{}, err
	}
	if set.Mode != nil {
		f.overrideMode(record, *set.Mode)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return facetfs.Attr{}, mapError(err)
	}
	return f.fileAttr(record, info), nil
}

func (f *FS) moved(oldPath, newPath string) {
	oldPath = filepath.Clean(oldPath)
	newPath = filepath.Clean(newPath)
	f.mu.Lock()
	defer f.mu.Unlock()
	if replaced := f.paths[newPath]; replaced != nil {
		delete(replaced.paths, newPath)
		delete(f.paths, newPath)
		if len(replaced.paths) == 0 && replaced.open == 0 {
			delete(f.records, replaced.id)
		}
	}
	for path, record := range f.paths {
		if path != oldPath && !strings.HasPrefix(path, oldPath+string(filepath.Separator)) {
			continue
		}
		relative, err := filepath.Rel(oldPath, path)
		if err != nil {
			continue
		}
		replacement := filepath.Join(newPath, relative)
		delete(record.paths, path)
		delete(f.paths, path)
		record.paths[replacement] = struct{}{}
		f.paths[replacement] = record
		// Refresh info so it carries the new path. os.SameFile reloads a
		// FileInfo's identity by re-opening its stored path on Windows; a
		// FileInfo left pointing at the pre-rename path would fail that
		// comparison and make the object look stale after the rename.
		if info, err := os.Lstat(replacement); err == nil {
			record.info = info
		}
	}
}
