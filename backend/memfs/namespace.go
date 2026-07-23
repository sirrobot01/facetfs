package memfs

import (
	"context"
	"io/fs"
	"time"

	"github.com/sirrobot01/facetfs"
	"github.com/sirrobot01/facetfs/internal/names"
)

func (f *FS) Create(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, options facetfs.CreateOptions) (facetfs.ObjectRef, facetfs.Handle, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, err := f.directory(parent)
	if err != nil {
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	if id, ok := dir.children[name]; ok {
		if options.Exclusive {
			return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrExists
		}
		n := f.nodes[id]
		if n.kind == facetfs.NodeTypeDirectory {
			return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrIsDirectory
		}
		if n.kind == facetfs.NodeTypeSymlink {
			return facetfs.ObjectRef{}, nil, facetfs.Attr{}, facetfs.ErrNotSupported
		}
		object := ref(parent.ExportID, n)
		return object, f.open(object, n, options.Open), attr(n), nil
	}

	mode := fs.FileMode(0o666)
	if options.Attr.Mode != nil {
		mode = *options.Attr.Mode
	}
	n := f.makeNode(facetfs.NodeTypeRegular, mode)
	if err := f.setAttr(n, options.Attr); err != nil {
		delete(f.nodes, n.id)
		return facetfs.ObjectRef{}, nil, facetfs.Attr{}, err
	}
	dir.children[name] = n.id
	f.touch(dir)
	object := ref(parent.ExportID, n)
	return object, f.open(object, n, options.Open), attr(n), nil
}

func (f *FS) Mkdir(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, set facetfs.SetAttr) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, err := f.directory(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if _, ok := dir.children[name]; ok {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrExists
	}
	mode := fs.FileMode(0o777)
	if set.Mode != nil {
		mode = *set.Mode
	}
	n := f.makeNode(facetfs.NodeTypeDirectory, mode)
	if err := f.setAttr(n, set); err != nil {
		delete(f.nodes, n.id)
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	dir.children[name] = n.id
	f.touch(dir)
	return ref(parent.ExportID, n), attr(n), nil
}

func (f *FS) Symlink(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name, target string, set facetfs.SetAttr) (facetfs.ObjectRef, facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if err := names.Validate(name); err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, err := f.directory(parent)
	if err != nil {
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	if _, ok := dir.children[name]; ok {
		return facetfs.ObjectRef{}, facetfs.Attr{}, facetfs.ErrExists
	}
	n := f.makeNode(facetfs.NodeTypeSymlink, 0o777)
	n.target = target
	if err := f.setAttr(n, set); err != nil {
		delete(f.nodes, n.id)
		return facetfs.ObjectRef{}, facetfs.Attr{}, err
	}
	dir.children[name] = n.id
	f.touch(dir)
	return ref(parent.ExportID, n), attr(n), nil
}

func (f *FS) Readlink(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	n, err := f.node(object)
	if err != nil {
		return "", err
	}
	if n.kind != facetfs.NodeTypeSymlink {
		return "", facetfs.ErrInvalid
	}
	return n.target, nil
}

func (f *FS) Link(ctx context.Context, _ facetfs.Request, object, parent facetfs.ObjectRef, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if object.ExportID != parent.ExportID {
		return facetfs.ErrCrossDevice
	}
	if err := names.Validate(name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.node(object)
	if err != nil {
		return err
	}
	if n.kind == facetfs.NodeTypeDirectory {
		return facetfs.ErrIsDirectory
	}
	dir, err := f.directory(parent)
	if err != nil {
		return err
	}
	if _, ok := dir.children[name]; ok {
		return facetfs.ErrExists
	}
	dir.children[name] = n.id
	n.links++
	f.touch(n)
	f.touch(dir)
	return nil
}

func (f *FS) Remove(ctx context.Context, _ facetfs.Request, parent facetfs.ObjectRef, name string, kind facetfs.RemoveKind) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := names.Validate(name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, err := f.directory(parent)
	if err != nil {
		return err
	}
	id, ok := dir.children[name]
	if !ok {
		return facetfs.ErrNotFound
	}
	n := f.nodes[id]
	if kind == facetfs.RemoveDirectory && n.kind != facetfs.NodeTypeDirectory {
		return facetfs.ErrNotDirectory
	}
	if kind == facetfs.RemoveFile && n.kind == facetfs.NodeTypeDirectory {
		return facetfs.ErrIsDirectory
	}
	if n.kind == facetfs.NodeTypeDirectory && len(n.children) != 0 {
		return facetfs.ErrNotEmpty
	}
	delete(dir.children, name)
	n.links--
	f.touch(n)
	f.touch(dir)
	f.release(n)
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
	f.mu.Lock()
	defer f.mu.Unlock()
	sourceDir, err := f.directory(oldParent)
	if err != nil {
		return err
	}
	targetDir, err := f.directory(newParent)
	if err != nil {
		return err
	}
	sourceID, ok := sourceDir.children[oldName]
	if !ok {
		return facetfs.ErrNotFound
	}
	if sourceDir == targetDir && oldName == newName {
		return nil
	}
	source := f.nodes[sourceID]
	if source.kind == facetfs.NodeTypeDirectory {
		var contains func(*node) bool
		contains = func(dir *node) bool {
			if dir == targetDir {
				return true
			}
			for _, id := range dir.children {
				child := f.nodes[id]
				if child.kind == facetfs.NodeTypeDirectory && contains(child) {
					return true
				}
			}
			return false
		}
		if contains(source) {
			return facetfs.ErrInvalid
		}
	}
	if targetID, exists := targetDir.children[newName]; exists {
		if targetID == sourceID {
			return nil
		}
		if !options.Replace {
			return facetfs.ErrExists
		}
		target := f.nodes[targetID]
		if source.kind == facetfs.NodeTypeDirectory && target.kind != facetfs.NodeTypeDirectory {
			return facetfs.ErrNotDirectory
		}
		if source.kind != facetfs.NodeTypeDirectory && target.kind == facetfs.NodeTypeDirectory {
			return facetfs.ErrIsDirectory
		}
		if target.kind == facetfs.NodeTypeDirectory && len(target.children) != 0 {
			return facetfs.ErrNotEmpty
		}
		target.links--
		f.touch(target)
		f.release(target)
	}
	delete(sourceDir.children, oldName)
	targetDir.children[newName] = sourceID
	f.touch(source)
	f.touch(sourceDir)
	if sourceDir != targetDir {
		f.touch(targetDir)
	}
	return nil
}

func (f *FS) SetAttr(ctx context.Context, _ facetfs.Request, object facetfs.ObjectRef, set facetfs.SetAttr) (facetfs.Attr, error) {
	if err := ctx.Err(); err != nil {
		return facetfs.Attr{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.node(object)
	if err != nil {
		return facetfs.Attr{}, err
	}
	if err := f.setAttr(n, set); err != nil {
		return facetfs.Attr{}, err
	}
	return attr(n), nil
}

func (f *FS) setAttr(n *node, set facetfs.SetAttr) error {
	changed := false
	if set.Size != nil {
		if *set.Size < 0 {
			return facetfs.ErrInvalid
		}
		if n.kind == facetfs.NodeTypeDirectory {
			return facetfs.ErrIsDirectory
		}
		if n.kind != facetfs.NodeTypeRegular {
			return facetfs.ErrInvalid
		}
		if *set.Size > maxFileSize {
			return facetfs.ErrNoSpace
		}
		if len(n.data) != int(*set.Size) {
			data := make([]byte, int(*set.Size))
			copy(data, n.data)
			n.data = data
			n.modified = time.Now().UTC()
			changed = true
		}
	}
	if set.Owner != nil {
		n.owner = *set.Owner
		changed = true
	}
	if set.Group != nil {
		n.group = *set.Group
		changed = true
	}
	if set.Mode != nil {
		n.mode = set.Mode.Perm()
		changed = true
	}
	if set.AccessedAt != nil {
		n.accessed = *set.AccessedAt
		changed = true
	}
	if set.ModifiedAt != nil {
		n.modified = *set.ModifiedAt
		changed = true
	}
	if changed {
		f.touch(n)
	}
	return nil
}
