package facetfs

import (
	"context"
	"errors"

	"github.com/sirrobot01/facetfs/internal/coord"
)

func (s *Server) Root(ctx context.Context, request Request, exportID string) (ObjectRef, Attr, error) {
	export, err := s.resolveExport(request, exportID)
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{ExportID: exportID, Action: ActionRoot}); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	return export.Backend.Root(ctx, request, exportID)
}

func (s *Server) Lookup(ctx context.Context, request Request, parent ObjectRef, name string) (ObjectRef, Attr, error) {
	export, err := s.resolveObject(request, parent)
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLookup, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	return export.Backend.Lookup(ctx, request, parent, name)
}

func (s *Server) GetAttr(ctx context.Context, request Request, object ObjectRef, mask AttrMask) (Attr, error) {
	export, err := s.resolveObject(request, object)
	if err != nil {
		return Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionGetAttr, Object: object}); err != nil {
		return Attr{}, err
	}
	return export.Backend.GetAttr(ctx, request, object, mask)
}

func (s *Server) ReadDir(ctx context.Context, request Request, dir ObjectRef, cursor DirCursor, limit int) (DirPage, error) {
	export, err := s.resolveObject(request, dir)
	if err != nil {
		return DirPage{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionReadDir, Object: dir}); err != nil {
		return DirPage{}, err
	}
	return export.Backend.ReadDir(ctx, request, dir, cursor, limit)
}

func (s *Server) Open(ctx context.Context, request Request, object ObjectRef, options OpenOptions) (Handle, error) {
	export, err := s.resolveObject(request, object)
	if err != nil {
		return nil, err
	}
	if options.Access&OpenRead != 0 {
		if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionRead, Object: object}); err != nil {
			return nil, err
		}
	}
	if options.Access&OpenWrite != 0 {
		if export.ReadOnly {
			return nil, ErrReadOnly
		}
		if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionWrite, Object: object}); err != nil {
			return nil, err
		}
	}
	if options.Access&OpenDelete != 0 {
		if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionRemove, Object: object}); err != nil {
			return nil, err
		}
	}
	if options.Access&(OpenWrite|OpenDelete) != 0 {
		if err := s.guardLocks(request, objectKey(object)); err != nil {
			return nil, err
		}
	}
	owner, err := requestOwner(request)
	if err != nil {
		return nil, err
	}
	reservation, err := s.opens.Reserve(objectKey(object), owner, uint8(options.Access), uint8(options.Share))
	if errors.Is(err, coord.ErrConflict) {
		return nil, ErrLockConflict
	}
	if err != nil {
		return nil, err
	}
	handle, err := export.Backend.Open(ctx, request, object, options)
	if err != nil {
		s.opens.Release(reservation)
		return nil, err
	}
	return s.wrapHandle(ctx, request, handle, options.Access, reservation)
}

func (s *Server) Create(ctx context.Context, request Request, parent ObjectRef, name string, options CreateOptions) (ObjectRef, Handle, Attr, error) {
	owner, err := requestOwner(request)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	backend, err := s.mutable(request, parent)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionCreate, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	if err := s.guardLocks(request, objectKey(parent)); err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(parent), namespaceKey(parent, name))
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	defer unlock()
	object, handle, attr, err := backend.Create(ctx, request, parent, name, options)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	reservation, err := s.opens.Reserve(objectKey(object), owner, uint8(options.Open.Access), uint8(options.Open.Share))
	if errors.Is(err, coord.ErrConflict) {
		_ = handle.Close(context.WithoutCancel(ctx))
		return ObjectRef{}, nil, Attr{}, ErrLockConflict
	}
	if err != nil {
		_ = handle.Close(context.WithoutCancel(ctx))
		return ObjectRef{}, nil, Attr{}, err
	}
	wrapped, err := s.wrapHandle(ctx, request, handle, options.Open.Access, reservation)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	s.changed(ChangeEvent{Kind: ChangeCreated, Object: object, Parent: parent})
	return object, wrapped, attr, nil
}

func (s *Server) Mkdir(ctx context.Context, request Request, parent ObjectRef, name string, set SetAttr) (ObjectRef, Attr, error) {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionMkdir, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.guardLocks(request, objectKey(parent)); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(parent), namespaceKey(parent, name))
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	defer unlock()
	object, attr, err := backend.Mkdir(ctx, request, parent, name, set)
	if err == nil {
		s.changed(ChangeEvent{Kind: ChangeCreated, Object: object, Parent: parent})
	}
	return object, attr, err
}

func (s *Server) Symlink(ctx context.Context, request Request, parent ObjectRef, name, target string, set SetAttr) (ObjectRef, Attr, error) {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionSymlink, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.guardLocks(request, objectKey(parent)); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(parent), namespaceKey(parent, name))
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	defer unlock()
	object, attr, err := backend.Symlink(ctx, request, parent, name, target, set)
	if err == nil {
		s.changed(ChangeEvent{Kind: ChangeCreated, Object: object, Parent: parent})
	}
	return object, attr, err
}

func (s *Server) Readlink(ctx context.Context, request Request, object ObjectRef) (string, error) {
	export, err := s.resolveObject(request, object)
	if err != nil {
		return "", err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionReadlink, Object: object}); err != nil {
		return "", err
	}
	return export.Backend.Readlink(ctx, request, object)
}

func (s *Server) Link(ctx context.Context, request Request, object, parent ObjectRef, name string) error {
	if object.ExportID != parent.ExportID {
		return ErrCrossDevice
	}
	backend, err := s.mutable(request, parent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLink, Object: object, Parent: parent, Name: name}); err != nil {
		return err
	}
	if err := s.guardLocks(request, objectKey(parent)); err != nil {
		return err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(object), objectKey(parent), namespaceKey(parent, name))
	if err != nil {
		return err
	}
	defer unlock()
	err = backend.Link(ctx, request, object, parent, name)
	if err == nil {
		s.changed(ChangeEvent{Kind: ChangeNamespace, Object: object, Parent: parent})
	}
	return err
}

func (s *Server) Remove(ctx context.Context, request Request, parent ObjectRef, name string, kind RemoveKind) error {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionRemove, Parent: parent, Name: name}); err != nil {
		return err
	}
	if err := s.guardLocks(request, objectKey(parent)); err != nil {
		return err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(parent), namespaceKey(parent, name))
	if err != nil {
		return err
	}
	defer unlock()
	object, _, err := backend.Lookup(ctx, request, parent, name)
	if err != nil {
		return err
	}
	if err := s.guardLocks(request, objectKey(object)); err != nil {
		return err
	}
	if s.opens.Conflicts(objectKey(object), uint8(OpenDelete)) {
		return ErrLockConflict
	}
	err = backend.Remove(ctx, request, parent, name, kind)
	if err == nil {
		s.dropLocks(object)
		s.changed(ChangeEvent{Kind: ChangeRemoved, Object: object, Parent: parent})
	}
	return err
}

func (s *Server) Rename(ctx context.Context, request Request, oldParent ObjectRef, oldName string, newParent ObjectRef, newName string, options RenameOptions) error {
	if oldParent.ExportID != newParent.ExportID {
		return ErrCrossDevice
	}
	backend, err := s.mutable(request, oldParent)
	if err != nil {
		return err
	}
	check := AccessCheck{
		ExportID:  oldParent.ExportID,
		Action:    ActionRename,
		Parent:    oldParent,
		Name:      oldName,
		NewParent: newParent,
		NewName:   newName,
	}
	if err := s.authorizer.Authorize(ctx, request, check); err != nil {
		return err
	}
	if err := s.guardLocks(request, objectKey(oldParent), objectKey(newParent)); err != nil {
		return err
	}
	unlock, err := s.namespaces.Lock(ctx,
		objectKey(oldParent), namespaceKey(oldParent, oldName),
		objectKey(newParent), namespaceKey(newParent, newName),
	)
	if err != nil {
		return err
	}
	defer unlock()
	object, _, err := backend.Lookup(ctx, request, oldParent, oldName)
	if err != nil {
		return err
	}
	if err := s.guardLocks(request, objectKey(object)); err != nil {
		return err
	}
	if s.opens.Conflicts(objectKey(object), uint8(OpenDelete)) {
		return ErrLockConflict
	}
	var replaced ObjectRef
	overwrites := false
	if target, _, lookupErr := backend.Lookup(ctx, request, newParent, newName); lookupErr == nil {
		if err := s.guardLocks(request, objectKey(target)); err != nil {
			return err
		}
		if s.opens.Conflicts(objectKey(target), uint8(OpenDelete)) {
			return ErrLockConflict
		}
		replaced, overwrites = target, true
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return lookupErr
	}
	err = backend.Rename(ctx, request, oldParent, oldName, newParent, newName, options)
	if err == nil {
		// The rename destroys any object it overwrote. The renamed object keeps its
		// identity, and with it its locks.
		if overwrites {
			s.dropLocks(replaced)
		}
		s.changed(ChangeEvent{Kind: ChangeNamespace, Object: object, Parent: oldParent, NewParent: newParent})
	}
	return err
}

func (s *Server) SetAttr(ctx context.Context, request Request, object ObjectRef, set SetAttr) (Attr, error) {
	backend, err := s.mutable(request, object)
	if err != nil {
		return Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionSetAttr, Object: object}); err != nil {
		return Attr{}, err
	}
	if err := s.guardLocks(request, objectKey(object)); err != nil {
		return Attr{}, err
	}
	unlock, err := s.namespaces.Lock(ctx, objectKey(object))
	if err != nil {
		return Attr{}, err
	}
	defer unlock()
	if s.opens.Conflicts(objectKey(object), uint8(OpenWrite)) {
		return Attr{}, ErrLockConflict
	}
	attr, err := backend.SetAttr(ctx, request, object, set)
	if err == nil {
		s.changed(ChangeEvent{Kind: ChangeMetadata, Object: object})
	}
	return attr, err
}

func (s *Server) StatFS(ctx context.Context, request Request, object ObjectRef) (FSStat, error) {
	export, err := s.resolveObject(request, object)
	if err != nil {
		return FSStat{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionStatFS, Object: object}); err != nil {
		return FSStat{}, err
	}
	return export.Backend.StatFS(ctx, request, object)
}

func (s *Server) resolveExport(request Request, exportID string) (Export, error) {
	if s == nil {
		return Export{}, ErrInvalid
	}
	if !knownProtocol(request.Protocol) {
		return Export{}, ErrInvalid
	}
	export, ok := s.byID[exportID]
	if !ok || !export.Supports(request.Protocol) {
		return Export{}, ErrNotFound
	}
	return export, nil
}

func (s *Server) resolveObject(request Request, object ObjectRef) (Export, error) {
	if object.ExportID == "" {
		return Export{}, ErrStaleObject
	}
	return s.resolveExport(request, object.ExportID)
}

func (s *Server) mutable(request Request, object ObjectRef) (MutableBackend, error) {
	export, err := s.resolveObject(request, object)
	if err != nil {
		return nil, err
	}
	if export.ReadOnly {
		return nil, ErrReadOnly
	}
	backend, ok := export.Backend.(MutableBackend)
	if !ok {
		return nil, ErrNotSupported
	}
	return backend, nil
}
