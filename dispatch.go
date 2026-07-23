package facetfs

import "context"

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
	handle, err := export.Backend.Open(ctx, request, object, options)
	if err != nil {
		return nil, err
	}
	return s.wrapHandle(ctx, request, handle, options.Access)
}

func (s *Server) Create(ctx context.Context, request Request, parent ObjectRef, name string, options CreateOptions) (ObjectRef, Handle, Attr, error) {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionCreate, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	object, handle, attr, err := backend.Create(ctx, request, parent, name, options)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
	wrapped, err := s.wrapHandle(ctx, request, handle, options.Open.Access)
	if err != nil {
		return ObjectRef{}, nil, Attr{}, err
	}
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
	return backend.Mkdir(ctx, request, parent, name, set)
}

func (s *Server) Symlink(ctx context.Context, request Request, parent ObjectRef, name, target string, set SetAttr) (ObjectRef, Attr, error) {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return ObjectRef{}, Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionSymlink, Parent: parent, Name: name}); err != nil {
		return ObjectRef{}, Attr{}, err
	}
	return backend.Symlink(ctx, request, parent, name, target, set)
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
	return backend.Link(ctx, request, object, parent, name)
}

func (s *Server) Remove(ctx context.Context, request Request, parent ObjectRef, name string, kind RemoveKind) error {
	backend, err := s.mutable(request, parent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionRemove, Parent: parent, Name: name}); err != nil {
		return err
	}
	return backend.Remove(ctx, request, parent, name, kind)
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
	return backend.Rename(ctx, request, oldParent, oldName, newParent, newName, options)
}

func (s *Server) SetAttr(ctx context.Context, request Request, object ObjectRef, set SetAttr) (Attr, error) {
	backend, err := s.mutable(request, object)
	if err != nil {
		return Attr{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionSetAttr, Object: object}); err != nil {
		return Attr{}, err
	}
	return backend.SetAttr(ctx, request, object, set)
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
