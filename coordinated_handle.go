package facetfs

import "context"

type coordinatedHandle struct {
	server  *Server
	request Request
	handle  Handle
}

type coordinatedMutableHandle struct {
	*coordinatedHandle
	handle MutableHandle
}

func (s *Server) wrapHandle(ctx context.Context, request Request, handle Handle, access OpenAccess) (Handle, error) {
	base := &coordinatedHandle{server: s, request: request, handle: handle}
	mutable, ok := handle.(MutableHandle)
	if !ok {
		if access&OpenWrite != 0 {
			_ = handle.Close(context.WithoutCancel(ctx))
			return nil, ErrNotSupported
		}
		return base, nil
	}
	return &coordinatedMutableHandle{coordinatedHandle: base, handle: mutable}, nil
}

func (h *coordinatedHandle) ID() string        { return h.handle.ID() }
func (h *coordinatedHandle) Object() ObjectRef { return h.handle.Object() }

func (h *coordinatedHandle) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionRead, Object: h.Object()}); err != nil {
		return 0, err
	}
	return h.handle.ReadAt(ctx, p, off)
}

func (h *coordinatedHandle) Close(ctx context.Context) error {
	return h.handle.Close(ctx)
}

func (h *coordinatedMutableHandle) WriteAt(ctx context.Context, p []byte, off int64) (int, error) {
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionWrite, Object: h.Object()}); err != nil {
		return 0, err
	}
	return h.handle.WriteAt(ctx, p, off)
}

func (h *coordinatedMutableHandle) Flush(ctx context.Context, stable bool) error {
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionWrite, Object: h.Object()}); err != nil {
		return err
	}
	return h.handle.Flush(ctx, stable)
}

func (h *coordinatedMutableHandle) SetAttr(ctx context.Context, set SetAttr) (Attr, error) {
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionSetAttr, Object: h.Object()}); err != nil {
		return Attr{}, err
	}
	return h.handle.SetAttr(ctx, set)
}
