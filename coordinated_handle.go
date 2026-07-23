package facetfs

import (
	"context"
	"sync/atomic"

	"github.com/sirrobot01/facetfs/internal/coord"
)

type coordinatedHandle struct {
	server  *Server
	request Request
	handle  Handle
	owner   string
	open    coord.Reservation
	closed  atomic.Bool
}

type coordinatedMutableHandle struct {
	*coordinatedHandle
	handle MutableHandle
}

func (s *Server) wrapHandle(ctx context.Context, request Request, handle Handle, access OpenAccess, reservation coord.Reservation) (Handle, error) {
	owner, err := requestOwner(request)
	if err != nil {
		_ = handle.Close(context.WithoutCancel(ctx))
		s.opens.Release(reservation)
		return nil, err
	}
	base := &coordinatedHandle{server: s, request: request, handle: handle, owner: owner, open: reservation}
	mutable, ok := handle.(MutableHandle)
	if !ok {
		if access&OpenWrite != 0 {
			_ = handle.Close(context.WithoutCancel(ctx))
			s.opens.Release(reservation)
			return nil, ErrNotSupported
		}
		s.registerHandle(base)
		return base, nil
	}
	s.registerHandle(base)
	return &coordinatedMutableHandle{coordinatedHandle: base, handle: mutable}, nil
}

func (h *coordinatedHandle) ID() string        { return h.handle.ID() }
func (h *coordinatedHandle) Object() ObjectRef { return h.handle.Object() }

func (h *coordinatedHandle) ReadAt(ctx context.Context, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrInvalid
	}
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionRead, Object: h.Object()}); err != nil {
		return 0, err
	}
	if len(p) > 0 && h.server.locks.Conflicts(objectKey(h.Object()), h.owner, uint64(off), uint64(len(p)), false) {
		return 0, ErrLockConflict
	}
	return h.handle.ReadAt(ctx, p, off)
}

func (h *coordinatedHandle) Close(ctx context.Context) error {
	if h.closed.Swap(true) {
		return nil
	}
	err := h.handle.Close(context.WithoutCancel(ctx))
	h.server.opens.Release(h.open)
	h.server.unregisterHandle(h)
	return err
}

func (h *coordinatedMutableHandle) WriteAt(ctx context.Context, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrInvalid
	}
	if err := h.server.authorizer.Authorize(ctx, h.request, AccessCheck{Action: ActionWrite, Object: h.Object()}); err != nil {
		return 0, err
	}
	if len(p) > 0 && h.server.locks.Conflicts(objectKey(h.Object()), h.owner, uint64(off), uint64(len(p)), true) {
		return 0, ErrLockConflict
	}
	n, err := h.handle.WriteAt(ctx, p, off)
	if n > 0 {
		h.server.changed(ChangeEvent{Kind: ChangeData, Object: h.Object(), Offset: uint64(off), Length: uint64(n)})
	}
	return n, err
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
	attr, err := h.handle.SetAttr(ctx, set)
	if err == nil {
		h.server.changed(ChangeEvent{Kind: ChangeMetadata, Object: h.Object()})
	}
	return attr, err
}

func (s *Server) registerHandle(handle *coordinatedHandle) {
	s.handlesMu.Lock()
	defer s.handlesMu.Unlock()
	if s.handles[handle.owner] == nil {
		s.handles[handle.owner] = make(map[*coordinatedHandle]struct{})
	}
	s.handles[handle.owner][handle] = struct{}{}
}

func (s *Server) unregisterHandle(handle *coordinatedHandle) {
	s.handlesMu.Lock()
	defer s.handlesMu.Unlock()
	delete(s.handles[handle.owner], handle)
	if len(s.handles[handle.owner]) == 0 {
		delete(s.handles, handle.owner)
	}
}
