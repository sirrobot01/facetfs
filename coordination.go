package facetfs

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirrobot01/facetfs/internal/coord"
)

type LockOptions struct {
	Offset    uint64
	Length    uint64
	Exclusive bool
}

type Lock struct {
	ID        uint64
	Object    ObjectRef
	Owner     string
	Offset    uint64
	Length    uint64
	Exclusive bool
	lock      coord.RangeLock
}

func (s *Server) Lock(ctx context.Context, request Request, object ObjectRef, options LockOptions) (Lock, error) {
	if _, err := s.resolveObject(request, object); err != nil {
		return Lock{}, err
	}
	owner, err := requestOwner(request)
	if err != nil {
		return Lock{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLock, Object: object}); err != nil {
		return Lock{}, err
	}
	locked, err := s.locks.Lock(objectKey(object), owner, options.Offset, options.Length, options.Exclusive)
	if errors.Is(err, coord.ErrConflict) {
		return Lock{}, ErrLockConflict
	}
	if err != nil {
		return Lock{}, err
	}
	return Lock{
		ID: locked.ID, Object: object, Owner: owner, Offset: options.Offset, Length: options.Length,
		Exclusive: options.Exclusive, lock: locked,
	}, nil
}

func (s *Server) Unlock(request Request, lock Lock) error {
	if lock.ID == 0 || lock.lock.ID != lock.ID {
		return ErrInvalid
	}
	owner, err := requestOwner(request)
	if err != nil {
		return err
	}
	if owner != lock.Owner {
		return ErrAccessDenied
	}
	s.locks.Unlock(lock.lock)
	return nil
}

func (s *Server) CloseSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrInvalid
	}
	s.handlesMu.Lock()
	handles := make([]*coordinatedHandle, 0, len(s.handles[sessionID]))
	for handle := range s.handles[sessionID] {
		handles = append(handles, handle)
	}
	s.handlesMu.Unlock()
	var closeErr error
	for _, handle := range handles {
		closeErr = errors.Join(closeErr, handle.Close(context.WithoutCancel(ctx)))
	}
	s.opens.ReleaseOwner(sessionID)
	s.locks.ReleaseOwner(sessionID)
	return closeErr
}

func requestOwner(request Request) (string, error) {
	if request.SessionID == "" {
		return "", ErrInvalid
	}
	return request.SessionID, nil
}

func objectKey(object ObjectRef) string {
	return fmt.Sprintf("%s\x00%s\x00%d", object.ExportID, object.NodeID, object.Generation)
}

func namespaceKey(parent ObjectRef, name string) string {
	return objectKey(parent) + "\x00" + name
}
