package facetfs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sirrobot01/facetfs/internal/coord"
)

const (
	minLockDuration     = 15 * time.Second
	defaultLockDuration = 5 * time.Minute
	maxLockDuration     = time.Hour
)

// DocumentLockRequest describes a whole-object lock to acquire, such as a
// WebDAV Class 2 write lock.
type DocumentLockRequest struct {
	Exclusive bool
	Deep      bool
	Duration  time.Duration
	// Owner is opaque owner information supplied by the client (for example the
	// WebDAV <owner> element) and is surfaced only through lock discovery.
	Owner string
}

// DocumentLock is a held whole-object lock. Token is the unforgeable capability
// a later request must present to mutate the object or release the lock.
type DocumentLock struct {
	Token     string
	Object    ObjectRef
	Principal string
	Owner     string
	Exclusive bool
	Deep      bool
	Expires   time.Time
}

// AcquireLock places a document lock on object and returns its token. The lock
// conflicts with mutations from every protocol that does not present the token,
// per the default data-safety policy.
func (s *Server) AcquireLock(ctx context.Context, request Request, object ObjectRef, lock DocumentLockRequest) (DocumentLock, error) {
	if _, err := s.resolveObject(request, object); err != nil {
		return DocumentLock{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLock, Object: object}); err != nil {
		return DocumentLock{}, err
	}
	token, err := newLockToken()
	if err != nil {
		return DocumentLock{}, err
	}
	expires := s.now().Add(clampLockDuration(lock.Duration))
	held, err := s.doclocks.Acquire(coord.DocLock{
		Token:     token,
		Key:       objectKey(object),
		Owner:     request.Principal.Subject,
		Exclusive: lock.Exclusive,
		Deep:      lock.Deep,
		Expires:   expires,
	})
	switch {
	case errors.Is(err, coord.ErrConflict):
		return DocumentLock{}, ErrLockConflict
	case errors.Is(err, coord.ErrLimit):
		return DocumentLock{}, ErrTooManyOpenFiles
	case err != nil:
		return DocumentLock{}, err
	}
	return documentLock(object, held, lock.Owner), nil
}

// RefreshLock extends an existing document lock identified by token.
func (s *Server) RefreshLock(ctx context.Context, request Request, object ObjectRef, token string, duration time.Duration) (DocumentLock, error) {
	if token == "" {
		return DocumentLock{}, ErrInvalid
	}
	if _, err := s.resolveObject(request, object); err != nil {
		return DocumentLock{}, err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLock, Object: object}); err != nil {
		return DocumentLock{}, err
	}
	held, ok := s.doclocks.Refresh(objectKey(object), token, s.now().Add(clampLockDuration(duration)))
	if !ok {
		return DocumentLock{}, ErrInvalid
	}
	return documentLock(object, held, ""), nil
}

// ReleaseLock removes the document lock identified by token from object.
func (s *Server) ReleaseLock(ctx context.Context, request Request, object ObjectRef, token string) error {
	if token == "" {
		return ErrInvalid
	}
	if _, err := s.resolveObject(request, object); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, request, AccessCheck{Action: ActionLock, Object: object}); err != nil {
		return err
	}
	if !s.doclocks.Release(objectKey(object), token) {
		return ErrInvalid
	}
	return nil
}

// LockOf returns the document lock currently held on object, if any.
func (s *Server) LockOf(object ObjectRef) (DocumentLock, bool) {
	held, ok := s.doclocks.Holder(objectKey(object))
	if !ok {
		return DocumentLock{}, false
	}
	return documentLock(object, held, ""), true
}

// dropLocks discards every document lock on an object that no longer exists.
// Callers invoke it only after the backend has removed or replaced the object,
// so a lock never outlives what it protects.
func (s *Server) dropLocks(object ObjectRef) {
	s.doclocks.ReleaseKey(objectKey(object))
}

// guardLocks reports ErrLockConflict when any key carries a document lock that
// the request does not satisfy with a matching token.
func (s *Server) guardLocks(request Request, keys ...string) error {
	for _, key := range keys {
		if _, locked := s.doclocks.Guard(key, request.LockTokens); locked {
			return ErrLockConflict
		}
	}
	return nil
}

func documentLock(object ObjectRef, held coord.DocLock, owner string) DocumentLock {
	return DocumentLock{
		Token:     held.Token,
		Object:    object,
		Principal: held.Owner,
		Owner:     owner,
		Exclusive: held.Exclusive,
		Deep:      held.Deep,
		Expires:   held.Expires,
	}
}

func clampLockDuration(duration time.Duration) time.Duration {
	switch {
	case duration <= 0:
		return defaultLockDuration
	case duration < minLockDuration:
		return minLockDuration
	case duration > maxLockDuration:
		return maxLockDuration
	default:
		return duration
	}
}

func newLockToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
