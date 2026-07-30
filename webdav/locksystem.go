package webdav

import (
	"errors"
	"time"
)

var (
	// ErrLocked reports that a resource carries a live lock that the caller
	// did not satisfy with a token.
	ErrLocked = errors.New("webdav: resource is locked")
	// ErrNoSuchLock reports that no live lock matches the given root and token.
	ErrNoSuchLock = errors.New("webdav: no such lock")
	// ErrTooManyLocks reports that the lock system refused a new lock because
	// a resource ceiling was reached.
	ErrTooManyLocks = errors.New("webdav: too many locks")
)

// LockDetails describes a held or requested exclusive write lock.
type LockDetails struct {
	// Root is the cleaned, slash-rooted path the lock covers.
	Root string
	// Owner is opaque owner information supplied by the client (the WebDAV
	// <owner> element) and is surfaced only through lock discovery.
	Owner string
	// Duration is the requested lifetime. The lock system clamps it; Expires
	// reports the granted lifetime.
	Duration time.Duration
	Token    string
	Expires  time.Time
}

// LockSystem manages exclusive, Depth-0 write locks for a Handler. All locks
// expire; a lock on a path that ceases to exist simply times out.
// Implementations must be safe for concurrent use.
type LockSystem interface {
	// Create acquires an exclusive write lock on details.Root and returns the
	// held lock with its Token and Expires set. It returns ErrLocked when the
	// root already carries a live lock.
	Create(now time.Time, details LockDetails) (LockDetails, error)
	// Refresh extends the lock identified by root and token. It returns
	// ErrNoSuchLock when no live lock matches.
	Refresh(now time.Time, root, token string, duration time.Duration) (LockDetails, error)
	// Unlock releases the lock identified by root and token. It returns
	// ErrNoSuchLock when no live lock matches.
	Unlock(now time.Time, root, token string) error
	// Guard returns a live lock on root that none of tokens satisfies. A
	// mutation must be refused with 423 Locked when ok is true.
	Guard(now time.Time, root string, tokens []string) (details LockDetails, ok bool)
	// Holder returns the live lock on root, if any, for lock discovery and If
	// header evaluation.
	Holder(now time.Time, root string) (details LockDetails, ok bool)
}
