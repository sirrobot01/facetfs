package webdav

import (
	"crypto/rand"
	"fmt"
	"slices"
	"sync"
	"time"
)

const (
	minLockDuration     = 15 * time.Second
	defaultLockDuration = 5 * time.Minute
	maxLockDuration     = time.Hour
	// maxHeldLocks bounds the number of concurrently held locks so a client
	// cannot exhaust memory through a lock flood.
	maxHeldLocks = 1 << 16
)

// NewMemLS returns an in-memory LockSystem.
func NewMemLS() LockSystem {
	return &memLS{locks: map[string]LockDetails{}}
}

type memLS struct {
	mu    sync.Mutex
	locks map[string]LockDetails
}

// live returns the unexpired lock on root, dropping an expired one. The caller
// must hold m.mu.
func (m *memLS) live(root string, now time.Time) (LockDetails, bool) {
	held, ok := m.locks[root]
	if !ok {
		return LockDetails{}, false
	}
	if !held.Expires.After(now) {
		delete(m.locks, root)
		return LockDetails{}, false
	}
	return held, true
}

func (m *memLS) Create(now time.Time, details LockDetails) (LockDetails, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.live(details.Root, now); ok {
		return LockDetails{}, ErrLocked
	}
	if len(m.locks) >= maxHeldLocks {
		for root, held := range m.locks {
			if !held.Expires.After(now) {
				delete(m.locks, root)
			}
		}
		if len(m.locks) >= maxHeldLocks {
			return LockDetails{}, ErrTooManyLocks
		}
	}
	token, err := newLockToken()
	if err != nil {
		return LockDetails{}, err
	}
	details.Token = token
	details.Duration = clampLockDuration(details.Duration)
	details.Expires = now.Add(details.Duration)
	m.locks[details.Root] = details
	return details, nil
}

func (m *memLS) Refresh(now time.Time, root, token string, duration time.Duration) (LockDetails, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.live(root, now)
	if !ok || held.Token != token {
		return LockDetails{}, ErrNoSuchLock
	}
	held.Duration = clampLockDuration(duration)
	held.Expires = now.Add(held.Duration)
	m.locks[root] = held
	return held, nil
}

func (m *memLS) Unlock(now time.Time, root, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.live(root, now)
	if !ok || held.Token != token {
		return ErrNoSuchLock
	}
	delete(m.locks, root)
	return nil
}

func (m *memLS) Guard(now time.Time, root string, tokens []string) (LockDetails, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held, ok := m.live(root, now)
	if !ok || slices.Contains(tokens, held.Token) {
		return LockDetails{}, false
	}
	return held, true
}

func (m *memLS) Holder(now time.Time, root string) (LockDetails, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live(root, now)
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
