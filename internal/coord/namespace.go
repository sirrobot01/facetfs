package coord

import (
	"context"
	"slices"
	"sync"
)

type keyedLock struct {
	ch   chan struct{}
	refs int
}

type NamespaceLocks struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

func (l *NamespaceLocks) Lock(ctx context.Context, keys ...string) (func(), error) {
	keys = slices.Compact(slices.Sorted(slices.Values(keys)))
	locks := make([]*keyedLock, len(keys))
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*keyedLock)
	}
	for i, key := range keys {
		lock := l.locks[key]
		if lock == nil {
			lock = &keyedLock{ch: make(chan struct{}, 1)}
			lock.ch <- struct{}{}
			l.locks[key] = lock
		}
		lock.refs++
		locks[i] = lock
	}
	l.mu.Unlock()
	acquired := 0
	for _, lock := range locks {
		select {
		case <-lock.ch:
			acquired++
		case <-ctx.Done():
			l.release(keys, locks, acquired)
			return nil, ctx.Err()
		}
	}
	return func() {
		l.release(keys, locks, len(locks))
	}, nil
}

func (l *NamespaceLocks) release(keys []string, locks []*keyedLock, acquired int) {
	for i := acquired - 1; i >= 0; i-- {
		locks[i].ch <- struct{}{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, key := range keys {
		locks[i].refs--
		if locks[i].refs == 0 {
			delete(l.locks, key)
		}
	}
}
