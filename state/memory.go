package state

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("state: key not found")

type Memory struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func NewMemory() *Memory {
	return &Memory{values: make(map[string][]byte)}
}

func (m *Memory) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (m *Memory) Put(ctx context.Context, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.values[key] = bytes.Clone(value)
	m.mu.Unlock()
	return nil
}

func (m *Memory) CompareAndSwap(ctx context.Context, key string, old, new []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.values[key]
	if old == nil {
		if exists {
			return false, nil
		}
	} else if !exists || !bytes.Equal(current, old) {
		return false, nil
	}
	if new == nil {
		delete(m.values, key)
	} else {
		m.values[key] = bytes.Clone(new)
	}
	return true, nil
}

func (m *Memory) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.values, key)
	m.mu.Unlock()
	return nil
}

var _ Store = (*Memory)(nil)
