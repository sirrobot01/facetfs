package coord

import "sync"

type Bus[T any] struct {
	mu          sync.Mutex
	next        uint64
	subscribers map[uint64]chan T
}

func (b *Bus[T]) Subscribe(buffer int) (<-chan T, func()) {
	if buffer < 1 {
		buffer = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subscribers == nil {
		b.subscribers = make(map[uint64]chan T)
	}
	b.next++
	id := b.next
	ch := make(chan T, buffer)
	b.subscribers[id] = ch
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if subscriber := b.subscribers[id]; subscriber != nil {
			delete(b.subscribers, id)
			close(subscriber)
		}
	}
}

func (b *Bus[T]) Publish(event T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, subscriber := range b.subscribers {
		select {
		case subscriber <- event:
		default:
			delete(b.subscribers, id)
			close(subscriber)
		}
	}
}
