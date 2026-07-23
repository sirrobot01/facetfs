package testkit

import (
	"sort"
	"sync"
	"time"
)

type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	nextID uint64
	timers []fakeTimer
}

type fakeTimer struct {
	id       uint64
	deadline time.Time
	ch       chan time.Time
}

func NewFakeClock(now time.Time) *FakeClock {
	return &FakeClock{now: now}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.nextID++
	c.timers = append(c.timers, fakeTimer{id: c.nextID, deadline: c.now.Add(d), ch: ch})
	sort.Slice(c.timers, func(i, j int) bool {
		if c.timers[i].deadline.Equal(c.timers[j].deadline) {
			return c.timers[i].id < c.timers[j].id
		}
		return c.timers[i].deadline.Before(c.timers[j].deadline)
	})
	return ch
}

func (c *FakeClock) Advance(d time.Duration) {
	if d < 0 {
		panic("testkit: cannot move clock backwards")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for len(c.timers) > 0 && !c.timers[0].deadline.After(c.now) {
		timer := c.timers[0]
		c.timers = c.timers[1:]
		timer.ch <- timer.deadline
	}
}
