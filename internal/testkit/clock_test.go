package testkit

import (
	"testing"
	"time"
)

func TestFakeClock(t *testing.T) {
	start := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	first := clock.After(time.Second)
	second := clock.After(2 * time.Second)

	clock.Advance(time.Second)
	if got := <-first; !got.Equal(start.Add(time.Second)) {
		t.Fatalf("first timer = %v", got)
	}
	select {
	case <-second:
		t.Fatal("second timer fired early")
	default:
	}

	clock.Advance(time.Second)
	if got := <-second; !got.Equal(start.Add(2 * time.Second)) {
		t.Fatalf("second timer = %v", got)
	}
	if got := clock.Now(); !got.Equal(start.Add(2 * time.Second)) {
		t.Fatalf("Now() = %v", got)
	}
}
