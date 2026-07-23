package coord

import "testing"

func TestBus(t *testing.T) {
	var bus Bus[int]
	events, cancel := bus.Subscribe(1)
	bus.Publish(1)
	if got := <-events; got != 1 {
		t.Fatalf("event = %d", got)
	}
	cancel()
	if _, ok := <-events; ok {
		t.Fatal("subscription remained open")
	}
}

func TestBusClosesSlowSubscriber(t *testing.T) {
	var bus Bus[int]
	events, _ := bus.Subscribe(1)
	bus.Publish(1)
	bus.Publish(2)
	if got := <-events; got != 1 {
		t.Fatalf("event = %d", got)
	}
	if _, ok := <-events; ok {
		t.Fatal("slow subscription remained open")
	}
}
