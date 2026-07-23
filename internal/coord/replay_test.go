package coord

import (
	"testing"
	"time"

	"github.com/sirrobot01/facetfs/internal/testkit"
)

func TestReplayCache(t *testing.T) {
	clock := testkit.NewFakeClock(time.Unix(0, 0))
	cache := NewReplayCache(clock.Now)
	cache.Put("request", []byte("result"), time.Second)
	value, ok := cache.Get("request")
	if !ok || string(value) != "result" {
		t.Fatalf("Get() = %q, %v", value, ok)
	}
	value[0] = 'x'
	clock.Advance(time.Second)
	if _, ok := cache.Get("request"); ok {
		t.Fatal("expired entry remained in cache")
	}
}
