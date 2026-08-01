package facetcache

import (
	"math/rand"
	"testing"
)

// TestRangeSetAgainstBitmap drives a rangeSet and a per-byte bitmap through
// the same random operations and requires them to agree on every query.
func TestRangeSetAgainstBitmap(t *testing.T) {
	const space = 2048
	rnd := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		var s rangeSet
		var bits [space]bool
		for op := 0; op < 60; op++ {
			r := rng{int64(rnd.Intn(space)), int64(rnd.Intn(space / 4))}
			if r.end() > space {
				r.size = space - r.pos
			}
			if rnd.Intn(3) == 0 {
				s.remove(r)
				for i := r.pos; i < r.end(); i++ {
					bits[i] = false
				}
			} else {
				s.insert(r)
				for i := r.pos; i < r.end(); i++ {
					bits[i] = true
				}
			}
		}
		verifyRangeSet(t, s, bits[:])
		for q := 0; q < 40; q++ {
			r := rng{int64(rnd.Intn(space)), int64(1 + rnd.Intn(space/4))}
			if r.end() > space {
				r.size = space - r.pos
			}
			if r.size <= 0 {
				continue
			}
			want := true
			for i := r.pos; i < r.end(); i++ {
				if !bits[i] {
					want = false
					break
				}
			}
			if got := s.present(r); got != want {
				t.Fatalf("present(%v) = %v, want %v (set %v)", r, got, want, s)
			}
			m := s.findMissing(r)
			wantMissing := r
			for wantMissing.size > 0 && bits[wantMissing.pos] {
				wantMissing.pos++
				wantMissing.size--
			}
			if wantMissing.size == 0 {
				wantMissing = rng{r.end(), 0}
			}
			if m != wantMissing {
				t.Fatalf("findMissing(%v) = %v, want %v (set %v)", r, m, wantMissing, s)
			}
			var missing int64
			for _, sub := range s.missingWithin(r, nil) {
				for i := sub.pos; i < sub.end(); i++ {
					if bits[i] {
						t.Fatalf("missingWithin(%v) returned covered byte %d", r, i)
					}
				}
				missing += sub.size
			}
			var wantCount int64
			for i := r.pos; i < r.end(); i++ {
				if !bits[i] {
					wantCount++
				}
			}
			if missing != wantCount {
				t.Fatalf("missingWithin(%v) covered %d bytes, want %d", r, missing, wantCount)
			}
		}
	}
}

// verifyRangeSet checks the structural invariants: sorted, coalesced,
// non-empty entries, and byte-exact agreement with the bitmap.
func verifyRangeSet(t *testing.T, s rangeSet, bits []bool) {
	t.Helper()
	var total int64
	for i, e := range s {
		if e.size <= 0 {
			t.Fatalf("empty entry %v at %d in %v", e, i, s)
		}
		if i > 0 && s[i-1].end() >= e.pos {
			t.Fatalf("uncoalesced or unsorted entries at %d in %v", i, s)
		}
		total += e.size
	}
	if total != s.size() {
		t.Fatalf("size() = %d, want %d", s.size(), total)
	}
	var want int64
	for _, b := range bits {
		if b {
			want++
		}
	}
	if total != want {
		t.Fatalf("set holds %d bytes, bitmap holds %d", total, want)
	}
}
