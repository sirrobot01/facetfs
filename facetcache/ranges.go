package facetcache

import "sort"

// rng is a half-open byte range [pos, pos+size).
type rng struct {
	pos, size int64
}

func (r rng) end() int64 { return r.pos + r.size }

// rangeSet is a sorted, coalesced set of non-empty byte ranges. Entries never
// overlap and never touch, so any covered interval is covered by exactly one
// entry. Streaming produces very few distinct extents, which is why a sorted
// slice with binary search beats a tree here.
type rangeSet []rng

// search returns the index of the first entry whose end is after pos.
func (s rangeSet) search(pos int64) int {
	return sort.Search(len(s), func(i int) bool { return s[i].end() > pos })
}

// insert adds r to the set, merging any entries it overlaps or touches.
func (s *rangeSet) insert(r rng) {
	if r.size <= 0 {
		return
	}
	set := *s
	// The merge span starts at the first entry that overlaps or touches
	// r.pos from the left (end >= r.pos, not > as in queries), so adjacent
	// entries coalesce in both directions.
	i := sort.Search(len(set), func(k int) bool { return set[k].end() >= r.pos })
	j := i
	for j < len(set) && set[j].pos <= r.end() {
		j++
	}
	if i == j {
		// No neighbour merges; splice r in at i.
		set = append(set, rng{})
		copy(set[i+1:], set[i:])
		set[i] = r
		*s = set
		return
	}
	pos := min(r.pos, set[i].pos)
	end := max(r.end(), set[j-1].end())
	set[i] = rng{pos, end - pos}
	set = append(set[:i+1], set[j:]...)
	*s = set
}

// remove deletes [r.pos, r.end()) from the set, splitting entries that
// straddle a boundary.
func (s *rangeSet) remove(r rng) {
	if r.size <= 0 {
		return
	}
	set := *s
	i := set.search(r.pos)
	if i == len(set) {
		return
	}
	// Build into a fresh slice: splitting an entry in place would append
	// over the tail entries while they are still being read.
	out := make(rangeSet, i, len(set)+1)
	copy(out, set[:i])
	for ; i < len(set); i++ {
		e := set[i]
		if e.pos >= r.end() {
			out = append(out, set[i:]...)
			break
		}
		if e.pos < r.pos {
			out = append(out, rng{e.pos, r.pos - e.pos})
		}
		if e.end() > r.end() {
			out = append(out, rng{r.end(), e.end() - r.end()})
		}
	}
	*s = out
}

// present reports whether the whole of r is covered. The set is coalesced,
// so coverage means a single entry spans r.
func (s rangeSet) present(r rng) bool {
	if r.size <= 0 {
		return true
	}
	i := s.search(r.pos)
	return i < len(s) && s[i].pos <= r.pos && s[i].end() >= r.end()
}

// findMissing trims the covered prefix off r and returns the remainder. The
// result keeps r's end; its size is zero when r is fully covered.
func (s rangeSet) findMissing(r rng) rng {
	if r.size <= 0 {
		return rng{r.pos, 0}
	}
	i := s.search(r.pos)
	if i < len(s) && s[i].pos <= r.pos {
		covered := s[i].end() - r.pos
		if covered >= r.size {
			return rng{r.end(), 0}
		}
		return rng{r.pos + covered, r.size - covered}
	}
	return r
}

// missingWithin appends the uncovered sub-ranges of r to dst and returns it.
// dst lets callers reuse a stack scratch slice on the fill path.
func (s rangeSet) missingWithin(r rng, dst []rng) []rng {
	pos := r.pos
	for pos < r.end() {
		m := s.findMissing(rng{pos, r.end() - pos})
		if m.size == 0 {
			break
		}
		// Clip the missing run at the next covered entry, if any starts
		// inside it.
		i := s.search(m.pos)
		end := m.end()
		if i < len(s) && s[i].pos < end {
			end = s[i].pos
		}
		dst = append(dst, rng{m.pos, end - m.pos})
		pos = end
	}
	return dst
}

// size returns the total number of covered bytes.
func (s rangeSet) size() int64 {
	var n int64
	for _, e := range s {
		n += e.size
	}
	return n
}

// clone returns an independent copy for metadata snapshots.
func (s rangeSet) clone() rangeSet {
	if len(s) == 0 {
		return nil
	}
	out := make(rangeSet, len(s))
	copy(out, s)
	return out
}
