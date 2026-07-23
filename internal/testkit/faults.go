package testkit

import "sync"

type Faults struct {
	mu     sync.Mutex
	points map[string][]error
}

func (f *Faults) Add(point string, failures ...error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.points == nil {
		f.points = make(map[string][]error)
	}
	f.points[point] = append(f.points[point], failures...)
}

func (f *Faults) Check(point string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	failures := f.points[point]
	if len(failures) == 0 {
		return nil
	}
	failure := failures[0]
	if len(failures) == 1 {
		delete(f.points, point)
	} else {
		f.points[point] = failures[1:]
	}
	return failure
}
