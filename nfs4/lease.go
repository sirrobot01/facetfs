package nfs4

import "time"

// sweepExpired releases clients whose lease has elapsed. Expired stateids
// remain tombstoned for one more lease interval so late operations receive
// NFS4ERR_EXPIRED instead of being mistaken for unrelated unknown state.
func (st *stateStore) sweepExpired() {
	now := st.now()
	st.mu.Lock()
	for other, expiredAt := range st.expired {
		if !now.Before(expiredAt.Add(st.lease)) {
			delete(st.expired, other)
		}
	}
	for id, expiredAt := range st.expiredIDs {
		if !now.Before(expiredAt.Add(st.lease)) {
			delete(st.expiredIDs, id)
		}
	}
	for id, client := range st.unconfirmed {
		if !now.Before(client.lastRenew.Add(st.lease)) {
			delete(st.unconfirmed, id)
		}
	}
	var files []*openFile
	for _, client := range st.confirmed {
		if now.Before(client.lastRenew.Add(st.lease)) {
			continue
		}
		st.expiredIDs[client.id] = now
		for other, owner := range st.stateOwners {
			if owner.client == client {
				st.expired[other] = now
			}
		}
		files = append(files, st.releaseLocked(client)...)
	}
	st.mu.Unlock()
	for _, file := range files {
		file.Close()
	}
}

func (s *Server) startSweeper() func() {
	s.state.sweepExpired()
	s.sweepMu.Lock()
	s.sweepRefs++
	if s.sweepRefs == 1 {
		stop := make(chan struct{})
		s.sweepStop = stop
		interval := s.lease() / 2
		if interval <= 0 {
			interval = time.Nanosecond
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.state.sweepExpired()
				case <-stop:
					return
				}
			}
		}()
	}
	s.sweepMu.Unlock()

	return func() {
		s.sweepMu.Lock()
		s.sweepRefs--
		if s.sweepRefs == 0 {
			close(s.sweepStop)
			s.sweepStop = nil
		}
		s.sweepMu.Unlock()
	}
}
