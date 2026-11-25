package agent

import "sync"

// changeSignal wakes every waiter at the next change: each wait returns a
// channel that the next fire closes.
type changeSignal struct {
	mu sync.Mutex
	ch chan struct{}
}

func (s *changeSignal) wait() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch == nil {
		s.ch = make(chan struct{})
	}
	return s.ch
}

func (s *changeSignal) fire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch != nil {
		close(s.ch)
		s.ch = nil
	}
}

// ForwardingChanged returns a channel closed at the next change of this
// node's configuration or routes. Take it before checking a route, so a
// change between the check and the wait is not missed.
func (r *DataPlane) ForwardingChanged() <-chan struct{} {
	return r.forwarding.wait()
}
