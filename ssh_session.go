package socker

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	_SESSION_STATUS_EFFECTIVE int32 = iota
	_SESSION_STATUS_RELEASED
	_SESSION_STATUS_DROP
)

type session struct {
	status int32
	pool   *sessionPool
}

func (s *session) Release() {
	if !atomic.CompareAndSwapInt32(&s.status, _SESSION_STATUS_EFFECTIVE, _SESSION_STATUS_RELEASED) {
		return
	}
	s.pool.put(s)
}

func (s *session) Drop() {
	if !atomic.CompareAndSwapInt32(&s.status, _SESSION_STATUS_EFFECTIVE, _SESSION_STATUS_DROP) {
		return
	}
}

type sessionPool struct {
	size int

	mu sync.RWMutex
	c  chan struct{}
}

func initPoolChan(size int) chan struct{} {
	c := make(chan struct{}, size)
	for i := 0; i < size; i++ {
		c <- struct{}{}
	}
	return c
}

func newSessionPool(size int) *sessionPool {
	const DEFAULT_MAX_SESSION = 10

	var c chan struct{}
	if size == 0 {
		size = DEFAULT_MAX_SESSION
	}
	if size > 0 {
		c = initPoolChan(size)
	}
	return &sessionPool{
		size: size,
		c:    c,
	}
}

func (p *sessionPool) Size() int {
	return p.size
}

func (p *sessionPool) Close() {
	if p.size <= 0 {
		return
	}
	if p.c != nil {
		p.mu.Lock()
		if p.c != nil {
			close(p.c)
			p.c = nil
		}
		p.mu.Unlock()
	}
}

func (p *sessionPool) takeWithTimeout() bool {
	timer := time.NewTimer(time.Millisecond * 10)
	select {
	case <-p.c:
		timer.Stop()
		return true
	case <-timer.C:
		return false
	}
}

func (p *sessionPool) Take() (*session, bool) {
	if p.size <= 0 {
		return &session{pool: p, status: _SESSION_STATUS_EFFECTIVE}, true
	}

	if p.c != nil {
		var taken bool
		p.mu.RLock()
		if p.c != nil {
			<-p.c
			taken = true
		}
		p.mu.RUnlock()
		if taken {
			return &session{pool: p, status: _SESSION_STATUS_EFFECTIVE}, true
		}
	}

	return nil, false
}

func (p *sessionPool) put(s *session) bool {
	if p != s.pool {
		return false
	}
	if p.size <= 0 {
		return true
	}
	if p.c == nil {
		return false
	}

	var putted bool
	p.mu.RLock()
	if p.c != nil {
		select {
		case p.c <- struct{}{}:
			putted = true
		default:
		}
	}
	p.mu.RUnlock()
	return putted
}
