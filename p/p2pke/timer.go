package p2pke

import (
	"sync"
	"time"
)

type Timer struct {
	timer     *time.Timer
	mu        sync.RWMutex
	runMu     sync.Mutex
	isPending bool
}

func newTimer(fn func()) *Timer {
	t := &Timer{}
	t.timer = time.AfterFunc(time.Hour, func() {
		t.runMu.Lock()
		defer t.runMu.Unlock()
		t.mu.Lock()
		if !t.isPending {
			t.mu.Unlock()
			return
		}
		t.isPending = false
		t.mu.Unlock()
		fn()
	})
	t.Stop()
	return t
}

func (t *Timer) Reset(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.isPending = true
	t.timer.Reset(d)
}

func (t *Timer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.isPending = false
	t.timer.Stop()
}

func (t *Timer) StopSync() {
	t.Stop()
	t.runMu.Lock()
	t.Stop()
	t.runMu.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.mu.RLock()
	defer timer.mu.RUnlock()
	return timer.isPending
}
