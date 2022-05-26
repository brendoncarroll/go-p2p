package p2pke

import (
	"sync"
	"time"
)

type Timer struct {
	mu    sync.Mutex
	timer *time.Timer
}

func newTimer(fn func()) *Timer {
	t := &Timer{}
	t.timer = time.AfterFunc(time.Hour, func() {
		fn()
	})
	t.timer.Stop()
	return t
}

func (t *Timer) Reset(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timer.Reset(d)
}

func (t *Timer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timer.Stop()
}
