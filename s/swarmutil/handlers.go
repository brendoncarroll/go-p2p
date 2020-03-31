package swarmutil

import (
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

// TODO: not sure how do this with atomics
var thlocks = sync.Map{}
var ahlocks = sync.Map{}

func AtomicSetTH(dst *p2p.TellHandler, x p2p.TellHandler) {
	v, _ := thlocks.LoadOrStore(dst, &sync.RWMutex{})
	mu := v.(*sync.RWMutex)
	mu.Lock()
	*dst = x
	mu.Unlock()
}

func AtomicGetTH(src *p2p.TellHandler) p2p.TellHandler {
	v, _ := thlocks.LoadOrStore(src, &sync.RWMutex{})
	mu := v.(*sync.RWMutex)
	mu.RLock()
	x := *src
	mu.RUnlock()
	return x
}

func AtomicSetAH(dst *p2p.AskHandler, x p2p.AskHandler) {
	v, _ := ahlocks.LoadOrStore(dst, &sync.RWMutex{})
	mu := v.(*sync.RWMutex)
	mu.Lock()
	*dst = x
	mu.Unlock()
}

func AtomicGetAH(src *p2p.AskHandler) p2p.AskHandler {
	v, _ := ahlocks.LoadOrStore(src, &sync.RWMutex{})
	mu := v.(*sync.RWMutex)
	mu.RLock()
	x := *src
	mu.RUnlock()
	return x
}
