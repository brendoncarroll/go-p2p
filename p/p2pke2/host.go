package p2pke2

import (
	"context"
	"sync"
	"time"
)

type HostParams[K comparable, S any] struct {
	ChannelStateParams[S]
}

type Host[K comparable, S any] struct {
	params HostParams[K, S]

	mu       sync.RWMutex
	channels map[K]*channelEntry[S]
}

func NewHost[K comparable, S any](params HostParams[K, S]) *Host[K, S] {
	h := &Host[K, S]{
		params: params,

		channels: make(map[K]*channelEntry[S]),
	}
	return h
}

func (h *Host[K, S]) Deliver(out []byte, k K, now Time, inbound []byte) ([]byte, error) {
	ce := h.getEntry(k)
	ce.mu.Lock()
	defer ce.mu.Unlock()
	return ce.state.Deliver(out, now, inbound)
}

func (h *Host[K, S]) Send(ctx context.Context, k K, now Time, msg []byte, fn func([]byte)) error {
	ce := h.getEntry(k)
	var out []byte
	ticker := time.NewTicker(h.params.ChannelStateParams.HandshakeTimeout)
	defer ticker.Stop()
	for {
		if err := func() (err error) {
			ce.mu.Lock()
			defer ce.mu.Unlock()
			if ce.state.ShouldHandshake(now) {
				out, err = ce.state.SendHandshake(out[:0], now)
				if err != nil {
					return err
				}
				fn(out)
			}
			if ce.state.IsReady(now) {
				out, err = ce.state.Send(out[:0], now, msg)
				if err != nil {
					return err
				}
				fn(out)
			}
			return nil
		}(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			now = tai64.FromGoTime(t)
		}
	}
}

func (h *Host[K, S]) Heartbeat(k K, now Time, fn func([]byte)) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ce := range h.channels {
		h.heartbeatEntry(ce, now, fn)
	}
}

func (h *Host[K, S]) heartbeatEntry(ce *channelEntry[S], now Time, fn func([]byte)) {

}

func (h *Host[K, S]) getEntry(k K) *channelEntry[S] {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ce, exists := h.channels[k]
	if !exists {
		upgradeLock(&h.mu)
		if _, exists := h.channels[k]; !exists {
			ce = &channelEntry[S]{
				state: NewChannelState[S](h.params),
			}
			h.channels[k] = ce
		}
		downgradeLock(&h.mu)
	}
	return ce
}

type channelEntry[S any] struct {
	mu    sync.Mutex
	state ChannelState[S]
}

func upgradeLock(mu *sync.RWMutex) {
	mu.RUnlock()
	mu.Lock()
}

func downgradeLock(mu *sync.RWMutex) {
	mu.Unlock()
	mu.RLock()
}
