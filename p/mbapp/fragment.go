package mbapp

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type collector struct {
	isAsk     bool
	isReply   bool
	partCount int
	createdAt time.Time

	mu     sync.Mutex
	bitMap bitMap
	buf    []byte
}

func newCollector(isAsk, isReply bool, partCount, totalSize int, now time.Time) *collector {
	return &collector{
		isAsk:     isAsk,
		isReply:   isReply,
		partCount: partCount,

		buf:    make([]byte, totalSize),
		bitMap: newBitMap(partCount),
	}
}

func (c *collector) addPart(partIndex int, data []byte) error {
	if partIndex >= c.partCount {
		return errors.Errorf("partIndex %d >= partCount %d", partIndex, c.partCount)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bitMap.get(partIndex) {
		return nil
	}
	partSize := len(c.buf) / c.partCount
	offset := partSize * partIndex
	if offset > len(c.buf) {
		return errors.Errorf("incorrect partSize=%v or partIndex=%v, offset=%v", partSize, partIndex, offset)
	}
	copy(c.buf, data)
	c.bitMap.set(partIndex, true)
	return nil
}

func (c *collector) isComplete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bitMap.allSet()
}

func (c *collector) withBuffer(fn func([]byte) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fn(c.buf)
}

type fragLayer struct {
	ttl        time.Duration
	mu         sync.RWMutex
	collectors map[GroupID]*collector

	cf context.CancelFunc
}

func newFragLayer() *fragLayer {
	ctx, cf := context.WithCancel(context.Background())
	fl := &fragLayer{
		cf:         cf,
		collectors: make(map[GroupID]*collector),
	}
	go fl.cleanupLoop(ctx)
	return fl
}

func (fl *fragLayer) getCollector(id GroupID, isAsk, isReply bool, partCount, totalSize int) (*collector, error) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	col, exists := fl.collectors[id]
	if !exists {
		now := time.Now().UTC()
		col = newCollector(isAsk, isReply, partCount, totalSize, now)
		fl.collectors[id] = col
	}
	// TODO: check that all parameters match, or error
	return col, nil
}

func (fl *fragLayer) dropCollector(id GroupID) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	delete(fl.collectors, id)
}

func (fl *fragLayer) cleanupLoop(ctx context.Context) {
	const period = time.Minute
	ticker := time.NewTicker(period)
	for {
		func() {
			fl.mu.Lock()
			defer fl.mu.Unlock()
			now := time.Now().UTC()
			for id, c := range fl.collectors {
				if now.Sub(c.createdAt) > fl.ttl {
					delete(fl.collectors, id)
				}
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (fl *fragLayer) Close() error {
	fl.cf()
	return nil
}
