package mbapp

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.brendoncarroll.net/p2p"
)

type collector struct {
	partCount int
	createdAt time.Time

	mu     sync.Mutex
	bitMap bitMap
	buf    []byte
}

func newCollector(partCount, totalSize int, now time.Time) *collector {
	return &collector{
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
	var offset int
	if partIndex == (c.partCount - 1) {
		offset = len(c.buf) - len(data)
	} else {
		offset = len(data) * partIndex
	}
	if offset >= len(c.buf) {
		return errors.Errorf("invalid offset len=%d for buf of len=%d", offset, len(c.buf))
	}
	copy(c.buf[offset:], data)
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

type collectorID struct {
	Remote  string
	GroupID GroupID
}

type fragLayer struct {
	ttl        time.Duration
	mu         sync.RWMutex
	collectors map[collectorID]*collector

	cf context.CancelFunc
}

func newFragLayer() *fragLayer {
	ctx, cf := context.WithCancel(context.Background())
	fl := &fragLayer{
		cf:         cf,
		collectors: make(map[collectorID]*collector),
	}
	go fl.cleanupLoop(ctx)
	return fl
}

func (fl *fragLayer) handlePart(remote p2p.Addr, gid GroupID, partIndex, partCount uint16, totalSize uint32, body []byte, fn func([]byte) error) error {
	cid := collectorID{Remote: remote.String(), GroupID: gid}
	if partCount < 2 && !disableFastPath {
		return fn(body)
	}
	col, err := fl.getCollector(cid, partCount, totalSize)
	if err != nil {
		return err
	}
	col.addPart(int(partIndex), body)
	if !col.isComplete() {
		return nil
	}
	defer fl.dropCollector(cid)
	return col.withBuffer(fn)
}

func (fl *fragLayer) getCollector(cid collectorID, partCount uint16, totalSize uint32) (*collector, error) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	col, exists := fl.collectors[cid]
	if !exists {
		now := time.Now().UTC()
		col = newCollector(int(partCount), int(totalSize), now)
		fl.collectors[cid] = col
	}
	// TODO: check that all parameters match, or error
	return col, nil
}

func (fl *fragLayer) dropCollector(cid collectorID) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	delete(fl.collectors, cid)
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
