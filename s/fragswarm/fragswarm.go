package fragswarm

import (
	"context"
	"encoding/binary"
	"runtime"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const Overhead = 3 * binary.MaxVarintLen32

func New(x p2p.Swarm, mtu int) p2p.Swarm {
	return newSwarm(x, mtu)
}

func NewSecure(x p2p.SecureSwarm, mtu int) p2p.SecureSwarm {
	y := newSwarm(x, mtu)
	return p2p.ComposeSecureSwarm(y, x)
}

type swarm struct {
	p2p.Swarm
	mtu int

	cf context.CancelFunc

	mu     sync.Mutex
	aggs   map[aggKey]*aggregator
	msgIDs map[string]uint32
	tells  *swarmutil.TellHub
}

func newSwarm(x p2p.Swarm, mtu int) *swarm {
	ctx, cf := context.WithCancel(context.Background())
	s := &swarm{
		Swarm: x,
		mtu:   mtu,

		cf:     cf,
		aggs:   make(map[aggKey]*aggregator),
		msgIDs: make(map[string]uint32),
		tells:  swarmutil.NewTellHub(),
	}
	go s.recvLoops(ctx, runtime.GOMAXPROCS(0))
	go s.cleanupLoop(ctx)
	return s
}

func (s *swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	if p2p.VecSize(data) > s.mtu {
		return p2p.ErrMTUExceeded
	}
	underMTU := s.Swarm.MTU(ctx, addr) - Overhead
	s.mu.Lock()
	id := s.msgIDs[keyForAddr(addr)]
	s.msgIDs[keyForAddr(addr)]++
	s.mu.Unlock()

	size := p2p.VecSize(data)
	data2 := p2p.VecBytes(nil, data)
	total := size / underMTU
	if size%underMTU > 0 {
		total++
	}
	if total == 0 {
		total = 1
	}
	if total == 1 {
		msg := newMessage(id, 0, 1, data2)
		return s.Swarm.Tell(ctx, addr, msg)
	}

	eg := errgroup.Group{}
	for part := 0; part < total; part++ {
		part := part
		start := underMTU * part
		end := size
		if start+underMTU < end {
			end = start + underMTU
		}
		eg.Go(func() error {
			msg := newMessage(id, uint8(part), uint8(total), data2[start:end])
			return s.Swarm.Tell(ctx, addr, msg)
		})
	}
	return eg.Wait()
}

func (s *swarm) Receive(ctx context.Context, th p2p.TellHandler) error {
	return s.tells.Receive(ctx, th)
}

func (s *swarm) MaxIncomingSize() int {
	return s.mtu
}

func (s *swarm) recvLoops(ctx context.Context, numWorkers int) error {
	eg, ctx := errgroup.WithContext(ctx)
	for i := 0; i < numWorkers; i++ {
		eg.Go(func() error {
			for {
				if err := s.Swarm.Receive(ctx, func(m p2p.Message) {
					if err := s.handleTell(ctx, m); err != nil {
						logrus.Error(err)
					}
				}); err != nil {
					return err
				}
			}
		})
	}
	err := eg.Wait()
	s.tells.CloseWithError(err)
	return err
}

// handleTell will not retain x.Payload
func (s *swarm) handleTell(ctx context.Context, x p2p.Message) error {
	id, part, totalParts, data, err := parseMessage(x.Payload)
	if err != nil {
		log := logrus.WithFields(logrus.Fields{"src": x.Src})
		log.Error("error parsing message")
		return err
	}
	// if there is only one part skip creating the aggregator
	if totalParts == 1 {
		return s.tells.Deliver(ctx, p2p.Message{
			Src:     x.Src,
			Dst:     x.Dst,
			Payload: data,
		})
	}
	key := aggKey{addr: keyForAddr(x.Src), id: id}
	s.mu.Lock()
	agg, exists := s.aggs[key]
	if !exists {
		agg = newAggregator()
		s.aggs[key] = agg
	}
	s.mu.Unlock()
	if agg.addPart(part, totalParts, data) {
		err = s.tells.Deliver(ctx, p2p.Message{
			Src:     x.Src,
			Dst:     x.Dst,
			Payload: agg.assemble(),
		})
		s.mu.Lock()
		delete(s.aggs, key)
		s.mu.Unlock()
	}
	return err
}

func (s *swarm) MTU(ctx context.Context, target p2p.Addr) int {
	return s.mtu
}

func (s *swarm) Close() error {
	s.cf()
	return s.Swarm.Close()
}

func (s *swarm) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.cleanup()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *swarm) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Second)
	for k, a := range s.aggs {
		if a.createdAt.Before(cutoff) {
			delete(s.aggs, k)
		}
	}
}

type aggKey struct {
	addr string
	id   uint32
}

type aggregator struct {
	mu        sync.Mutex
	createdAt time.Time
	parts     [][]byte
}

func newAggregator() *aggregator {
	return &aggregator{createdAt: time.Now()}
}

func (a *aggregator) addPart(part, total uint8, data []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parts == nil {
		a.parts = make([][]byte, total)
	}
	a.parts[int(part)] = append([]byte{}, data...)
	for i := range a.parts {
		if a.parts[i] == nil {
			return false
		}
	}
	return true
}

func (a *aggregator) assemble() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parts == nil {
		return nil
	}
	var buf []byte
	for _, part := range a.parts {
		buf = append(buf, part...)
	}
	return buf
}

func newMessage(id uint32, part uint8, total uint8, data []byte) p2p.IOVec {
	var msg [][]byte
	msg = appendUvarint(msg, uint64(id))
	msg = appendUvarint(msg, uint64(part))
	msg = appendUvarint(msg, uint64(total))
	msg = append(msg, data)
	return msg
}

func parseMessage(x []byte) (id uint32, part uint8, total uint8, data []byte, err error) {
	fields := [3]uint64{}
	var n int
	if err := func() error {
		for i := range fields {
			field, n2 := binary.Uvarint(x[n:])
			if n2 < 1 {
				return errors.Errorf("invalid message")
			}
			fields[i] = field
			n += n2
		}
		id = uint32(fields[0])
		part = uint8(fields[1])
		total = uint8(fields[2])
		if part >= total {
			return errors.Errorf("part >= total")
		}
		return nil
	}(); err != nil {
		return 0, 0, 0, nil, err
	}
	return id, part, total, x[n:], nil
}

func appendUvarint(b p2p.IOVec, x uint64) p2p.IOVec {
	buf := [binary.MaxVarintLen64]byte{}
	n := binary.PutUvarint(buf[:], x)
	return append(b, buf[:n])
}

func keyForAddr(x p2p.Addr) string {
	data, err := x.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}
