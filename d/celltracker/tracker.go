package celltracker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-state/cells"
)

// CellTracker is p2p tracker implemented on top of a CAS cell
type CellTracker struct {
	cell cells.Cell
}

func New(cell cells.Cell) *CellTracker {
	return &CellTracker{
		cell: cell,
	}
}

func (ct *CellTracker) Announce(ctx context.Context, id p2p.PeerID, addrs []string, ttl time.Duration) error {
	now := time.Now()
	sightings := []Sighting{}
	for _, addr := range addrs {
		sightings = append(sightings, Sighting{
			Addr:      addr,
			Timestamp: now,
			TTL:       ttl,
		})
	}

	return ct.apply(ctx, func(x TrackerState) (*TrackerState, error) {
		if x.Peers == nil {
			x.Peers = make(map[p2p.PeerID][]Sighting, 1)
		}
		x.Peers[id] = sightings
		return &x, nil
	})
}

func (ct *CellTracker) Find(ctx context.Context, id p2p.PeerID) ([]string, error) {
	return ct.ListAddrs(ctx, id)
}

func (ct *CellTracker) ListPeers(ctx context.Context) ([]p2p.PeerID, error) {
	peerIDs := []p2p.PeerID{}
	state, err := ct.get(ctx)
	if err != nil {
		return nil, err
	}
	for id := range state.Peers {
		peerIDs = append(peerIDs, id)
	}
	return peerIDs, nil
}

func (ct *CellTracker) ListAddrs(ctx context.Context, id p2p.PeerID) ([]string, error) {
	addrs := []string{}
	state, err := ct.get(ctx)
	if err != nil {
		return nil, err
	}
	for _, sighting := range state.Peers[id] {
		addrs = append(addrs, sighting.Addr)
	}
	return addrs, nil
}

func (ct *CellTracker) Reset(ctx context.Context) error {
	return cells.Apply(ctx, ct.cell, func(current []byte) ([]byte, error) {
		return nil, nil
	})
}

func (ct *CellTracker) get(ctx context.Context) (*TrackerState, error) {
	current, err := cells.GetBytes(ctx, ct.cell)
	if err != nil {
		return nil, err
	}
	currentState := TrackerState{}
	if err := json.Unmarshal(current, &currentState); err != nil {
		return nil, err
	}
	return &currentState, nil
}

func (ct *CellTracker) apply(ctx context.Context, fn func(TrackerState) (*TrackerState, error)) error {
	return cells.Apply(ctx, ct.cell, func(current []byte) ([]byte, error) {
		currentState := TrackerState{}
		if len(current) > 1 {
			if err := json.Unmarshal(current, &currentState); err != nil {
				return nil, err
			}
		}
		nextState, err := fn(currentState)
		if err != nil {
			return nil, err
		}
		next, err := json.Marshal(nextState)
		if err != nil {
			panic(err)
		}
		return next, nil
	})
}

type TrackerState struct {
	Peers map[p2p.PeerID][]Sighting `json:"peers"`
}

type Sighting struct {
	Addr      string        `json:"addr"`
	Timestamp time.Time     `json:"timestamp"`
	TTL       time.Duration `json:"ttl"`
}
