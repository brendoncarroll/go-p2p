package kademlia

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"go.brendoncarroll.net/p2p"
)

// DHTNode is the state of a single node in a DHT.
type DHTNode struct {
	params DHTNodeParams

	mu    sync.RWMutex
	peers Cache[[]byte]
	data  Cache[[]byte]
}

type DHTNodeParams struct {
	LocalID                      p2p.PeerID
	PeerCacheSize, DataCacheSize int
	Now                          func() time.Time
	MaxPeerTTL                   time.Duration
	MaxDataTTL                   time.Duration
}

func NewDHTNode(params DHTNodeParams) *DHTNode {
	if params.Now == nil {
		params.Now = time.Now
	}
	if params.MaxPeerTTL == 0 {
		params.MaxPeerTTL = 60 * time.Second
	}
	if params.MaxDataTTL == 0 {
		params.MaxDataTTL = 300 * time.Second
	}
	minPerBucket := 1
	locus := params.LocalID[:]
	if params.PeerCacheSize < minPerBucket*len(locus)*8 {
		locus = locus[:params.PeerCacheSize/8]
	}
	n := &DHTNode{
		params: params,
		peers:  *NewCache[[]byte](locus, params.PeerCacheSize, minPerBucket),
	}
	if params.DataCacheSize > 0 {
		n.data = *NewCache[[]byte](locus, params.DataCacheSize, 0)
	}
	return n
}

func (node *DHTNode) AddPeer(id p2p.PeerID, info []byte) bool {
	node.mu.Lock()
	defer node.mu.Unlock()
	if id == node.params.LocalID {
		return false
	}
	k := id[:]
	_, added := node.peers.Update(k, func(e Entry[[]byte], exists bool) Entry[[]byte] {
		v := append([]byte{}, info...)
		now := time.Now()
		e2 := e
		if !exists {
			e2.Key = k
			e2.CreatedAt = now
		}
		e2.ExpiresAt = now.Add(node.params.MaxPeerTTL)
		e2.Value = v
		return e2
	})
	return added
}

func (node *DHTNode) RemovePeer(localID p2p.PeerID) bool {
	node.mu.Lock()
	defer node.mu.Unlock()
	e := node.peers.Delete(localID[:])
	return e != nil
}

// GetPeerInfo returns information associated with the peer, if it exists.
func (node *DHTNode) GetPeer(x p2p.PeerID) ([]byte, bool) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	return node.peers.Get(x[:], node.params.Now())
}

func (node *DHTNode) HasPeer(x p2p.PeerID) bool {
	_, yes := node.GetPeer(x)
	return yes
}

func (node *DHTNode) ListPeers(limit int) (ret []p2p.PeerID) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	node.peers.ForEach(nil, func(e Entry[[]byte]) bool {
		if limit > 0 && len(ret) >= limit {
			return false
		}
		ret = append(ret, peerIDFromBytes(e.Key))
		return true
	})
	return ret
}

// ListNodeInfos returns the n nodes closest to key.
func (node *DHTNode) ListNodeInfos(key []byte, n int) (ret []NodeInfo) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	node.peers.ForEach(key, func(e Entry[[]byte]) bool {
		if len(ret) >= n {
			return false
		}
		ret = append(ret, NodeInfo{
			ID:   peerIDFromBytes(e.Key),
			Info: e.Value,
		})
		return true
	})
	return ret
}

func (node *DHTNode) closerNodes(key []byte) (ret []NodeInfo) {
	node.peers.ForEachCloser(key, func(peerEnt Entry[[]byte]) bool {
		ret = append(ret, NodeInfo{
			ID:   peerIDFromBytes(peerEnt.Key),
			Info: peerEnt.Value,
		})
		return true
	})
	return ret
}

// Put attempts to insert the key into the nodes's data cache.
func (node *DHTNode) Put(key, value []byte, ttl time.Duration) bool {
	createdAt := time.Now()
	expiresAt := createdAt.Add(ttl)
	node.mu.Lock()
	_, added := node.data.Put(key, value, createdAt, expiresAt)
	node.mu.Unlock()
	return added
}

func (node *DHTNode) LocalID() p2p.PeerID {
	return node.params.LocalID
}

func (node *DHTNode) Get(key []byte) []byte {
	node.mu.RLock()
	defer node.mu.RUnlock()
	now := node.params.Now()
	v, _ := node.data.Get(key, now)
	return v
}

func (node *DHTNode) WouldAdd(key []byte) bool {
	return node.data.WouldAdd(key, node.params.Now())
}

func (node *DHTNode) Count() int {
	return node.data.Count()
}

func (n *DHTNode) String() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return fmt.Sprintf("DHTNode{locus=%v, peers=%v, data=%v}", n.params.LocalID, n.peers.Count(), n.data.Count())
}

// HandlePut handles a put from another node.
func (node *DHTNode) HandlePut(from p2p.PeerID, req PutReq) (PutRes, error) {
	ttl := time.Duration(req.TTLms) * time.Millisecond
	if ttl > node.params.MaxDataTTL {
		ttl = node.params.MaxDataTTL
	}
	createdAt := time.Now()
	expiresAt := createdAt.Add(ttl)
	node.mu.Lock()
	evicted, added := node.data.Put(req.Key, req.Value, createdAt, expiresAt)
	node.mu.Unlock()
	return PutRes{
		Accepted: wasAccepted(req.Key, evicted, added),
		Closer:   node.closerNodes(req.Key),
	}, nil
}

func (n *DHTNode) HandleGet(from p2p.PeerID, req GetReq) (GetRes, error) {
	v := n.Get(req.Key)
	return GetRes{
		Value:  v,
		Closer: n.closerNodes(req.Key),
	}, nil
}

func (n *DHTNode) HandleFindNode(from p2p.PeerID, req FindNodeReq) (FindNodeRes, error) {
	limit := req.Limit
	if limit > 10 {
		limit = 10
	}
	nodes := n.ListNodeInfos(req.Target[:], limit)
	return FindNodeRes{
		Nodes: nodes,
	}, nil
}

func peerIDFromBytes(x []byte) (ret p2p.PeerID) {
	copy(ret[:], x)
	return ret
}

func wasAccepted[V any](key []byte, evicted *Entry[V], added bool) bool {
	return added || evicted == nil || !bytes.Equal(evicted.Key, key)
}
