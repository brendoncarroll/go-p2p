package kademlia

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
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
	Validate                     func(k, v []byte) bool
	Now                          func() time.Time
}

func NewDHTNode(params DHTNodeParams) *DHTNode {
	if params.Validate == nil {
		params.Validate = func(k, v []byte) bool { return true }
	}
	if params.Now == nil {
		params.Now = time.Now
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
	_, added := node.peers.Put(id[:], info)
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
	return node.peers.Get(x[:])
}

func (node *DHTNode) HasPeer(x p2p.PeerID) bool {
	_, yes := node.GetPeer(x)
	return yes
}

func (node *DHTNode) ListPeers(limit int) (ret []p2p.PeerID) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	node.peers.ForEach(func(e Entry[[]byte]) bool {
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
	node.peers.ForEachAsc(key, func(e Entry[[]byte]) bool {
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

func (node *DHTNode) closerPeers(key []byte) (ret []p2p.PeerID) {
	node.peers.ForEachCloser(key, func(peerEnt Entry[[]byte]) bool {
		ret = append(ret, peerIDFromBytes(peerEnt.Key))
		return true
	})
	return ret
}

// Put attempts to insert the key into the DHTNode and returns all the peers
// closer to that
func (node *DHTNode) Put(key, value []byte, expiresAt time.Time) (accepted bool, ret []p2p.PeerID) {
	if !node.params.Validate(key, value) {
		log.Printf("invalid key %q", key)
		return false, nil
	}
	node.mu.Lock()
	e, _ := node.data.Put(key, value)
	accepted = e == nil || !bytes.Equal(e.Key, key)
	node.mu.Unlock()
	node.mu.RLock()
	defer node.mu.RUnlock()
	return accepted, node.closerPeers(key)
}

func (node *DHTNode) LocalID() p2p.PeerID {
	return node.params.LocalID
}

func (node *DHTNode) Get(key []byte, now time.Time) (value []byte, closer []p2p.PeerID) {
	node.mu.RLock()
	defer node.mu.RUnlock()
	v, _ := node.data.Get(key)
	return v, node.closerPeers(key)
}

func (node *DHTNode) WouldAdd(key []byte) bool {
	return node.data.WouldAdd(key)
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
func (n *DHTNode) HandlePut(from p2p.PeerID, req PutReq) (PutRes, error) {
	expiresAt := time.Now().Add(time.Duration(req.TTLms) * time.Millisecond)
	accepted, closer := n.Put(req.Key, req.Value, expiresAt)
	return PutRes{
		Accepted: accepted,
		Closer:   closer,
	}, nil
}

func (n *DHTNode) HandleGet(from p2p.PeerID, req GetReq) (GetRes, error) {
	v, closer := n.Get(req.Key, time.Now())
	return GetRes{
		Value:  v,
		Closer: closer,
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
