package kademlia

import (
	"fmt"
	"log"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/exp/slices"
)

type DHTFindNodeParams struct {
	Initial  []NodeInfo
	Target   p2p.PeerID
	Ask      FindNodeFunc
	Validate func(NodeInfo) bool
}

type DHTFindNodeResult struct {
	Info []byte

	Closest   p2p.PeerID
	Contacted int
}

func DHTFindNode(params DHTFindNodeParams) (*DHTFindNodeResult, error) {
	if params.Validate == nil {
		params.Validate = func(NodeInfo) bool { return true }
	}
	var res DHTFindNodeResult
	dhtIterate(params.Initial, params.Target[:], 10, func(node NodeInfo) ([]NodeInfo, bool) {
		if res.Closest.IsZero() || DistanceLt(params.Target[:], node.ID[:], res.Closest[:]) {
			res.Closest = node.ID
			res.Info = node.Info
		}
		if res.Closest == params.Target {
			return nil, false
		}
		resp, err := params.Ask(node, FindNodeReq{
			Target: params.Target,
			Limit:  3,
		})
		if err != nil {
			log.Println(err)
			return nil, true
		}
		res.Contacted++
		nodes2 := resp.Nodes[:0]
		for _, node2 := range resp.Nodes {
			if params.Validate(node2) {
				nodes2 = append(nodes2, node2)
			}
		}
		return nodes2, true
	})
	var err error
	if res.Closest != params.Target {
		err = fmt.Errorf("could not find %v closest %v", params.Target, res.Closest)
	}
	return &res, err
}

type DHTJoinParams struct {
	Initial []NodeInfo
	Target  p2p.PeerID
	Ask     FindNodeFunc
	AddPeer func(p2p.PeerID, []byte) bool
}

// DHTJoin joins a node to the rest of the DHT.
func DHTJoin(params DHTJoinParams) int {
	var added int
	dhtIterate(params.Initial, params.Target[:], len(params.Initial), func(node NodeInfo) ([]NodeInfo, bool) {
		if params.AddPeer(node.ID, node.Info) {
			added++
		}
		resp, err := params.Ask(node, FindNodeReq{
			Target: params.Target,
			Limit:  10,
		})
		if err != nil {
			return nil, true
		}
		return resp.Nodes, true
	})
	return added
}

type DHTGetParams struct {
	Key      []byte
	Initial  []NodeInfo
	Validate func([]byte) bool
	Ask      GetFunc
}

type DHTGetResult struct {
	// Value is the value associated with the key
	Value []byte
	// From is the node that returned the value
	From p2p.PeerID
	// ExpiresAt is when the entry expires
	ExpiresAt time.Time
	// Closest is the peer closest to the key that we contacted.
	Closest      p2p.PeerID
	NumContacted int
	NumResponded int
}

// DHTPGet performs the Kademlia FIND_VALUE operation.
func DHTGet(params DHTGetParams) (*DHTGetResult, error) {
	if params.Validate == nil {
		params.Validate = func([]byte) bool { return true }
	}
	req := GetReq{Key: params.Key}
	peers := params.Initial

	var res DHTGetResult
	dhtIterate(peers, params.Key, 3, func(node NodeInfo) ([]NodeInfo, bool) {
		// if we are getting further away then break
		if !res.From.IsZero() && DistanceLt(params.Key, res.From[:], node.ID[:]) {
			return nil, false
		}
		res.NumContacted++
		resp, err := params.Ask(node, req)
		if err != nil {
			log.Println(err)
			return nil, true
		}
		res.NumResponded++
		res.Closest = node.ID
		if resp.Value != nil && params.Validate(resp.Value) {
			res.Value = resp.Value
			res.From = node.ID
		}
		return resp.Closer, true
	})
	var err error
	if res.From.IsZero() {
		err = fmt.Errorf("could not find key %s, closest peer %v", params.Key, res.From[:])
	}
	return &res, err
}

type DHTPutParams struct {
	Initial    []NodeInfo
	Key, Value []byte
	TTL        time.Duration

	Ask         PutFunc
	MinAccepted int
}

type DHTPutResult struct {
	Closest  p2p.PeerID
	Accepted int

	Contacted int
	Responded int
}

// DHTPut performs the Kademlia STORE operation
func DHTPut(params DHTPutParams) (*DHTPutResult, error) {
	if params.MinAccepted < 1 {
		params.MinAccepted = 2
	}
	req := PutReq{
		Key:   params.Key,
		Value: params.Value,
		TTLms: uint64(params.TTL.Milliseconds()),
	}
	var res DHTPutResult
	dhtIterate(params.Initial, params.Key, len(params.Initial)*3/2, func(node NodeInfo) ([]NodeInfo, bool) {
		res.Contacted++
		resp, err := params.Ask(node, req)
		if err != nil {
			return nil, true
		}
		res.Responded++
		if resp.Accepted {
			res.Accepted++
			if DistanceLt(params.Key, node.ID[:], res.Closest[:]) {
				res.Closest = node.ID
			}
		}
		return resp.Closer, true
	})
	var err error
	if res.Accepted < params.MinAccepted {
		err = fmt.Errorf("failed to put accepted=%d min=%d", res.Accepted, params.MinAccepted)
	}
	return &res, err
}

// dhtIterate calls fn with the closest known peer, and updates the set of known peers
// with newPeers.
// it is up to the caller to determine whether they want to stop at the best peer
// n is the number of candidate peers to consider at a time.
func dhtIterate(nodes []NodeInfo, key []byte, n int, fn func(node NodeInfo) (newPeers []NodeInfo, cont bool)) {
	if n < 1 {
		panic(n)
	}
	for len(nodes) > 0 {
		// TODO: use a heap
		slices.SortFunc(nodes, func(a, b NodeInfo) bool {
			return DistanceLt(key, a.ID[:], b.ID[:])
		})
		if len(nodes) > n {
			nodes = nodes[:n]
		}
		var node NodeInfo
		node, nodes = pop(nodes)

		newNodes, cont := fn(node)
		if !cont {
			break
		}
		for _, newNode := range newNodes {
			if !DistanceLt(key, newNode.ID[:], node.ID[:]) {
				continue // ignore peers that aren't actually closer
			}
			if !contains(nodes, newNode, func(a, b NodeInfo) bool {
				return a.ID == b.ID
			}) {
				nodes = append(nodes, newNode)
			}
		}
	}
}

func pop[E any, S ~[]E](xs S) (x E, _ S) {
	xs[0], xs[len(xs)-1] = xs[len(xs)-1], xs[0]
	x = xs[len(xs)-1]
	xs = xs[:len(xs)-1]
	return x, xs
}

func contains[E any, S ~[]E](xs S, x E, fn func(a, b E) bool) bool {
	for i := range xs {
		if fn(xs[i], x) {
			return true
		}
	}
	return false
}
