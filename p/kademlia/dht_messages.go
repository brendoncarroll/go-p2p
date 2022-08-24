package kademlia

import (
	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-tai64"
)

// FindNodeReq is the request in the FindNode rpc
type FindNodeReq struct {
	Target p2p.PeerID `json:"target"`
	Limit  int        `json:"limit"`
}

// FindNodeRes it the response in the FindNode rpc
type FindNodeRes struct {
	Nodes []NodeInfo `json:"nodes"`
}

// NodeInfo is information about a node, and its ID.
type NodeInfo struct {
	ID   p2p.PeerID `json:"id"`
	Info []byte     `json:"info"`
}

// FindNodeFunc is the type of functions implementing the FindNode rpc.
type FindNodeFunc = func(NodeInfo, FindNodeReq) (FindNodeRes, error)

// GetReq is the request in the Get rpc.
type GetReq struct {
	Key []byte `json:"key"`
}

// GetRes is the response in the Get rpc.
type GetRes struct {
	Value     []byte       `json:"value"`
	ExpiresAt tai64.TAI64N `json:"expires_at"`
	Closer    []NodeInfo   `json:"closer"`
}

// GetFunc is the type of functions implementing the Get rpc.
type GetFunc = func(NodeInfo, GetReq) (GetRes, error)

// PutReq is the request in the Put rpc.
type PutReq struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
	TTLms uint64 `json:"ttl_ms"`
}

// PutRes is the response in the Put rpc.
type PutRes struct {
	Accepted bool       `json:"accepted"`
	Closer   []NodeInfo `json:"closer"`
}

// PutFunc is the type of functions implementing the Put rpc.
type PutFunc = func(NodeInfo, PutReq) (PutRes, error)

type PingReq struct{}

type PingRes struct {
	Timestamp tai64.TAI64N `json:"timestamp"`
}
