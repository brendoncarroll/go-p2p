package kademlia

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/sync/errgroup"
)

type Request struct {
	Get      *GetReq      `json:"get,omitempty"`
	Put      *PutReq      `json:"put,omitempty"`
	FindNode *FindNodeReq `json:"find_node,omitempty"`
}

type peerInfo struct {
	Addr p2p.Addr
}

// DHTService runs a DHT using a p2p.SecureAskSwarm for communication
type DHTService[A p2p.Addr] struct {
	swarm         p2p.SecureAskSwarm[A]
	fingerprinter p2p.Fingerprinter

	dhtNode *DHTNode
	cf      context.CancelFunc
	eg      errgroup.Group
}

func NewDHTService[A p2p.Addr](swarm p2p.SecureAskSwarm[A], peerCacheSize, dataCacheSize int) *DHTService[A] {
	ctx, cf := context.WithCancel(context.Background())
	s := &DHTService[A]{
		swarm:         swarm,
		fingerprinter: p2p.DefaultFingerprinter,

		cf: cf,
	}
	localID := s.fingerprinter(swarm.PublicKey())
	s.dhtNode = NewDHTNode(DHTNodeParams{
		LocalID:       localID,
		PeerCacheSize: peerCacheSize,
		DataCacheSize: dataCacheSize,
	})
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		s.eg.Go(func() error {
			return s.readLoop(ctx)
		})
	}
	return s
}

// func (s *DHTService[A]) Put(ctx context.Context, key, value []byte, ttl time.Duration) error {
// 	_, err := DHTPut(DHTPutParams{
// 		Key: key,
// 		Ask: func(dst p2p.PeerID, req PutReq) (PutRes, error) {
// 			if dst == s.dhtNode.LocalID() {
// 				return s.dhtNode.HandlePut(s.dhtNode.LocalID(), req)
// 			}
// 			addr, err := s.findPeer(ctx, dst)
// 			if err != nil {
// 				return PutRes{}, err
// 			}
// 			return askJSON[A, Request, PutRes](ctx, s.swarm, addr, Request{
// 				Put: &req,
// 			})
// 		},
// 	})
// 	return err
// }

// func (s *DHTService[A]) Get(ctx context.Context, key []byte) ([]byte, error) {
// 	res, err := DHTGet(DHTGetParams{})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return res.Value, nil
// }

func (s *DHTService[A]) Close() error {
	s.cf()
	err := s.swarm.Close()
	s.eg.Wait()
	return err
}

func (s *DHTService[A]) readLoop(ctx context.Context) error {
	for {
		if err := s.swarm.ServeAsk(ctx, s.handleAsk); err != nil {
			return err
		}
	}
}

func (s *DHTService[A]) handleAsk(ctx context.Context, resp []byte, msg p2p.Message[A]) int {
	var req Request
	var n int
	if err := func() error {
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			return err
		}
		pubKey, err := s.swarm.LookupPublicKey(ctx, msg.Src)
		if err != nil {
			return err
		}
		peerID := s.fingerprinter(pubKey)
		var res any
		switch {
		case req.Get != nil:
			res, err = s.handleGet(ctx, peerID, *req.Get)
		case req.Put != nil:
			res, err = s.handlePut(ctx, peerID, *req.Put)
		default:
			return errors.New("empty request")
		}
		if err != nil {
			return err
		}
		data, err := json.Marshal(res)
		if err != nil {
			panic(err)
		}
		n = copy(resp, data)
		return nil
	}(); err != nil {
		return -1
	}
	return n
}

func (s *DHTService[A]) handleGet(ctx context.Context, from p2p.PeerID, req GetReq) (GetRes, error) {
	return s.dhtNode.HandleGet(from, req)
}

func (s *DHTService[A]) handlePut(ctx context.Context, from p2p.PeerID, req PutReq) (PutRes, error) {
	return s.dhtNode.HandlePut(from, req)
}

func askJSON[A p2p.Addr, Req, Res any](ctx context.Context, swarm p2p.AskSwarm[A], dst A, req Req) (Res, error) {
	var res Res
	respBuf := make([]byte, swarm.MaxIncomingSize())
	reqData, err := json.Marshal(req)
	if err != nil {
		return res, err
	}
	n, err := swarm.Ask(ctx, respBuf, dst, p2p.IOVec{reqData})
	if err != nil {
		return res, err
	}
	return res, json.Unmarshal(respBuf[:n], &res)
}
