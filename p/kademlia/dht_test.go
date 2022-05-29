package kademlia

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/exp/maps"
)

func TestDHTBootstrap(t *testing.T) {
	const N = 100
	const numPeers = 10
	nodes := setupNodes(t, N, numPeers, 0)
	for _, node := range nodes {
		require.Len(t, node.ListPeers(0), numPeers)
	}
	var improvements int
	for local := range nodes {
		t.Log(nodes[local])
		for remote := range nodes {
			if nodes[local].AddPeer(remote, nil) {
				improvements++
			}
		}
	}
	// all the nodes should have found the closest nodes, and there should not
	// be any improvement
	require.Equal(t, 0, improvements)
}

func TestDHTFindNode(t *testing.T) {
	const N = 100
	const numPeers = 10
	nodes := setupNodes(t, N, numPeers, 0)
	ids := maps.Keys(nodes)

	for i := 0; i < 10; i++ {
		a, b := ids[i], ids[len(ids)-1-i]
		res, err := DHTFindNode(DHTFindNodeParams{
			Initial: nodes[a].ListNodeInfos(b[:], 10),
			Target:  b,
			Ask: func(dst NodeInfo, req FindNodeReq) (FindNodeRes, error) {
				return nodes[dst.ID].HandleFindNode(a, req)
			},
		})
		require.NoError(t, err)
		t.Log(res)
	}
}

// func TestDHTPut(t *testing.T) {
// 	const N = 100
// 	nodes := setupNodes(t, N, 2, 10)
// 	var count int
// 	for localID := range nodes {
// 		key := sha3.Sum256([]byte(strconv.Itoa(count)))
// 		value := []byte(strconv.Itoa(count) + "value")
// 		res, err := DHTPut(DHTPutParams{
// 			Initial: nodes[localID].ListPeers(2),
// 			Key:     key[:],
// 			Value:   value,
// 			TTL:     time.Hour,
// 			Ask: func(dst p2p.PeerID, req PutReq) (PutRes, error) {
// 				return nodes[dst].HandlePut(localID, req)
// 			},
// 		})
// 		t.Log("put result", res)
// 		require.NoError(t, err, "adding key number %d", count)
// 		count++
// 	}
// }

// func TestDHTPutGet(t *testing.T) {
// 	const N = 10
// 	nodes := setupNodes(t, N, 3, 3)
// 	var keys [][32]byte
// 	var values [][]byte
// 	var count int
// 	for localID := range nodes {
// 		key := sha3.Sum256([]byte(strconv.Itoa(count)))
// 		keys = append(keys, key)
// 		value := []byte(strconv.Itoa(count) + "_value")
// 		values = append(values, value)
// 		_, err := DHTPut(DHTPutParams{
// 			Initial: nodes[localID].ListPeers(2),
// 			Key:     key[:],
// 			Value:   value,
// 			TTL:     time.Hour,
// 			Ask: func(dst p2p.PeerID, req PutReq) (PutRes, error) {
// 				return nodes[dst].HandlePut(localID, req)
// 			},
// 		})
// 		require.NoError(t, err)
// 		count++
// 	}
// 	for localID := range nodes {
// 		for i, key := range keys {
// 			res, err := DHTGet(DHTGetParams{
// 				Initial: nodes[localID].ListPeers(3),
// 				Key:     key[:],
// 				Ask: func(dst p2p.PeerID, req GetReq) (GetRes, error) {
// 					return nodes[dst].HandleGet(localID, req)
// 				},
// 			})
// 			require.NoError(t, err, "node ")
// 			require.Equal(t, values[i], res.Value)
// 			require.False(t, DistanceLt(key[:], localID[:], res.Peer[:]))
// 		}
// 	}
// }

func setupNodes(t testing.TB, n, peerSize, dataSize int) map[p2p.PeerID]*DHTNode {
	nodes := make(map[p2p.PeerID]*DHTNode)
	for i := 0; i < n; i++ {
		id := newPeer(i)
		nodes[id] = NewDHTNode(DHTNodeParams{
			LocalID:       id,
			PeerCacheSize: peerSize,
			DataCacheSize: dataSize,
		})
		id2 := newPeer(0)
		nodes[id].AddPeer(id2, nil)
	}
	join := func(localID p2p.PeerID) {
		node := nodes[localID]
		err := DHTJoin(DHTJoinParams{
			Initial: node.ListNodeInfos(localID[:], 10),
			Target:  localID,
			Ask: func(dst NodeInfo, req FindNodeReq) (FindNodeRes, error) {
				if _, exists := nodes[dst.ID]; !exists {
					return FindNodeRes{}, fmt.Errorf("node %v unreachable", dst)
				}
				nodes[dst.ID].AddPeer(localID, nil)
				return nodes[dst.ID].HandleFindNode(localID, req)
			},
			AddPeer: node.AddPeer,
		})
		require.NoError(t, err)
	}
	for i := 0; i < 3; i++ {
		for id := range nodes {
			join(id)
		}
	}
	return nodes
}

func newPeer(i int) p2p.PeerID {
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], uint64(i))
	return sha3.Sum256(buf[:])
}
