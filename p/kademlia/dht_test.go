package kademlia

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// TestDHTSetup tests the setupNodes function used in the other tests.
func TestDHTSetup(t *testing.T) {
	const N = 1000
	const numPeers = 10
	nodes := setupNodes(t, N, numPeers, 0)

	t.Run("FullyConnected", func(t *testing.T) {
		lt := func(a, b p2p.PeerID) bool {
			return bytes.Compare(a[:], b[:]) < 0
		}
		clusters := computeComponents(nodes)
		if len(clusters) != 1 {
			for id, cluster := range clusters {
				t.Log(id, len(cluster), sortedKeys(cluster, lt))
			}
		}
		require.Equal(t, 1, len(clusters), "should only have 1 cluster")
	})
	t.Run("FullCaches", func(t *testing.T) {
		for _, node := range nodes {
			require.Len(t, node.ListPeers(0), numPeers)
		}
	})
	t.Run("StablePeers", func(t *testing.T) {
		var improvements int
		for local := range nodes {
			for remote := range nodes {
				if local == remote {
					continue
				}
				if nodes[local].peers.WouldAdd(remote[:]) {
					improvements++
				}
			}
		}
		// all the nodes should have found the closest nodes, and there should not
		// be any improvement
		require.Equal(t, 0, improvements)
	})
}

func TestDHTFindNode(t *testing.T) {
	const (
		N        = 1000
		numPeers = 20
	)
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

func TestDHTGet(t *testing.T) {
	const (
		N        = 1000
		peerSize = 20
		dataSize = 2
	)
	nodes := setupNodes(t, N, peerSize, dataSize)

	// create test key and value
	key := sha3.Sum256([]byte("test key"))
	expectedValue := "test value"
	// find the closest node to that value.
	closest := findClosest(nodes, key[:])
	// give the entry to only that node.
	accepted, err := nodes[closest].Put(key[:], []byte(expectedValue), time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.True(t, accepted)
	t.Logf("put key %q on node %v lz=%v", key, closest, DistanceLz(closest[:], key[:]))
	for src, node := range nodes {
		_, err := DHTGet(DHTGetParams{
			Initial: node.ListNodeInfos(key[:], 3),
			Key:     key[:],
			Ask: func(node NodeInfo, req GetReq) (GetRes, error) {
				dst := nodes[node.ID]
				return dst.HandleGet(src, req)
			},
		})
		require.NoError(t, err, "Get failed on node %v", src)
	}
}

// func TestDHTJoin(t *testing.T) {
// 	const N = 100
// 	const peerSize = 10
// 	nodes := make(map[p2p.PeerID]*DHTNode)
// 	for i := 0; i < N; i++ {
// 		id := newPeer(i)
// 		nodes[id] = NewDHTNode(DHTNodeParams{
// 			LocalID:       id,
// 			PeerCacheSize: peerSize,
// 		})
// 	}
// 	for localID := range nodes {
// 		added := DHTJoin(DHTJoinParams{
// 			Initial: nodes[localID].ListNodeInfos(localID[:], 10),
// 			Target:  localID,
// 			Ask: func(dst NodeInfo, req FindNodeReq) (FindNodeRes, error) {
// 				if _, exists := nodes[dst.ID]; !exists {
// 					return FindNodeRes{}, fmt.Errorf("node %v unreachable", dst)
// 				}
// 				nodes[dst.ID].AddPeer(localID, nil)
// 				return nodes[dst.ID].HandleFindNode(localID, req)
// 			},
// 			AddPeer: nodes[localID].AddPeer,
// 		})
// 		require.Greater(t, added, 0)
// 	}
// }

// func TestDHTPut(t *testing.T) {
// 	const (
// 		N        = 1000
// 		peerSize = 20
// 		dataSize = 1000
// 	)
// 	nodes := setupNodes(t, N, peerSize, dataSize)
// 	makeKey := func(i int) []byte {
// 		ret := sha3.Sum256([]byte(strconv.Itoa(i)))
// 		return ret[:]
// 	}
// 	makeValue := func(i int) []byte {
// 		return []byte("value-" + strconv.Itoa(i))
// 	}
// 	var count int
// 	for src := range nodes {
// 		key := makeKey(count)
// 		value := makeValue(count)
// 		_, err := DHTPut(DHTPutParams{
// 			Initial: nodes[src].ListNodeInfos(key, 3),
// 			Key:     key[:],
// 			Value:   value,
// 			TTL:     time.Hour,
// 			Ask: func(dst NodeInfo, req PutReq) (PutRes, error) {
// 				return nodes[dst.ID].HandlePut(src, req)
// 			},
// 		})
// 		require.NoError(t, err, "adding key number %d", count)
// 		count++
// 	}
// 	for i := 0; i < count; i++ {
// 		key := makeKey(i)
// 		expectedValue := makeValue(i)
// 		closest := findClosest(nodes, key)
// 		actualValue, closer := nodes[closest].Get(key, time.Now())
// 		require.NotNil(t, actualValue, "key %q missing from node %v lz=%v", key, closest, DistanceLz(key[:], closest[:]))
// 		require.Equal(t, expectedValue, actualValue)
// 		require.Len(t, closer, 0)
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
	}
	for id1 := range nodes {
		for id2 := range nodes {
			nodes[id1].AddPeer(id2, nil)
			nodes[id2].AddPeer(id1, nil)
		}
	}
	return nodes
}

func newPeer(i int) p2p.PeerID {
	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:], uint64(i))
	return sha3.Sum256(buf[:])
}

func computeComponents(nodes map[p2p.PeerID]*DHTNode) map[int]map[p2p.PeerID]struct{} {
	var clusterID int
	clusters := make(map[int]map[p2p.PeerID]struct{})
	id2Cluster := make(map[p2p.PeerID]int)
	addToCluster := func(id p2p.PeerID, cid int) {
		if clusters[cid] == nil {
			clusters[cid] = make(map[p2p.PeerID]struct{})
		}
		clusters[cid][id] = struct{}{}
		id2Cluster[id] = cid
	}
	mergeClusters := func(a, b int) int {
		if a == b {
			return a
		}
		if b < a {
			a, b = b, a
		}
		if clusters[a] == nil {
			clusters[a] = make(map[p2p.PeerID]struct{})
		}
		for id := range clusters[b] {
			clusters[a][id] = struct{}{}
			id2Cluster[id] = a
		}
		delete(clusters, b)
		return a
	}
	for id := range nodes {
		cid := clusterID
		clusterID++
		todo := []p2p.PeerID{id}
		for len(todo) > 0 {
			var id p2p.PeerID
			id, todo = pop(todo)
			if cid2, exists := id2Cluster[id]; exists {
				cid = mergeClusters(cid, cid2)
				continue
			}
			addToCluster(id, cid)
			todo = append(todo, nodes[id].ListPeers(0)...)
		}
	}
	if len(clusters) == 0 && len(nodes) != 0 {
		panic("len(clusters)==0")
	}
	return clusters
}

func sortedKeys[K comparable, V any, M map[K]V](m M, lt func(a, b K) bool) []K {
	keys := maps.Keys(m)
	slices.SortFunc(keys, lt)
	return keys
}

func findClosest(nodes map[p2p.PeerID]*DHTNode, key []byte) (closest p2p.PeerID) {
	for id := range nodes {
		if DistanceLt(key[:], id[:], closest[:]) {
			closest = id
		}
	}
	return closest
}
