package kademlia

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
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
	t.Parallel()
	const N = 1000
	const numPeers = 10
	nodes := setupNodes(t, N, numPeers, 0)
	testNetwork(t, nodes, numPeers)
}

func testNetwork(t *testing.T, nodes map[p2p.PeerID]*DHTNode, numPeers int) {
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
				if nodes[local].peers.WouldAdd(remote[:], time.Now()) {
					t.Logf("%v contains %v %v", local, remote, nodes[local].peers.Contains(remote[:], time.Now()))
					t.Logf("%v would add %v", local, remote)
					t.Logf("%v has %v", local, nodes[local].ListPeers(0))
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
	t.Parallel()
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
	t.Parallel()
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
	accepted := nodes[closest].Put(key[:], []byte(expectedValue), time.Hour)
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

func TestDHTPut(t *testing.T) {
	t.Parallel()
	const (
		N        = 1000
		peerSize = 20
		dataSize = 30
	)
	nodes := setupNodes(t, N, peerSize, dataSize)
	makeKey := func(i int) []byte {
		ret := sha3.Sum256([]byte(strconv.Itoa(i)))
		return ret[:]
	}
	makeValue := func(i int) []byte {
		return []byte("value-" + strconv.Itoa(i))
	}
	var count int
	for src := range nodes {
		key := makeKey(count)
		value := makeValue(count)
		_, err := DHTPut(DHTPutParams{
			Initial: nodes[src].ListNodeInfos(key, 3),
			Key:     key[:],
			Value:   value,
			TTL:     time.Hour,
			Ask: func(dst NodeInfo, req PutReq) (PutRes, error) {
				return nodes[dst.ID].HandlePut(src, req)
			},
		})
		require.NoError(t, err, "adding key number %d", count)
		count++
	}
	for i := 0; i < count; i++ {
		key := makeKey(i)
		expectedValue := makeValue(i)
		closest := findClosest(nodes, key)
		actualValue := nodes[closest].Get(key)
		if actualValue == nil {
			t.Logf("node %x data:", closest[:])
			nodes[closest].data.ForEach(nil, func(e Entry[[]byte]) bool {
				t.Logf("%x", e.Key)
				return true
			})
		}
		require.NotNil(t, actualValue, "key %x missing from node %v lz=%v", key, closest, DistanceLz(key[:], closest[:]))
		require.Equal(t, expectedValue, actualValue)
	}
}

func TestDHTPutGet(t *testing.T) {
	t.Parallel()
	const (
		N          = 1000
		peerSize   = 20
		dataSize   = 10
		numEntries = 100
	)
	nodes := setupNodes(t, N, peerSize, dataSize)
	makeKey := func(i int) []byte {
		k := sha3.Sum256([]byte(strconv.Itoa(i)))
		return k[:]
	}
	makeValue := func(i int) []byte {
		return []byte(strconv.Itoa(i) + "-value")
	}
	var count int
	for src := range nodes {
		key := makeKey(count)
		value := makeValue(count)
		_, err := DHTPut(DHTPutParams{
			Initial: nodes[src].ListNodeInfos(key, 3),
			Key:     key[:],
			Value:   value,
			TTL:     time.Hour,
			Ask: func(dst NodeInfo, req PutReq) (PutRes, error) {
				return nodes[dst.ID].HandlePut(src, req)
			},
		})
		require.NoError(t, err)
		count++
		if count > numEntries {
			break
		}
	}
	for src := range nodes {
		for i := 0; i < count; i++ {
			key := makeKey(i)
			res, err := DHTGet(DHTGetParams{
				Initial: nodes[src].ListNodeInfos(key, 3),
				Key:     key[:],
				Ask: func(dst NodeInfo, req GetReq) (GetRes, error) {
					return nodes[dst.ID].HandleGet(src, req)
				},
			})
			require.NoError(t, err)
			require.Equal(t, makeValue(i), res.Value)
		}
	}
}

func TestDHTJoin(t *testing.T) {
	t.Parallel()
	const (
		N        = 1000
		peerSize = 10
	)
	nodes := make(map[p2p.PeerID]*DHTNode)
	for i := 0; i < N; i++ {
		id := newPeer(i)
		nodes[id] = NewDHTNode(DHTNodeParams{
			LocalID:       id,
			PeerCacheSize: peerSize,
		})
		id2 := newPeer(0)
		nodes[id].AddPeer(id2, nil)

		if i < 1 {
			continue
		}
		src := id
		DHTJoin(DHTJoinParams{
			Initial: nodes[src].ListNodeInfos(src[:], peerSize),
			Target:  src,
			Ask: func(dst NodeInfo, req FindNodeReq) (FindNodeRes, error) {
				if _, exists := nodes[dst.ID]; !exists {
					return FindNodeRes{}, fmt.Errorf("node %v unreachable", dst)
				}
				nodes[dst.ID].AddPeer(src, nil)
				return nodes[dst.ID].HandleFindNode(src, req)
			},
			AddPeer: nodes[src].AddPeer,
		})
	}
	comps := computeComponents(nodes)
	require.Len(t, comps, 1)
	for k := range comps {
		require.Len(t, comps[k], N)
	}
}

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
		if closest.IsZero() || DistanceLt(key[:], id[:], closest[:]) {
			closest = id
		}
	}
	return closest
}

func logCeil(x int) int {
	return int(math.Ceil(math.Log2(float64(x))))
}
