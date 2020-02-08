package p2ptest

import (
	"github.com/brendoncarroll/go-p2p"
)

type AdjList = [][]p2p.Addr

func Ring(swarms []p2p.Swarm) (adjList AdjList) {
	adjList = make(AdjList, len(swarms))
	l := len(swarms)
	for i := 0; i < l; i++ {
		adjList[i] = append(adjList[i], swarms[(i+1)%l].LocalAddrs()[0])
	}
	return adjList
}

func Cluster(swarms []p2p.Swarm) (adjList AdjList) {
	adjList = make(AdjList, len(swarms))
	for i := range swarms {
		for j := range swarms {
			adjList[i] = append(adjList[i], swarms[j].LocalAddrs()[0])
		}
	}
	return adjList
}

func HubAndSpoke(swarms []p2p.Swarm) (adjList AdjList) {
	adjList = make(AdjList, len(swarms))
	for i := 1; i < len(swarms); i++ {
		adjList[0] = append(adjList[0], swarms[i].LocalAddrs()[0])
	}
	return adjList
}
