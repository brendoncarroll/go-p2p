package p2ptest

import (
	"github.com/brendoncarroll/go-p2p"
)

type AdjList = [][]int

func Ring(n int) (adjList AdjList) {
	for i := 0; i < n; i++ {
		adjList[i] = append(adjList[i], (i+1)%n)
	}
	return adjList
}

func Cluster(swarms []p2p.Swarm) (adjList AdjList) {
	adjList = make(AdjList, len(swarms))
	for i := range swarms {
		for j := range swarms {
			adjList[i] = append(adjList[i], j)
		}
	}
	return adjList
}

func HubAndSpoke(swarms []p2p.Swarm) (adjList AdjList) {
	adjList = make(AdjList, len(swarms))
	for i := 1; i < len(swarms); i++ {
		adjList[0] = append(adjList[0], i)
	}
	return adjList
}

func Chain(n int) (adjList AdjList) {
	adjList = make(AdjList, n)
	for i := range adjList {
		if i-1 >= 0 {
			adjList[i] = append(adjList[i], i-1)
		}
		if i+1 < n {
			adjList[i] = append(adjList[i], i+1)
		}
	}
	return adjList
}
