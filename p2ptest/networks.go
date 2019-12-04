package p2ptest

import (
	"github.com/brendoncarroll/go-p2p"
)

type Matrix [][]p2p.Addr

func Ring(swarms []p2p.Swarm) (adjMat [][]p2p.Addr) {
	adjMat = make([][]p2p.Addr, len(swarms))
	l := len(swarms)
	for i := 0; i < l; i++ {
		adjMat[i] = append(adjMat[i], swarms[(i+1)%l].LocalAddr())
	}
	return adjMat
}

func Cluster(swarms []p2p.Swarm) (adjMat [][]p2p.Addr) {
	adjMat = make([][]p2p.Addr, len(swarms))
	for i := range swarms {
		for j := range swarms {
			adjMat[i] = append(adjMat[i], swarms[j].LocalAddr())
		}
	}
	return adjMat
}

func HubAndSpoke(swarms []p2p.Swarm) (adjMat [][]p2p.Addr) {
	adjMat = make([][]p2p.Addr, len(swarms))
	for i := 1; i < len(swarms); i++ {
		adjMat[0] = append(adjMat[0], swarms[i].LocalAddr())
	}
	return adjMat
}
