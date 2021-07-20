package p2ptest

type AdjList = [][]int

func MakeChain(n int) AdjList {
	adjList := make(AdjList, n)
	Chain(adjList)
	return adjList
}

func Chain(adjList AdjList) {
	n := len(adjList)
	for i := range adjList {
		prev := i - 1
		next := i + 1
		if prev >= 0 {
			connectUni(adjList, i, prev)
		}
		if next < n {
			connectUni(adjList, i, next)
		}
	}
}

func MakeRing(n int) AdjList {
	adjList := make(AdjList, n)
	Ring(adjList)
	return adjList
}

func Ring(adjList AdjList) {
	n := len(adjList)
	for i := 0; i < n; i++ {
		next := (i + 1) % n
		prev := (i + n - 1) % n
		if next != i {
			connectUni(adjList, i, next)
		}
		if prev != i && prev != next {
			connectUni(adjList, i, prev)
		}
	}
}

func MakeCluster(n int) AdjList {
	adjList := make(AdjList, n)
	Cluster(adjList)
	return adjList
}

func Cluster(adjList AdjList) {
	n := len(adjList)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				adjList[i] = append(adjList[i], j)
			}
		}
	}
}

func MakeHubAndSpoke(n int) AdjList {
	adjList := make(AdjList, n)
	HubAndSpoke(adjList)
	return adjList
}

func HubAndSpoke(adjList AdjList) {
	n := len(adjList)
	for i := 1; i < n; i++ {
		connectBiDi(adjList, 0, i)
	}
}

func connectUni(adjList AdjList, i, j int) {
	adjList[i] = append(adjList[i], j)
}

func connectBiDi(adjList AdjList, i, j int) {
	connectUni(adjList, i, j)
	connectUni(adjList, j, i)
}
