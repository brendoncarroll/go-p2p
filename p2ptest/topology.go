package p2ptest

type AdjList = [][]int

func Chain(n int) (adjList AdjList) {
	adjList = make(AdjList, n)
	for i := range adjList {
		prev := i - 1
		next := i + 1
		if prev >= 0 {
			connect(adjList, i, prev)
		}
		if next < n {
			connect(adjList, i, next)
		}
	}
	return adjList
}

func Ring(n int) (adjList AdjList) {
	adjList = make(AdjList, n)
	for i := 0; i < n; i++ {
		next := (i + 1) % n
		prev := (i + n - 1) % n
		if next != i {
			connect(adjList, i, next)
		}
		if prev != i {
			connect(adjList, i, prev)
		}
	}
	return adjList
}

func Cluster(n int) (adjList AdjList) {
	adjList = make(AdjList, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				adjList[i] = append(adjList[i], j)
			}
		}
	}
	return adjList
}

func HubAndSpoke(n int) (adjList AdjList) {
	adjList = make(AdjList, n)
	for i := 1; i < n; i++ {
		connect(adjList, 0, i)
	}
	return adjList
}

func connect(adjList AdjList, i, j int) {
	adjList[i] = append(adjList[i], j)
	adjList[j] = append(adjList[j], i)
}
