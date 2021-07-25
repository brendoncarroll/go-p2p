package mbapp

type bitMap struct {
	buf []byte
	n   int
}

func newBitMap(n int) bitMap {
	l := n / 8
	if n%8 > 0 {
		l++
	}
	return bitMap{
		buf: make([]byte, l),
		n:   n,
	}
}

func (bm bitMap) set(i int, v bool) {
	if i >= bm.len() {
		panic("bitMap: index out of bounds")
	}
	if v {
		bm.buf[i/8] |= (1 << i % 8)
	} else {
		bm.buf[i/8] &= ^(1 << i % 8)
	}
}

func (bm bitMap) get(i int) bool {
	if i >= bm.len() {
		panic("bitMap: index out of bounds")
	}
	return bm.buf[i/8]&(1<<i%8) > 0
}

func (bm bitMap) len() int {
	return bm.n
}

func (bm bitMap) allSet() bool {
	l := bm.len()
	for i := 0; i < l; i++ {
		if !bm.get(i) {
			return false
		}
	}
	return true
}
