package p2pke2

type replayFilter struct {
	last    uint64
	bitMask uint64
}

func (rp *replayFilter) Apply(x uint64) bool {
	if x < rp.last && rp.last-x > 64 {
		return false
	}
	if x > rp.last {
		rp.bitMask = rp.bitMask << (x - rp.last)
		rp.last = x
	}
	if rp.bitMask&1 > 0 {
		return false
	}
	rp.bitMask |= 1
	return true
}
