package kademlia

import (
	"math/bits"
)

func Leading0s(x []byte) int {
	total := 0
	for i := range x {
		lz := bits.LeadingZeros8(x[i])
		total += lz
		if lz < 8 {
			break
		}
	}
	return total
}

func XORBytes(dst, a, b []byte) {
	l := len(a)
	if len(b) < len(a) {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func HasPrefix(x []byte, prefix []byte, nbits int) bool {
	if nbits > len(prefix)*8 {
		panic("nbits longer than prefix")
	}
	if len(x)*8 < nbits {
		return false
	}
	xor := make([]byte, len(x))
	XORBytes(xor, x, prefix)
	lz := Leading0s(xor)
	return lz >= nbits
}
