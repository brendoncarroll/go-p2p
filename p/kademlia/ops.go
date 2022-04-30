package kademlia

import (
	"math/bits"
)

// Leading0s returns the number of 0s that occur before the first 1
// when iterating bit by bit, most significant bit first low
// indexed byte to high indexed byte.
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

// XORBytes writes the XOR of a and b, byte-wise into dst.
func XORBytes(dst, a, b []byte) int {
	l := len(a)
	if len(b) < len(a) {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return l
}

// HasPrefix returns true if the first `nbits` bits of x match
// the first `nbits` bits of prefix.
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
