package kademlia

import (
	"math/bits"
)

// LeadingZeros returns the number of 0s that occur before the first 1
// when iterating bit by bit, most significant bit first low
// indexed byte to high indexed byte.
func LeadingZeros(x []byte) int {
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
	l := min(len(dst), len(a), len(b))
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
	lz := LeadingZeros(xor)
	return lz >= nbits
}

// Distance is the Kademlia distance metric.
// Distance(a, b) == Distance(b, a)
// len(Distance(a, b)) == min(len(a), len(b))
func Distance(a, b []byte) []byte {
	dist := make([]byte, min(len(a), len(b)))
	XORBytes(dist, a, b)
	return dist
}

// DistanceCmp is equivalent to bytes.Compare(Distance(x, a), Distance(x, b))
func DistanceCmp(x []byte, a, b []byte) int {
	l := min(len(x), len(a), len(b))
	for i := 0; i < l; i++ {
		xa := x[i] ^ a[i]
		xb := x[i] ^ b[i]
		if xa < xb {
			return -1
		} else if xb < xa {
			return 1
		}
	}
	if len(x) == l {
		return 0
	}
	if len(a) < len(b) {
		return -1
	}
	if len(b) < len(a) {
		return 1
	}
	return 0
}

// DistanceLt returns true if Distance(x, a) < Distance(x, b)
func DistanceLt(x []byte, a, b []byte) bool {
	return DistanceCmp(x, a, b) < 0
}

// DistanceGt returns true if Distance(x, a) > Distance(x, b)
func DistanceGt(x []byte, a, b []byte) bool {
	return DistanceCmp(x, a, b) > 0
}

// DistanceLz returns the number of leading zeros in the distance between a and b
// DistanceLz == LeadingZeros(Distance(a, b))
func DistanceLz(a, b []byte) (ret int) {
	l := min(len(a), len(b))
	for i := 0; i < l; i++ {
		lz := bits.LeadingZeros8(a[i] ^ b[i])
		ret += lz
		if lz < 8 {
			break
		}
	}
	return ret
}

func min(xs ...int) (ret int) {
	for i, x := range xs {
		if i == 0 || x < ret {
			ret = x
		}
	}
	return ret
}
