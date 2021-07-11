package chord

import (
	"math/big"
)

// DistanceAbsolute computes the distance moving either clockwise or anticlockwise on the circle.
// to, from, and out must be the same length or DistanceAbsolute will panic
//
// dist = abs(to - from) = abs(from - to)
func DistanceAbsolute(out, to, from []byte) {
	checkBuffers(out, from, to)
	dist := sub(from, to)
	dist.Abs(dist)
	dist.FillBytes(out)
}

// Distance computes the distance moving clockwise around the circle, starting at a, and going to b.
// to, from, and out must be the same length or DistanceForward will panic
//
// dist = (to - from) % m
// where m is the 2^(len(out)*8)a
func DistanceForward(out, to, from []byte) {
	checkBuffers(out, from, to)
	dist := sub(from, to)
	dist.Mod(dist, getMod(out))
	dist.FillBytes(out)
}

func sub(from, to []byte) *big.Int {
	dist := big.Int{}
	fromInt := big.Int{}
	fromInt.SetBytes(from)
	toInt := big.Int{}
	toInt.SetBytes(to)
	dist.Sub(&toInt, &fromInt)
	return &dist
}

func checkBuffers(out, a, b []byte) {
	if len(a) != len(b) {
		panic("a and b must be equal length")
	}
	if len(out) != len(a) {
		panic("out must be the same length as a and b")
	}
}

func getMod(x []byte) *big.Int {
	mod := big.NewInt(1)
	mod.Lsh(mod, uint(len(x)*8))
	return mod
}
