package keccakf

import "testing"

func BenchmarkF1600(b *testing.B) {
	b.SetBytes(int64(200))
	var x State1600
	for i := 0; i < b.N; i++ {
		keccakF1600(&x)
	}
}
