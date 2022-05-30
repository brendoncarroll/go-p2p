package kademlia

import (
	"bytes"
	"testing"
)

func FuzzDistanceCmp(f *testing.F) {
	f.Fuzz(func(t *testing.T, x, a, b []byte) {
		da := Distance(x, a)
		db := Distance(x, b)
		actual := DistanceCmp(x, a, b)
		expected := bytes.Compare(da, db)
		if expected != actual {
			t.Errorf("HAVE: %v WANT: %v . wrong comparison for x=%q a=%q b=%q", actual, expected, x, a, b)
		}
	})
}

func FuzzDistance(f *testing.F) {
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ab := Distance(a, b)
		ba := Distance(b, a)
		if !bytes.Equal(ab, ba) {
			t.Errorf("Distance(a, b) != Distance(b, a)")
		}
	})
}
