package chord

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDistanceForward(t *testing.T) {
	type testCase struct {
		From, To []byte
		D        []byte
	}
	tcs := []testCase{
		{
			From: []byte{0, 0, 0, 1},
			To:   []byte{0, 0, 0, 8},
			D:    []byte{0, 0, 0, 7},
		},
	}
	for _, tc := range tcs {
		actual := make([]byte, len(tc.D))
		expected := tc.D
		DistanceForward(actual, tc.To, tc.From)
		assert.Equal(t, expected, actual)
	}
}

func TestDistanceAbsolute(t *testing.T) {
	type testCase struct {
		A, B []byte
		D    []byte
	}
	tcs := []testCase{
		{
			A: []byte{0, 0, 0, 1},
			B: []byte{0, 0, 0, 8},
			D: []byte{0, 0, 0, 7},
		},
	}
	for _, tc := range tcs {
		actual := make([]byte, len(tc.A))
		expected := tc.D
		DistanceAbsolute(actual, tc.A, tc.B)
		assert.Equal(t, expected, actual)
	}
}
