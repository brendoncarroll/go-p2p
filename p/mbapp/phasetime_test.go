package mbapp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPhaseTime(t *testing.T) {
	unit := time.Millisecond
	x := time.Now().UTC()
	y := NewPhaseTime32(x, unit)
	z := y.UTC(x, unit)
	ee := time.Unix(0, lastEvenEpoch(x, period32(unit)))
	oe := time.Unix(0, lastOddEpoch(x, period32(unit)))
	t.Log("last even", ee, "last odd", oe)
	require.Equal(t, x.Unix(), z.Unix())
}
