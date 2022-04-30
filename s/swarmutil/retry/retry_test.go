package retry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExponential(t *testing.T) {
	initial := time.Second
	fn := NewExponentialBackoff(initial, 2)
	require.Equal(t, initial, fn(0, 0))
	require.Greater(t, fn(1, 0), initial)
	require.Less(t, fn(1, 0), initial*2)
	require.Equal(t, initial*2, fn(2, 0))
}
