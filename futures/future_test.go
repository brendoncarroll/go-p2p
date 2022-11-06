package futures

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

var ctx = context.Background()

func TestJoin(t *testing.T) {
	af := NewSuccess(123)
	bf := NewSuccess("abc")
	cf := Join2(af, bf, func(i int, s string) string {
		return strconv.Itoa(i) + s
	})
	c, err := Await(ctx, cf)
	require.NoError(t, err)
	require.Equal(t, "123abc", c)
}

func TestPromise(t *testing.T) {
	p := NewPromise[int]()
	require.False(t, p.IsDone())
	p.Succeed(123)
	require.True(t, p.IsDone())
	x, err := Await[int](ctx, p)
	require.NoError(t, err)
	require.Equal(t, 123, x)
}
