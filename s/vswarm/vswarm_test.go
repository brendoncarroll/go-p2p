package vswarm_test

import (
	"strconv"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/vswarm"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[intAddr]) {
		r := vswarm.New[intAddr](parseIntAddr, vswarm.WithQueueLen[intAddr](10))
		for i := range xs {
			xs[i] = r.Create(intAddr(i))
		}
		t.Cleanup(func() {
			for i := range xs {
				require.NoError(t, xs[i].Close())
			}
		})
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[intAddr]) {
		r := vswarm.New[intAddr](parseIntAddr)
		for i := range xs {
			xs[i] = r.Create(intAddr(i))
		}
		t.Cleanup(func() {
			for i := range xs {
				require.NoError(t, xs[i].Close())
			}
		})
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[intAddr, string]) {
		r := vswarm.NewSecure[intAddr, string](parseIntAddr)
		for i := range xs {
			xs[i] = r.Create(intAddr(i), strconv.Itoa(i))
		}
		t.Cleanup(func() {
			for i := range xs {
				require.NoError(t, xs[i].Close())
			}
		})
	})
}

func BenchmarkSwarm(b *testing.B) {
	swarmtest.BenchSwarm(b, func(t testing.TB, xs []p2p.Swarm[intAddr]) {
		r := vswarm.New[intAddr](parseIntAddr, vswarm.WithQueueLen[intAddr](10))
		for i := range xs {
			xs[i] = r.Create(intAddr(i))
		}
		t.Cleanup(func() {
			for i := range xs {
				require.NoError(t, xs[i].Close())
			}
		})
	})
}

type intAddr int

func (a intAddr) MarshalText() ([]byte, error) {
	return []byte(strconv.Itoa(int(a))), nil
}

func (a intAddr) String() string {
	return strconv.Itoa(int(a))
}

func parseIntAddr(x []byte) (intAddr, error) {
	i, err := strconv.Atoi(string(x))
	return intAddr(i), err
}
