package swarmtest

import (
	"context"
	"fmt"
	"math/rand"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestSuiteSwarm(t *testing.T, newSwarms func(testing.TB, int) []p2p.Swarm) {
	t.Run("TestLocalAddrs", func(t *testing.T) {
		xs := newSwarms(t, 1)
		x := xs[0]
		TestLocalAddrs(t, x)
	})
	t.Run("TestMarshalParse", func(t *testing.T) {
		xs := newSwarms(t, 1)
		x := xs[0]
		TestMarshalParse(t, x)
	})
	t.Run("TestTell", func(t *testing.T) {
		xs := newSwarms(t, 10)
		require.Len(t, xs, 10)
		TestTellAllPairs(t, xs)
	})
	t.Run("TestTellBidirectional", func(t *testing.T) {
		xs := newSwarms(t, 2)
		a, b := xs[0], xs[1]
		TestTellBidirectional(t, a, b)
	})
}

func TestLocalAddrs(t *testing.T, s p2p.Swarm) {
	addrs := s.LocalAddrs()
	assert.True(t, len(addrs) > 0, "LocalAddrs must return at least 1")
}

func TestMarshalParse(t *testing.T, s p2p.Swarm) {
	addr := s.LocalAddrs()[0]
	data, err := addr.MarshalText()
	assert.Nil(t, err)
	addr2, err := s.ParseAddr(data)
	assert.Nil(t, err)
	assert.Equal(t, addr, addr2, "Did not parse to same address")
}

func TestTellAllPairs(t *testing.T, xs []p2p.Swarm) {
	for i, x1 := range xs {
		for j, x2 := range xs {
			if j != i {
				TestTell(t, x1, x2)
			}
		}
	}
}

func TestTell(t *testing.T, src, dst p2p.Swarm) {
	done := make(chan struct{}, 1)
	recv := p2p.Message{}
	dst.OnTell(func(msg *p2p.Message) {
		if assert.NotNil(t, msg, "p2p message must not be nil") {
			recv = *msg
		}
		close(done)
	})
	defer dst.OnTell(p2p.NoOpTellHandler)

	dstAddr := dst.LocalAddrs()[0]
	payload := genPayload()

	err := src.Tell(context.TODO(), dstAddr, payload)
	require.Nil(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout waiting for tell")
	}

	assert.Equal(t, string(payload), string(recv.Payload))
	assert.Equal(t, dstAddr, recv.Dst, "DST addr incorrect. HAVE: %v WANT: %v", recv.Dst, dstAddr)
	assert.NotNil(t, recv.Src, "SRC addr is nil")
}

func TestTellBidirectional(t *testing.T, a, b p2p.Swarm) {
	const N = 50
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()

	aInbox := make(chan []byte, N)
	bInbox := make(chan []byte, N)
	a.OnTell(func(msg *p2p.Message) {
		aInbox <- append([]byte{}, msg.Payload...)
	})
	b.OnTell(func(msg *p2p.Message) {
		bInbox <- append([]byte{}, msg.Payload...)
	})
	eg := errgroup.Group{}
	sleepRandom := func() {
		dur := time.Millisecond * time.Duration(1+rand.Intn(10)-5)
		time.Sleep(dur)
	}
	eg.Go(func() error {
		for i := 0; i < N; i++ {
			x := fmt.Sprintf("test %d", i)
			if err := a.Tell(ctx, b.LocalAddrs()[0], []byte(x)); err != nil {
				return err
			}
			sleepRandom()
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < N; i++ {
			x := fmt.Sprintf("test %d", i)
			if err := b.Tell(ctx, a.LocalAddrs()[0], []byte(x)); err != nil {
				return err
			}
			sleepRandom()
		}
		return nil
	})
	require.Nil(t, eg.Wait())
	time.Sleep(time.Second)
	passN := N * 3 / 4
	aSlice := collectChan(ctx, passN, aInbox)
	bSlice := collectChan(ctx, passN, bInbox)
	t.Log("a inbox: ", len(aSlice))
	t.Log("b inbox: ", len(bSlice))
	assert.GreaterOrEqual(t, len(aSlice), passN)
	assert.GreaterOrEqual(t, len(bSlice), passN)
}

func collectChan(ctx context.Context, N int, ch chan []byte) (ret [][]byte) {
	for i := 0; i < N; i++ {
		select {
		case <-ctx.Done():
			return
		case x := <-ch:
			ret = append(ret, x)
		}
	}
	return ret
}

func genPayload() []byte {
	x := fmt.Sprintf("test-%d", mrand.Int63())
	return []byte(x)
}

func CloseSwarms(t testing.TB, xs []p2p.Swarm) {
	for i := range xs {
		require.Nil(t, xs[i].Close())
	}
}

func CloseAskSwarms(t testing.TB, xs []p2p.AskSwarm) {
	for i := range xs {
		require.Nil(t, xs[i].Close())
	}
}
