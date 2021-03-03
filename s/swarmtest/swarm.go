package swarmtest

import (
	"context"
	"fmt"
	"math/rand"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
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
		aQueue, bQueue := swarmutil.NewTellQueue(), swarmutil.NewTellQueue()
		go a.ServeTells(func(msg *p2p.Message) {
			aQueue.DeliverTell(msg)
		})
		go b.ServeTells(func(msg *p2p.Message) {
			bQueue.DeliverTell(msg)
		})
		TestTellBidirectional(t, a, b, aQueue, bQueue)
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
	recv := makeChans(xs)
	for i := range xs {
		for j := range xs {
			if j != i {
				dst := xs[j].LocalAddrs()[0]
				testTell(t, xs[i], dst, recv[j])
			}
		}
	}
}

func makeChans(xs []p2p.Swarm) []chan p2p.Message {
	recv := make([]chan p2p.Message, len(xs))
	for i := range xs {
		i := i
		recv[i] = make(chan p2p.Message, 1)
		go xs[i].ServeTells(func(msg *p2p.Message) {
			recv[i] <- copyMessage(msg)
		})
	}
	return recv
}

func testTell(t *testing.T, src p2p.Swarm, dstAddr p2p.Addr, recvChan chan p2p.Message) {
	ctx := context.Background()
	payload := genPayload()
	require.NoError(t, src.Tell(ctx, dstAddr, p2p.IOVec{payload}))

	var recv p2p.Message
	select {
	case <-ctx.Done():
		t.Error("timeout waiting for tell")
	case recv = <-recvChan:
	}

	assert.Equal(t, string(payload), string(recv.Payload))
	assert.Equal(t, dstAddr, recv.Dst, "DST addr incorrect. HAVE: %v WANT: %v", recv.Dst, dstAddr)
	assert.NotNil(t, recv.Src, "SRC addr is nil")
}

func TestTellBidirectional(t *testing.T, a, b p2p.Swarm, aQueue, bQueue *swarmutil.TellQueue) {
	const N = 50
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()

	aInbox := make(chan p2p.Message, N)
	bInbox := make(chan p2p.Message, N)
	go copyTells(ctx, aInbox, aQueue)
	go copyTells(ctx, bInbox, bQueue)

	eg := errgroup.Group{}
	sleepRandom := func() {
		dur := time.Millisecond * time.Duration(1+rand.Intn(10)-5)
		time.Sleep(dur)
	}
	eg.Go(func() error {
		for i := 0; i < N; i++ {
			x := fmt.Sprintf("test %d", i)
			if err := a.Tell(ctx, b.LocalAddrs()[0], p2p.IOVec{[]byte(x)}); err != nil {
				return err
			}
			sleepRandom()
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < N; i++ {
			x := fmt.Sprintf("test %d", i)
			if err := b.Tell(ctx, a.LocalAddrs()[0], p2p.IOVec{[]byte(x)}); err != nil {
				return err
			}
			sleepRandom()
		}
		return nil
	})
	require.Nil(t, eg.Wait())
	passN := N * 3 / 4
	aSlice := collectChan(ctx, N, aInbox)
	bSlice := collectChan(ctx, N, bInbox)
	t.Log("a inbox: ", len(aSlice))
	t.Log("b inbox: ", len(bSlice))
	assert.GreaterOrEqual(t, len(aSlice), passN)
	assert.GreaterOrEqual(t, len(bSlice), passN)
}

func collectChan(ctx context.Context, N int, ch chan p2p.Message) (ret []p2p.Message) {
	for i := 0; i < N; i++ {
		select {
		case <-ctx.Done():
			return ret
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
		require.NoError(t, xs[i].Close())
	}
}

func CloseAskSwarms(t testing.TB, xs []p2p.AskSwarm) {
	for i := range xs {
		require.Nil(t, xs[i].Close())
	}
}

func CloseSecureSwarms(t testing.TB, xs []p2p.SecureSwarm) {
	for i := range xs {
		require.Nil(t, xs[i].Close())
	}
}

func copyMessage(x *p2p.Message) p2p.Message {
	return p2p.Message{
		Dst:     x.Dst,
		Src:     x.Src,
		Payload: append([]byte{}, x.Payload...),
	}
}

func copyTells(ctx context.Context, ch chan p2p.Message, q *swarmutil.TellQueue) {
	for {
		if err := q.ServeTell(ctx, func(m *p2p.Message) {
			ch <- copyMessage(m)
		}); err != nil {
			return
		}
	}
}
