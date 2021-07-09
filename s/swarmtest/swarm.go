package swarmtest

import (
	"context"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestSwarm runs a suite of tests to ensure a Swarm exhibits the correct behaviors
// newSwarms should fill the passed slice with swarms which can communicate with one another,
// and register any cleanup on the provided testing.TB
func TestSwarm(t *testing.T, newSwarms func(testing.TB, []p2p.Swarm)) {
	t.Run("LocalAddrs", func(t *testing.T) {
		xs := make([]p2p.Swarm, 1)
		newSwarms(t, xs)
		x := xs[0]
		TestLocalAddrs(t, x)
	})
	t.Run("MarshalParse", func(t *testing.T) {
		xs := make([]p2p.Swarm, 1)
		newSwarms(t, xs)
		x := xs[0]
		TestMarshalParse(t, x)
	})
	t.Run("SingleTell", func(t *testing.T) {
		xs := make([]p2p.Swarm, 2)
		newSwarms(t, xs)
		TestTell(t, xs[0], xs[1])
	})
	t.Run("Tell", func(t *testing.T) {
		xs := make([]p2p.Swarm, 10)
		newSwarms(t, xs)
		TestTellAllPairs(t, xs)
	})
	t.Run("TellBidirectional", func(t *testing.T) {
		xs := make([]p2p.Swarm, 2)
		newSwarms(t, xs)
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
	for i := range xs {
		for j := range xs {
			if j != i {
				TestTell(t, xs[i], xs[j])
			}
		}
	}
}

func TestTell(t *testing.T, src, dst p2p.Swarm) {
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	payload := genPayload()
	dstAddr := dst.LocalAddrs()[0]
	eg := errgroup.Group{}
	eg.Go(func() error {
		return src.Tell(ctx, dstAddr, p2p.IOVec{payload})
	})
	var recv p2p.Message
	eg.Go(func() error {
		var err error
		recv, err = readMessage(ctx, dst)
		return err
	})
	require.NoError(t, eg.Wait())
	assert.Equal(t, string(payload), string(recv.Payload))
	assert.Equal(t, dstAddr, recv.Dst, "DST addr incorrect. HAVE: %v WANT: %v", recv.Dst, dstAddr)
	assert.NotNil(t, recv.Src, "SRC addr is nil")
}

func TestTellBidirectional(t *testing.T, a, b p2p.Swarm) {
	const N = 50
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()

	eg := errgroup.Group{}
	sleepRandom := func() {
		dur := time.Millisecond * time.Duration(1+mrand.Intn(10)-5)
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
	aInbox := []p2p.Message{}
	bInbox := []p2p.Message{}
	readIntoMailbox := func(s p2p.Swarm, inbox *[]p2p.Message) error {
		for i := 0; i < N; i++ {
			msg, err := readMessage(ctx, s)
			if err != nil {
				return err
			}
			*inbox = append(*inbox, msg)
		}
		return nil
	}
	eg.Go(func() error {
		return readIntoMailbox(a, &aInbox)
	})
	eg.Go(func() error {
		return readIntoMailbox(b, &bInbox)
	})
	require.Nil(t, eg.Wait())

	passN := N * 3 / 4
	t.Log("a inbox: ", len(aInbox))
	t.Log("b inbox: ", len(bInbox))
	assert.GreaterOrEqual(t, len(aInbox), passN)
	assert.GreaterOrEqual(t, len(bInbox), passN)
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

func readMessage(ctx context.Context, s p2p.Swarm) (p2p.Message, error) {
	var src, dst p2p.Addr
	buf := make([]byte, s.MaxIncomingSize())
	n, err := s.Recv(ctx, &src, &dst, buf)
	if err != nil {
		return p2p.Message{}, nil
	}
	return p2p.Message{
		Src:     src,
		Dst:     dst,
		Payload: buf[:n],
	}, nil
}
