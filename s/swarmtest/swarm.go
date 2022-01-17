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
func TestSwarm[A p2p.Addr](t *testing.T, newSwarms func(testing.TB, []p2p.Swarm[A])) {
	t.Run("LocalAddrs", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 1)
		newSwarms(t, xs)
		x := xs[0]
		TestLocalAddrs(t, x)
	})
	t.Run("MarshalParse", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 1)
		newSwarms(t, xs)
		x := xs[0]
		TestMarshalParse(t, x)
	})
	t.Run("SingleTell", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 2)
		newSwarms(t, xs)
		TestTell(t, xs[0], xs[1])
	})
	t.Run("Tell", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 10)
		newSwarms(t, xs)
		TestTellAllPairs(t, xs)
	})
	t.Run("TellBidirectional", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 2)
		newSwarms(t, xs)
		a, b := xs[0], xs[1]
		TestTellBidirectional(t, a, b)
	})
	t.Run("TellMTU", func(t *testing.T) {
		xs := make([]p2p.Swarm[A], 2)
		newSwarms(t, xs)
		a, b := xs[0], xs[1]
		TestTellMTU(t, a, b)
	})
}

func TestLocalAddrs[A p2p.Addr](t *testing.T, s p2p.Swarm[A]) {
	addrs := s.LocalAddrs()
	assert.True(t, len(addrs) > 0, "LocalAddrs must return at least 1")
}

func TestMarshalParse[A p2p.Addr](t *testing.T, s p2p.Swarm[A]) {
	addr := s.LocalAddrs()[0]
	data, err := addr.MarshalText()
	assert.NoError(t, err)
	addr2, err := s.ParseAddr(data)
	assert.NoError(t, err)
	assert.Equal(t, &addr, addr2, "Did not parse to same address")
}

func TestTellAllPairs[A p2p.Addr](t *testing.T, xs []p2p.Swarm[A]) {
	for i := range xs {
		for j := range xs {
			if j != i {
				TestTell(t, xs[i], xs[j])
			}
		}
	}
}

func TestTell[A p2p.Addr](t *testing.T, src, dst p2p.Swarm[A]) {
	ctx, cf := context.WithTimeout(context.Background(), time.Second)
	defer cf()
	payload := genPayload()
	dstAddr := dst.LocalAddrs()[0]
	eg := errgroup.Group{}
	eg.Go(func() error {
		return src.Tell(ctx, dstAddr, p2p.IOVec{payload})
	})
	var recv p2p.Message[A]
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

func TestTellBidirectional[A p2p.Addr](t *testing.T, a, b p2p.Swarm[A]) {
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
	aInbox := []p2p.Message[A]{}
	bInbox := []p2p.Message[A]{}
	readIntoMailbox := func(s p2p.Swarm[A], inbox *[]p2p.Message[A]) error {
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
	require.NoError(t, eg.Wait())

	passN := N * 3 / 4
	t.Log("a inbox: ", len(aInbox))
	t.Log("b inbox: ", len(bInbox))
	assert.GreaterOrEqual(t, len(aInbox), passN)
	assert.GreaterOrEqual(t, len(bInbox), passN)
}

func TestTellMTU[A p2p.Addr](t *testing.T, a, b p2p.Swarm[A]) {
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()

	size := a.MTU(ctx, b.LocalAddrs()[0])
	err := a.Tell(ctx, b.LocalAddrs()[0], p2p.IOVec{make([]byte, size+1)})
	require.Equal(t, p2p.ErrMTUExceeded, err)

	var sent, received []byte
	eg := errgroup.Group{}
	eg.Go(func() error {
		size := a.MTU(ctx, b.LocalAddrs()[0])
		buf := make([]byte, size)
		sent = buf
		return a.Tell(ctx, b.LocalAddrs()[0], p2p.IOVec{buf})
	})
	eg.Go(func() error {
		msg, err := readMessage(ctx, b)
		if err != nil {
			return err
		}
		received = msg.Payload
		return nil
	})
	require.NoError(t, eg.Wait())
	require.NotNil(t, sent)
	require.NotNil(t, received)
	require.Equal(t, len(sent), len(received))
}

func genPayload() []byte {
	x := fmt.Sprintf("test-%d", mrand.Int63())
	return []byte(x)
}

func CloseSwarms[A p2p.Addr](t testing.TB, xs []p2p.Swarm[A]) {
	for i := range xs {
		require.NoError(t, xs[i].Close())
	}
}

func CloseAskSwarms[A p2p.Addr](t testing.TB, xs []p2p.AskSwarm[A]) {
	for i := range xs {
		require.NoError(t, xs[i].Close())
	}
}

func CloseSecureSwarms[A p2p.Addr](t testing.TB, xs []p2p.SecureSwarm[A]) {
	for i := range xs {
		require.NoError(t, xs[i].Close())
	}
}

func readMessage[A p2p.Addr](ctx context.Context, s p2p.Swarm[A]) (p2p.Message[A], error) {
	var mCopy p2p.Message[A]
	err := s.Receive(ctx, func(m p2p.Message[A]) {
		mCopy = p2p.Message[A]{
			Src:     m.Src,
			Dst:     m.Dst,
			Payload: append([]byte{}, m.Payload...),
		}
	})
	if err != nil {
		return p2p.Message[A]{}, err
	}
	return mCopy, nil
}
