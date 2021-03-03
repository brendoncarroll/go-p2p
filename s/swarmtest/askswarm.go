package swarmtest

import (
	"context"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuiteAskSwarm(t *testing.T, newSwarms func(testing.TB, int) []p2p.AskSwarm) {
	t.Run("MultipleAsks", func(t *testing.T) {
		xs := newSwarms(t, 10)
		require.Len(t, xs, 10)
		TestMultipleAsks(t, xs)
	})
}

func TestMultipleAsks(t *testing.T, xs []p2p.AskSwarm) {
	const N = 100
	queues := make([]*swarmutil.AskQueue, len(xs))
	for i := range xs {
		i := i
		queues[i] = swarmutil.NewAskQueue()
		go xs[i].ServeAsks(func(ctx context.Context, msg *p2p.Message, w io.Writer) {
			queues[i].DeliverAsk(ctx, msg, w)
		})
	}
	for i := 0; i < N; i++ {
		TestAsk(t, xs, queues)
	}
}

func TestAsk(t *testing.T, xs []p2p.AskSwarm, queues []*swarmutil.AskQueue) {
	ctx := context.Background()
	for _, i := range rand.Perm(len(xs)) {
		for _, j := range rand.Perm(len(xs)) {
			if i != j {
				func() {
					srcAddr := xs[i].LocalAddrs()[0]
					dstAddr := xs[j].LocalAddrs()[0]
					ctx, cf := context.WithTimeout(ctx, 5*time.Second)
					defer cf()
					mu := sync.Mutex{}
					gotAsk := false

					go queues[j].ServeAsk(ctx, func(ctx context.Context, msg *p2p.Message, w io.Writer) {
						assert.Equal(t, "ping", string(msg.Payload))
						_, err := w.Write([]byte("pong"))
						require.Nil(t, err)
						mu.Lock()
						gotAsk = true
						mu.Unlock()
					})
					reply, err := xs[i].Ask(ctx, xs[j].LocalAddrs()[0], p2p.IOVec{[]byte("ping")})
					require.Nil(t, err, "error in Ask %v -> %v", srcAddr, dstAddr)
					require.Equal(t, "pong", string(reply))
					mu.Lock()
					defer mu.Unlock()
					require.True(t, gotAsk)
				}()
			}
		}
	}
}
