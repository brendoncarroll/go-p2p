package swarmtest

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestAskSwarm runs a test suite on AskSwarms to ensure they implement p2p.AskSwarm correctly
func TestAskSwarm(t *testing.T, newSwarms func(testing.TB, []p2p.AskSwarm)) {
	t.Run("SingleAsk", func(t *testing.T) {
		xs := make([]p2p.AskSwarm, 2)
		newSwarms(t, xs)
		TestAsk(t, xs[0], xs[1])
	})
	t.Run("MultipleAsks", func(t *testing.T) {
		xs := make([]p2p.AskSwarm, 10)
		newSwarms(t, xs)
		TestMultipleAsks(t, xs)
	})
	t.Run("ErrorResponse", func(t *testing.T) {
		xs := make([]p2p.AskSwarm, 2)
		newSwarms(t, xs)
		TestErrorResponse(t, xs[0], xs[1])
	})
}

func TestMultipleAsks(t *testing.T, xs []p2p.AskSwarm) {
	const N = 100
	for i := 0; i < N; i++ {
		TestAskAll(t, xs)
	}
}

func TestAskAll(t *testing.T, xs []p2p.AskSwarm) {
	for _, i := range rand.Perm(len(xs)) {
		for _, j := range rand.Perm(len(xs)) {
			if i == j {
				continue
			}
			TestAsk(t, xs[i], xs[j])
		}
	}
}

func TestAsk(t *testing.T, src, dst p2p.AskSwarm) {
	ctx := context.Background()
	ctx, cf := context.WithTimeout(ctx, 3*time.Second)
	defer cf()

	dstAddr := dst.LocalAddrs()[0]

	eg := errgroup.Group{}
	actualRespData := make([]byte, src.MTU(ctx, dstAddr))
	eg.Go(func() error {
		reqData := []byte("ping")
		n, err := src.Ask(ctx, actualRespData, dstAddr, p2p.IOVec{reqData})
		actualRespData = actualRespData[:n]
		return err
	})
	var actualReqDst p2p.Addr
	var actualReqData []byte
	eg.Go(func() error {
		respData := []byte("pong")
		return dst.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message) int {
			actualReqDst = req.Dst
			actualReqData = append([]byte{}, req.Payload...)
			return copy(resp, respData)
		})
	})
	require.NoError(t, eg.Wait())

	assert.Equal(t, "ping", string(actualReqData))
	assert.Equal(t, dstAddr, actualReqDst)
	assert.Equal(t, "pong", string(actualRespData))
}

func TestErrorResponse(t *testing.T, src, dst p2p.AskSwarm) {
	ctx := context.Background()
	eg := errgroup.Group{}
	eg.Go(func() error {
		return dst.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message) int {
			return -1
		})
	})
	var callerError error
	eg.Go(func() error {
		resp := make([]byte, src.MaxIncomingSize())
		_, err := src.Ask(ctx, resp, dst.LocalAddrs()[0], p2p.IOVec{})
		callerError = err
		return nil
	})
	require.NoError(t, eg.Wait())
	require.NotNil(t, callerError)
}
