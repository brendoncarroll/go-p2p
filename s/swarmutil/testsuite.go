package swarmutil

import (
	"context"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
)

type SwarmFactory func([]p2p.Swarm)
type AskSwarmFactory func(int) []p2p.Swarm

func TestSuite(t *testing.T, fac SwarmFactory) {

	singleTests := []func(t *testing.T, x p2p.Swarm){
		TestLocalAddrs,
		TestMarshalParse,
	}
	for _, test := range singleTests {
		xs := make([]p2p.Swarm, 1)
		fac(xs)
		x := xs[0]
		test(t, x)
		assert.Nil(t, x.Close())
	}

	func() {
		xs := make([]p2p.Swarm, 2)
		fac(xs)
		for i, x1 := range xs {
			for j, x2 := range xs {
				if j == i {
					continue
				}
				TestTell(t, x1, x2)
			}
		}
		for _, x := range xs {
			assert.Nil(t, x.Close())
		}
	}()
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
	assert.Nil(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout waiting for tell")
	}

	assert.Equal(t, string(payload), string(recv.Payload))
	assert.Equal(t, dstAddr, recv.Dst, "DST addr incorrect. HAVE: %v WANT: %v", recv.Dst, dstAddr)
	assert.NotNil(t, recv.Src, "SRC addr is nil")
}

func genPayload() []byte {
	x := fmt.Sprintf("test-%d", mrand.Int63())
	return []byte(x)
}
