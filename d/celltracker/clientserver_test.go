package celltracker

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-state/cells"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientServer(t *testing.T) {
	const addr = "127.0.0.1:8080"
	ctx, cf := context.WithCancel(context.Background())
	defer cf()

	s := NewServer()
	defer s.Close()
	token := GenerateToken("http://" + addr + "/")
	t.Logf("token: %s", token)
	c, err := NewClient(token)
	require.Nil(t, err)

	go func() {
		if err := http.ListenAndServe(addr, s); err != nil {
			t.Log(err)
		}
	}()
	pollServer("http://" + addr)

	data, err := cells.GetBytes(ctx, c.cell)
	require.Nil(t, err)
	assert.Len(t, data, 0)

	err = c.Announce(ctx, p2p.PeerID{}, []string{"addr1", "addr2"}, time.Minute)
	require.Nil(t, err)

	addrs, err := c.Find(ctx, p2p.PeerID{})
	require.Nil(t, err)
	assert.Equal(t, addrs, []string{"addr1", "addr2"})
}

func pollServer(endpoint string) {
	const N = 10
	for i := 0; i < N; i++ {
		resp, err := http.Get(endpoint)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
