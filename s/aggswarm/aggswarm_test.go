package aggswarm

import (
	"crypto/ed25519"
	"testing"

	"github.com/brendoncarroll/go-p2p/memswarm"
	"github.com/stretchr/testify/assert"
)

func TestMulti(t *testing.T) {
	r1 := memswarm.NewRealm()
	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	transports := map[string]Transport{
		"mem1": r1.NewSwarmWithKey(privKey),
		"mem2": r1.NewSwarmWithKey(privKey),
	}
	as := New(privKey, transports)

	locals := as.LocalAddrs()
	t.Log(locals)
	assert.Len(t, locals, 2)
}
