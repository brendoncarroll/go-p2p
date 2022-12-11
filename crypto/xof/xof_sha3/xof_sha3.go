package xof_sha3

import (
	"github.com/brendoncarroll/go-p2p/crypto/xof"

	sha3int "github.com/brendoncarroll/go-p2p/crypto/xof/xof_sha3/internal/sha3"
)

type SHAKE256State sha3int.State

var _ xof.Scheme[SHAKE256State] = SHAKE256{}

type SHAKE256 struct{}

func (SHAKE256) New() SHAKE256State {
	return SHAKE256State(sha3int.NewState())
}

func (SHAKE256) Absorb(x *SHAKE256State, in []byte) {
	x2 := (*sha3int.State)(x)
	if _, err := x2.Write(in); err != nil {
		panic(err)
	}
}

func (SHAKE256) Expand(x *SHAKE256State, out []byte) {
	x2 := (*sha3int.State)(x)
	_, err := x2.Read(out)
	if err != nil {
		panic(err)
	}
}

func (SHAKE256) Reset(x *SHAKE256State) {
	x2 := (*sha3int.State)(x)
	x2.Reset()
}
