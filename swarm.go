package p2p

import (
	"context"
	"io"

	"github.com/pkg/errors"
)

type Message struct {
	Dst, Src Addr
	Payload  []byte
}

type AskHandler func(ctx context.Context, req *Message, w io.Writer)
type TellHandler func(msg *Message)

func NoOpAskHandler(ctx context.Context, req *Message, w io.Writer) {}

func NoOpTellHandler(msg *Message) {}

type Swarm interface {
	Teller

	LocalAddrs() []Addr
	MTU(ctx context.Context, addr Addr) int
	Close() error
	ParseAddr(data []byte) (Addr, error)
}

type Teller interface {
	Tell(ctx context.Context, addr Addr, data []byte) error
	OnTell(TellHandler)
}

type Asker interface {
	Ask(ctx context.Context, addr Addr, data []byte) ([]byte, error)
	OnAsk(AskHandler)
}

type AskSwarm interface {
	Swarm
	Asker
}

var (
	ErrPublicKeyNotFound = errors.Errorf("public key not found")
)

type Secure interface {
	PublicKey() PublicKey
	LookupPublicKey(ctx context.Context, addr Addr) (PublicKey, error)
}

type SecureSwarm interface {
	Swarm
	Secure
}

type SecureAskSwarm interface {
	Swarm
	Asker
	Secure
}

// LookupPublicKeyInHandler calls LookupPublicKey with
// an expired context, and panics on an error.  SecureSwarms must
// be able to return a PublicKey retrieved from memory, during the
// execution of an AskHandler or TellHandler.
// to lookup a public key outside a handler, use the swarms LookupPublicKey method
func LookupPublicKeyInHandler(s Secure, target Addr) PublicKey {
	ctx, cf := context.WithCancel(context.Background())
	cf()
	pubKey, err := s.LookupPublicKey(ctx, target)
	if err != nil {
		err = errors.Wrapf(err, "swarms must provide public key during callback")
		panic(err)
	}
	if pubKey == nil {
		panic("swarms must provide public key during callback. got nil")
	}
	return pubKey
}
