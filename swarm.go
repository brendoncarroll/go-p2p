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
