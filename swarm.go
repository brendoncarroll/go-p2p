package p2p

import (
	"context"
	"io"
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

type IterableSwarm interface {
	Remotes() []Addr
}

type SecureSwarm interface {
	PublicKey() PublicKey
	LookupPublicKey(addr Addr) PublicKey
}

type Mux interface {
	OpenChannel(string) (Swarm, error)
}
