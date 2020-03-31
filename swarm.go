package p2p

import (
	"bytes"
	"context"
	"io"
)

type Message struct {
	Dst, Src Addr
	Payload  []byte
	Vector   [][]byte
}

func (m *Message) AsBytes() []byte {
	if m.Payload != nil {
		return m.Payload
	}

	w := bytes.Buffer{}
	for _, data := range m.Vector {
		if _, err := w.Write(data); err != nil {
			panic(err)
		}
	}
	return w.Bytes()
}

func (m *Message) WriteAll(w io.Writer) error {
	if m.Payload != nil {
		_, err := w.Write(m.Payload)
		return err
	}

	for _, data := range m.Vector {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
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

type Secure interface {
	PublicKey() PublicKey
	LookupPublicKey(addr Addr) PublicKey
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

type composedSecureSwarm struct {
	Swarm
	Secure
}

type composedAskSwarm struct {
	Swarm
	Asker
}

type composedSecureAskSwarm struct {
	Swarm
	Asker
	Secure
}

func ComposeAskSwarm(swarm Swarm, ask Asker) AskSwarm {
	return composedAskSwarm{
		Swarm: swarm,
		Asker: ask,
	}
}

func ComposeSecureAskSwarm(swarm Swarm, ask Asker, sec Secure) SecureAskSwarm {
	return composedSecureAskSwarm{
		Swarm:  swarm,
		Asker:  ask,
		Secure: sec,
	}
}

func ComposeSecureSwarm(swarm Swarm, sec Secure) SecureSwarm {
	return composedSecureSwarm{
		Swarm:  swarm,
		Secure: sec,
	}
}
