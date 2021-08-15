package p2p

import (
	"context"
	"io"
	"net"

	"github.com/pkg/errors"
)

type Message struct {
	Dst, Src Addr
	Payload  []byte
}

type Teller interface {
	// Tell sends a message containing data to dst
	// Tell returns an error if the message cannot be set in flight.
	// A nil error does not guarentee delivery of the message.
	Tell(ctx context.Context, dst Addr, data IOVec) error
	// Recv blocks until the context is cancelled or 1 message is recieved.
	// The contents of message are written into src, dst and buf; the number of bytes written to buf is returned.
	// If buf is too small Recv returns io.ErrShortBuffer
	Receive(ctx context.Context, src, dst *Addr, buf []byte) (int, error)
	// MaxIncomingSize returns the minimum size a buffer must be so that Recv never returns io.ErrShortBuffer
	MaxIncomingSize() int
}

// AskHandler is used to generate a response to an Ask
// The response is written to resp and the number of bytes written is returned.
// Returning a value < 0 indicates an error.
// How to interpret values < 0 is up to the Swarm, but it must result in some kind of error returned from the corresponding call to Ask
type AskHandler func(ctx context.Context, resp []byte, req Message) int

type Asker interface {
	Ask(ctx context.Context, resp []byte, addr Addr, data IOVec) (int, error)
	ServeAsk(ctx context.Context, fn AskHandler) error
}

var _ AskHandler = NoOpAskHandler

func NoOpAskHandler(ctx context.Context, resp []byte, req Message) int { return 0 }

type Swarm interface {
	Teller

	// LocalAddrs returns all the addresses that can be used to contact this Swarm
	LocalAddrs() []Addr
	// MTU returns the maximum transmission unit for a particular address,
	// If the context is done, MTU returns a safe default value.
	MTU(ctx context.Context, addr Addr) int
	// Close releases all resources held by the swarm.
	// It should be called when the swarm is no longer in use.
	Close() error
	// ParseAddr attempts to parse an address from data
	ParseAddr(data []byte) (Addr, error)
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

type IOVec = net.Buffers

// VecSize returns the total size of the vector in bytes if it were contiguous.
// It is the sum of len(v[i]) for all i
func VecSize(v IOVec) int {
	var total int
	for i := range v {
		total += len(v[i])
	}
	return total
}

// VecBytes appends all the buffers in v to out and returns the result
func VecBytes(out []byte, v IOVec) []byte {
	for i := range v {
		out = append(out, v[i]...)
	}
	return out
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

func DiscardAsks(ctx context.Context, a Asker) error {
	for {
		if err := a.ServeAsk(ctx, NoOpAskHandler); err != nil {
			return err
		}
	}
}

func DiscardTells(ctx context.Context, t Teller) error {
	for {
		var src, dst Addr
		if _, err := t.Receive(ctx, &src, &dst, nil); err != nil {
			if err == io.ErrShortBuffer {
				continue
			}
			return err
		}
	}
}
