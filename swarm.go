package p2p

import (
	"context"
	"net"

	"github.com/pkg/errors"
)

type Message[A Addr] struct {
	Src, Dst A
	Payload  []byte
}

// TODO: Add back TellHandler
// https://github.com/golang/go/issues/46477
// type TellHandler[A Addr] = func(Message[A])

type Teller[A Addr] interface {
	// Tell sends a message containing data to dst
	// Tell returns an error if the message cannot be set in flight.
	// A nil error does not guarentee delivery of the message.
	// None of the buffers in v will be modified.
	Tell(ctx context.Context, dst A, v IOVec) error

	// Recv blocks until the context is cancelled or 1 message is recieved.
	// fn is called with the message, which may be used until fn returns.
	// None of the message's fields may be accessed outside of fn.
	// All of the message's fields may be modified inside fn. A message is only ever delivered to one place,
	// so the message will never be accessed concurrently or after the call to fn.
	Receive(ctx context.Context, fn func(Message[A])) error
}

// AskHandler is used to generate a response to an Ask
// The response is written to resp and the number of bytes written is returned.
// Returning a value < 0 indicates an error.
// How to interpret values < 0 is up to the Swarm, but it must result in some kind of error returned from the corresponding call to Ask
// TODO: Add back AskHandler
// https://github.com/golang/go/issues/46477
// type AskHandler[A Addr] func(ctx context.Context, resp []byte, req Message[A]) int

type Asker[A Addr] interface {
	// Ask sends req to addr, and writes the response to resp.
	// The number of bytes written to resp is returned, or an error.
	// If resp is too short for the response: io.ErrShortBuffer is returned.
	Ask(ctx context.Context, resp []byte, addr A, req IOVec) (int, error)
	// ServeAsk calls fn to serve a single ask request, it returns an error if anything went wrong.
	// Return values < 0 from fn will not result in an error returned from ServeAsk
	ServeAsk(ctx context.Context, ah func(ctx context.Context, resp []byte, req Message[A]) int) error
}

func NoOpAskHandler[A Addr](ctx context.Context, resp []byte, req Message[A]) int { return 0 }

// Swarm represents a single node's view of an address space for nodes.
// Nodes have their own position(s) or address(es) in the swarm.
// Nodes can send and receive messages to and from other nodes in the Swarm.
type Swarm[A Addr] interface {
	Teller[A]

	// LocalAddrs returns all the addresses that can be used to contact this Swarm
	LocalAddrs() []A
	// MTU returns the maximum transmission unit for a particular address,
	// If the context is done, MTU returns a safe default value.
	MTU(ctx context.Context, addr A) int
	// Close releases all resources held by the swarm.
	// It should be called when the swarm is no longer in use.
	Close() error
	// ParseAddr attempts to parse an address from data
	ParseAddr(data []byte) (A, error)
	// MaxIncomingSize returns the minimum size the payload of an incoming message could be
	MaxIncomingSize() int
}

type AskSwarm[A Addr] interface {
	Swarm[A]
	Asker[A]
}

var (
	ErrPublicKeyNotFound = errors.Errorf("public key not found")
)

type Secure[A Addr, PublicKey any] interface {
	PublicKey() PublicKey
	LookupPublicKey(ctx context.Context, addr A) (PublicKey, error)
}

type SecureSwarm[A Addr, PublicKey any] interface {
	Swarm[A]
	Secure[A, PublicKey]
}

type SecureAskSwarm[A Addr, PublicKey any] interface {
	Swarm[A]
	Asker[A]
	Secure[A, PublicKey]
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
func LookupPublicKeyInHandler[A Addr, PublicKey any](s Secure[A, PublicKey], target A) PublicKey {
	ctx, cf := context.WithCancel(context.Background())
	cf()
	pubKey, err := s.LookupPublicKey(ctx, target)
	if err != nil {
		err = errors.Wrapf(err, "swarms must provide public key during callback")
		panic(err)
	}
	return pubKey
}

func DiscardAsks[A Addr](ctx context.Context, a Asker[A]) error {
	for {
		if err := a.ServeAsk(ctx, NoOpAskHandler[A]); err != nil {
			return err
		}
	}
}

func DiscardTells[A Addr](ctx context.Context, t Teller[A]) error {
	for {
		if err := t.Receive(ctx, func(m Message[A]) {}); err != nil {
			return err
		}
	}
}

// Receive is convenience function which sets m to be a message received from t.
// m must be non-nil.
// m.Payload will be truncated (x = x[:0]), and then the message payload will be appended (x = append(x, payload...))
// This is useful if the caller wants their own copy of the message, instead of borrowing the swarm's temporarily.
func Receive[A Addr](ctx context.Context, t Teller[A], m *Message[A]) error {
	return t.Receive(ctx, func(m2 Message[A]) {
		m.Src = m2.Src
		m.Dst = m2.Dst
		m.Payload = append(m.Payload[:0], m2.Payload...)
	})
}
